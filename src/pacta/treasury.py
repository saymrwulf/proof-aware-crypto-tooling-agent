"""warden-treasury: trust-minimized Solana transaction watching.

An agent that must believe on-chain state ("did my deposit land?") today
asks an RPC provider and trusts the answer. Treasury mode demotes the RPC
from oracle to bandwidth: it takes the raw transaction bytes, parses the
wire format locally (stdlib only), and re-verifies every required
signature through the wallet's quorum - which includes the ``anza``
member, the certificate-covered verify path of the code Solana
validators themselves run. A lying RPC can withhold a transaction, but it
cannot manufacture one the quorum will accept.

Honesty ledger for this module: signature verification is custody-grade
(the quorum); the WIRE PARSING here (base58, compact-u16, the message
header) is ~120 lines of stdlib Python and is trusted base, exactly like
the wire parsers inside the forks are hypotheses of the theorems. A
malicious RPC also controls *which* transactions you see (completeness);
treasury verification establishes authenticity, not completeness.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58decode(text: str) -> bytes:
    """Base58 (Bitcoin/Solana alphabet), stdlib only."""
    value = 0
    for char in text:
        if char not in _B58_INDEX:
            raise ValueError(f"invalid base58 character {char!r}")
        value = value * 58 + _B58_INDEX[char]
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + raw


def _compact_u16(data: bytes, offset: int) -> tuple[int, int]:
    """Solana's compact-u16 (shortvec) length encoding."""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated compact-u16")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return result, offset
        shift += 7
        if shift > 14:
            raise ValueError("compact-u16 too long")


@dataclass(slots=True)
class ParsedTransaction:
    signatures: list[bytes]
    message: bytes                 # the exact bytes the signatures sign
    account_keys: list[bytes]      # 32-byte Ed25519 keys, signers first
    num_required_signatures: int
    version: int | None = None     # None = legacy, 0 = v0


def parse_transaction(tx: bytes) -> ParsedTransaction:
    """Parse a wire-format Solana transaction (legacy or v0).

    Layout: compact-u16 count of 64-byte signatures, then the message.
    Message: optional version byte (high bit set), 3-byte header
    (num_required_signatures, num_readonly_signed, num_readonly_unsigned),
    compact-u16 count of 32-byte account keys, 32-byte recent blockhash,
    instructions (not needed here - the signed payload is the whole
    message, byte for byte).
    """
    count, offset = _compact_u16(tx, 0)
    if count == 0 or count > 12:
        raise ValueError(f"implausible signature count {count}")
    signatures = []
    for _ in range(count):
        if offset + 64 > len(tx):
            raise ValueError("truncated signature section")
        signatures.append(tx[offset:offset + 64])
        offset += 64
    message = tx[offset:]
    if not message:
        raise ValueError("empty message")
    pos = 0
    version: int | None = None
    if message[0] & 0x80:
        version = message[0] & 0x7F
        if version != 0:
            raise ValueError(f"unsupported transaction version {version}")
        pos = 1
    if pos + 3 > len(message):
        raise ValueError("truncated message header")
    num_required = message[pos]
    pos += 3
    key_count, pos = _compact_u16(message, pos)
    if key_count < num_required:
        raise ValueError("fewer account keys than required signatures")
    keys = []
    for _ in range(key_count):
        if pos + 32 > len(message):
            raise ValueError("truncated account keys")
        keys.append(message[pos:pos + 32])
        pos += 32
    if len(signatures) != num_required:
        raise ValueError(
            f"signature count {len(signatures)} != header num_required_signatures {num_required}"
        )
    return ParsedTransaction(signatures, message, keys, num_required, version)


@dataclass(slots=True)
class TreasuryVerdict:
    authentic: bool
    signer_results: list[dict[str, Any]] = field(default_factory=list)
    version: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "pacta.wallet.treasury_verdict.v1",
            "authentic": self.authentic,
            "signer_results": self.signer_results,
            "transaction_version": self.version,
            "note": (
                "authenticity only: every required signature was quorum-verified over the "
                "message bytes; an RPC can still withhold transactions (no completeness claim)"
            ),
        }


def verify_transaction(wallet: Any, tx: bytes, state_dir: Any = None) -> TreasuryVerdict:
    """Quorum-verify every required signature of a wire-format transaction.

    Fail-closed: authentic only if EVERY required signature is a unanimous
    quorum accept. Each check lands in the wallet ledger with a treasury
    context, so the audit trail shows exactly which chain facts this
    wallet chose to believe, and on whose mathematics.
    """
    parsed = parse_transaction(tx)
    results = []
    authentic = True
    for i, signature in enumerate(parsed.signatures):
        signer_key = parsed.account_keys[i]
        outcome = wallet.verify_inbound(
            parsed.message,
            signature,
            signer_key,
            context=f"treasury: tx signer {i}",
            state_dir=state_dir,
        )
        results.append({
            "signer_index": i,
            "signer_key_hex": signer_key.hex(),
            "classification": outcome.classification,
            "accepted": outcome.accepted,
        })
        authentic = authentic and outcome.accepted
    return TreasuryVerdict(authentic, results, parsed.version)


def fetch_transaction(rpc_url: str, signature_b58: str, timeout: int = 20) -> bytes:
    """Fetch raw transaction bytes from a Solana JSON-RPC endpoint.

    The response is used as BYTES ONLY - nothing the RPC says about
    status, slots, or balances is consumed here. Trust demotion is the
    point: the RPC hands over an envelope; the quorum decides.
    """
    import base64

    request = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature_b58,
            {"encoding": "base64", "maxSupportedTransactionVersion": 0},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        rpc_url, data=request, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = json.loads(response.read())
    result = body.get("result")
    if not result:
        raise ValueError(f"RPC returned no transaction for {signature_b58}")
    encoded = (result.get("transaction") or [None])[0]
    if not isinstance(encoded, str):
        raise ValueError("RPC response has no base64 transaction body")
    return base64.b64decode(encoded)
