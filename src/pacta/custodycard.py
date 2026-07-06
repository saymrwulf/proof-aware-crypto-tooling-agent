"""The custody card and the proof-of-posture challenge.

A2A publishes agent cards at ``/.well-known/agent-card.json`` and (since
v1.0) signs them. warden's card goes one step further: it is
**self-proving**. Alongside the description sits, for every quorum
member, the transparency-log inclusion proof binding the member's
attested source to a signed tree head. A counterparty does not have to
believe the card's adjectives - it can recompute the Merkle roots with
~40 lines of stdlib code and check the STH signature against the log key
it already pins.

The proof-of-posture (PoP) challenge is the live counterpart: send a
nonce, get back a signed posture attestation (capsule hash, ledger head,
latch state, incident count) whose signature just passed the wallet's
own outbound firewall - with the quorum trail attached. A heartbeat you
can audit instead of trust.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .wallet import Refusal, Wallet

CARD_TYPE = "pacta.wallet.custody_card.v1"
POP_TYPE = "pacta.wallet.posture_attestation.v1"
WELL_KNOWN_PATH = ".well-known/custody-card.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_custody_card(wallet: Wallet, log_url: str = "https://ltl.zkdefi.org") -> dict[str, Any]:
    """The self-proving business card. Everything a counterparty agent needs
    to evaluate this wallet is embedded or Merkle-bound; nothing requires
    believing the operator."""
    capsule = wallet.capsule()
    posture = wallet.posture()
    identities = sorted(p.name.removesuffix(".pub.pem") for p in wallet.keys_dir.glob("*.pub.pem"))
    return {
        "type": CARD_TYPE,
        "name": "warden",
        "description": (
            "Verified-custody Ed25519 wallet. Inbound acceptance requires unanimity "
            "of quorum members compiled from sources whose correctness certificates "
            "are machine-checked in Lean 4 and replay-attested in a public RFC 9162 "
            "transparency log. Outbound signatures pass the same quorum as a firewall "
            "before release."
        ),
        "protocol": {
            "mcp": {
                "transport": "stdio",
                "command": "pacta wallet mcp --wallet <dir>",
                "tools": [
                    "wallet_status",
                    "verify_inbound",
                    "request_signature",
                    "custody_card",
                    "posture_challenge",
                    "list_incidents",
                    "explain_refusal",
                ],
            },
            "refusal_codes": [
                "EVIDENCE_REQUIRED", "POLICY_DENIED", "CUSTODY_LATCHED",
                "EVIDENCE_STALE", "MALFORMED_INTENT", "SIGNER_UNAVAILABLE",
                "FIREWALL_QUARANTINE", "PENDING_AIRGAP",
            ],
        },
        "identities": identities,
        "quorum": {
            "policy": capsule["policy"],
            "members": [
                {
                    "backend": m["backend"],
                    "component": m["component"],
                    "semantics": m["semantics"],
                    "entry_point": m["entry_point"],
                    "source_commit": m["source_commit"],
                    "binary_sha256": m["binary_sha256"],
                    "risk_tier": m["risk_tier"],
                    # The self-proving part: recompute, don't believe.
                    "transparency_evidence": m["evidence"],
                }
                for m in capsule["members"]
            ],
        },
        "signing": capsule["signing"],
        "state": {
            "latch": posture["latch"],
            "ledger_head": posture["ledger"]["head"],
            "ledger_entries": posture["ledger"]["entries"],
            "incidents": posture["incidents"],
        },
        "evidence_endpoints": {
            "log": log_url,
            "log_docs": f"{log_url}/docs",
            "verify_hint": (
                "for each member: leaf_hash = SHA256(0x00 || canonical attestation leaf); "
                "walk inclusion_proof to sth.root_hash; verify sth signature against the "
                "log public key you pin. Stdlib only; see the log's verify.py."
            ),
        },
        "honesty": [
            "verification path certificate-covered; signing path trusted base (attested artifact)",
            "SHA-512 enters the theorems as an opaque oracle",
            "wire parser outcomes are hypotheses; side channels and reproducible builds are R5, not claimed",
            "ML-DSA (PQC) slot fail-closed: no proven implementation exists",
        ],
        "generated_at": _now(),
    }


def write_well_known(wallet: Wallet, out_dir: str | Path, log_url: str = "https://ltl.zkdefi.org") -> Path:
    out = Path(out_dir) / WELL_KNOWN_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    card = build_custody_card(wallet, log_url)
    out.write_text(json.dumps(card, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def posture_challenge(
    wallet: Wallet,
    nonce: str,
    key_name: str = "warden",
) -> dict[str, Any] | Refusal:
    """Answer a counterparty's nonce with a firewalled, signed posture.

    The signature on the attestation is produced by the wallet's own
    outbound path, so it carries the full quorum trail - the counterparty
    sees not only *that* the wallet signed, but that four provably
    -equivalent verifiers unanimously accepted the signature before it
    left the building. If custody is latched, the challenge honestly
    fails with a CUSTODY_LATCHED refusal instead of a heartbeat.
    """
    if not isinstance(nonce, str) or not (8 <= len(nonce) <= 128):
        raise ValueError("nonce must be a string of 8..128 characters")
    posture = wallet.posture()
    body = {
        "type": POP_TYPE,
        "nonce": nonce,
        "posture": posture,
    }
    payload = _canonical(body)
    intent = {
        "purpose": f"proof-of-posture challenge response (nonce {nonce[:16]}...)",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    result = wallet.request_signature(intent, payload, key_name=key_name)
    if isinstance(result, Refusal):
        return result
    return {
        "type": POP_TYPE,
        "nonce": nonce,
        "posture": posture,
        "payload_hex": payload.hex(),
        "signature_hex": result["signature_hex"],
        "public_key_hex": result["public_key_hex"],
        "identity": result["identity"],
        "firewall": result["firewall"],
        "issued_at": result["issued_at"],
    }


def verify_posture_attestation(attestation: dict[str, Any], expected_nonce: str) -> tuple[bool, list[str]]:
    """Counterparty-side check, stdlib only: nonce echo, payload binding.

    Signature verification is left to the counterparty's own verifier
    (ideally its own quorum); this helper checks the structure so a
    counterparty without crypto can still catch replay and splicing.
    """
    problems: list[str] = []
    if attestation.get("type") != POP_TYPE:
        problems.append(f"unexpected type {attestation.get('type')}")
    if attestation.get("nonce") != expected_nonce:
        problems.append("nonce mismatch (replay?)")
    try:
        payload = bytes.fromhex(str(attestation.get("payload_hex", "")))
        body = json.loads(payload)
    except ValueError:
        problems.append("payload_hex is not hex/JSON")
        return False, problems
    if body.get("nonce") != expected_nonce:
        problems.append("signed payload does not bind the nonce")
    if body.get("posture") != attestation.get("posture"):
        problems.append("posture shown does not match posture signed")
    return (not problems), problems
