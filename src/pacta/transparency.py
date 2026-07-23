from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .postquantum import detect_ml_dsa
from .signing import canonical_json, public_key_fingerprint, sign_payload_ed25519_detailed, verify_payload_ed25519_detailed
from .yamlio import load_data

HASH_ALGORITHM = "RFC9162_SHA256"
LEAF_TYPE = "pacta.transparency.attestation_leaf.v1"
RECEIPT_TYPE = "pacta.transparency.receipt.v1"
STH_TYPE = "pacta.transparency.signed_tree_head.v1"


@dataclass(slots=True)
class ReceiptVerificationResult:
    accepted: bool
    diagnostics: list[str] = field(default_factory=list)
    log_id: str | None = None
    tree_size: int | None = None
    root_hash: str | None = None
    leaf_hash: str | None = None
    signatures: dict[str, str] = field(default_factory=dict)

    def evidence(self) -> dict[str, Any]:
        return {
            "transparency_receipt_status": "accepted" if self.accepted else "rejected",
            "transparency_log_id": self.log_id,
            "transparency_tree_size": self.tree_size,
            "transparency_root_hash": self.root_hash,
            "transparency_leaf_hash": self.leaf_hash,
            "transparency_signature_status": self.signatures,
        }


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    split = _largest_power_of_two_less_than(len(leaves))
    return node_hash(merkle_root(leaves[:split]), merkle_root(leaves[split:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    if index < 0 or index >= len(leaves):
        raise ValueError(f"Leaf index {index} is outside tree size {len(leaves)}")
    return _inclusion_path(leaves, index)


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: list[bytes], root_hash: bytes) -> bool:
    if tree_size <= 0 or index < 0 or index >= tree_size:
        return False
    try:
        calculated, consumed = _calculate_inclusion_root(leaf_hash(leaf), index, tree_size, proof, 0)
    except ValueError:
        return False
    return consumed == len(proof) and calculated == root_hash


def consistency_proof(leaves: list[bytes], old_tree_size: int) -> list[bytes]:
    if old_tree_size < 0 or old_tree_size > len(leaves):
        raise ValueError("old_tree_size must be between 0 and the current tree size")
    if old_tree_size in (0, len(leaves)):
        return []
    return _consistency_path(old_tree_size, leaves, complete=True)


def verify_consistency(
    old_tree_size: int,
    new_tree_size: int,
    old_root_hash: bytes,
    new_root_hash: bytes,
    proof: list[bytes],
) -> bool:
    if old_tree_size < 0 or new_tree_size < old_tree_size:
        return False
    if old_tree_size == 0:
        return True
    if old_tree_size == new_tree_size:
        return old_root_hash == new_root_hash and not proof
    if not proof:
        return False

    nodes = list(proof)
    if _is_power_of_two(old_tree_size):
        nodes.insert(0, old_root_hash)
    fn = old_tree_size - 1
    sn = new_tree_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    old_hash = nodes.pop(0)
    new_hash = old_hash

    while nodes:
        node = nodes.pop(0)
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            old_hash = node_hash(node, old_hash)
            new_hash = node_hash(node, new_hash)
            if not (fn & 1):
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            new_hash = node_hash(new_hash, node)
        fn >>= 1
        sn >>= 1

    # RFC 9162 2.1.4.2 Step 7 requires the new-size navigation counter to reach
    # zero: the consumed proof length must match the claimed tree sizes. Without
    # it, distinct (false) old-size claims can navigate one proof to the same
    # reconstructed roots, so a valid proof for one transition verifies under a
    # lied size. Reconstructing both roots is necessary but not sufficient.
    return old_hash == old_root_hash and new_hash == new_root_hash and sn == 0


def attestation_leaf(attestation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "type": LEAF_TYPE,
        "attestation": attestation,
    }


def leaf_bytes_for_attestation(attestation: dict[str, Any]) -> bytes:
    return canonical_json(attestation_leaf(attestation))


def leaf_hash_hex_for_attestation(attestation: dict[str, Any]) -> str:
    return leaf_hash(leaf_bytes_for_attestation(attestation)).hex()


def signed_tree_head_payload(sth: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in sth.items() if key != "signatures"}
    return canonical_json(payload)


def make_signed_tree_head(
    log_id: str,
    tree_size: int,
    root_hash_hex: str,
    timestamp: str,
    private_key_path: str | Path,
    public_key_path: str | Path,
    signing_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sth: dict[str, Any] = {
        "schema_version": 1,
        "type": STH_TYPE,
        "log_id": log_id,
        "tree_size": tree_size,
        "timestamp": timestamp,
        "root_hash": root_hash_hex,
        "hash_algorithm": HASH_ALGORITHM,
    }
    payload = signed_tree_head_payload(sth)
    signature_base64, signing_backend = sign_payload_ed25519_detailed(payload, private_key_path)
    sth["signatures"] = {
        "ed25519": {
            "scheme": "openssl-ed25519",
            "signing_backend": signing_backend,
            "status": "signed",
            "payload_digest_sha256": hashlib.sha256(payload).hexdigest(),
            "signature_base64": signature_base64,
            "public_key_fingerprint_sha256": public_key_fingerprint(public_key_path),
            **({"signing_provenance": signing_provenance} if signing_provenance else {}),
        },
        "ml_dsa": detect_ml_dsa().to_signature_slot(),
    }
    return sth


def verify_signed_tree_head(
    sth: dict[str, Any],
    public_key_path: str | Path,
    require_signatures: str = "ed25519",
) -> tuple[bool, list[str], dict[str, str]]:
    diagnostics: list[str] = []
    statuses: dict[str, str] = {}
    if sth.get("type") != STH_TYPE:
        diagnostics.append(f"Unexpected signed tree head type: {sth.get('type')}")
    if sth.get("hash_algorithm") != HASH_ALGORITHM:
        diagnostics.append(f"Unexpected hash algorithm: {sth.get('hash_algorithm')}")

    signatures = sth.get("signatures") or {}
    ed25519 = signatures.get("ed25519") or {}
    if ed25519.get("scheme") != "openssl-ed25519" or ed25519.get("status") != "signed":
        diagnostics.append("Signed tree head is missing a usable Ed25519 signature.")
        statuses["ed25519"] = str(ed25519.get("status") or "missing")
    else:
        payload = signed_tree_head_payload(sth)
        expected_digest = ed25519.get("payload_digest_sha256")
        actual_digest = hashlib.sha256(payload).hexdigest()
        if expected_digest and expected_digest != actual_digest:
            diagnostics.append("Signed tree head digest does not match signature metadata.")
            statuses["ed25519"] = "digest_mismatch"
        else:
            expected_fingerprint = ed25519.get("public_key_fingerprint_sha256")
            if expected_fingerprint and expected_fingerprint != public_key_fingerprint(public_key_path):
                diagnostics.append("Signed tree head Ed25519 public-key fingerprint mismatch.")
                statuses["ed25519"] = "key_mismatch"
            else:
                ok, error, backend = verify_payload_ed25519_detailed(payload, str(ed25519.get("signature_base64") or ""), public_key_path)
                statuses["ed25519"] = "verified" if ok else "failed"
                statuses["ed25519_backend"] = backend
                if not ok:
                    diagnostics.append(f"Signed tree head Ed25519 verification failed: {error}")

    ml_dsa = signatures.get("ml_dsa") or {}
    statuses["ml_dsa"] = str(ml_dsa.get("status") or "missing")
    if require_signatures == "both" and statuses["ml_dsa"] != "verified":
        diagnostics.append("ML-DSA signed tree head signature is required by policy but is not verified.")
    elif require_signatures not in {"ed25519", "both"}:
        diagnostics.append(f"Unsupported transparency signature policy: {require_signatures}")
    return not diagnostics, diagnostics, statuses


def load_receipt(path: str | Path) -> dict[str, Any]:
    raw = load_data(path)
    if not isinstance(raw, dict):
        raise ValueError(f"Transparency receipt must be a mapping: {path}")
    return raw


def verify_receipt(
    attestation: dict[str, Any],
    receipt: dict[str, Any],
    log_public_key_path: str | Path,
    require_signatures: str = "ed25519",
) -> ReceiptVerificationResult:
    diagnostics: list[str] = []
    if receipt.get("type") != RECEIPT_TYPE:
        diagnostics.append(f"Unexpected transparency receipt type: {receipt.get('type')}")
    if receipt.get("hash_algorithm") != HASH_ALGORITHM:
        diagnostics.append(f"Unexpected transparency receipt hash algorithm: {receipt.get('hash_algorithm')}")

    sth = receipt.get("sth") or {}
    sth_ok, sth_diagnostics, statuses = verify_signed_tree_head(sth, log_public_key_path, require_signatures=require_signatures)
    diagnostics.extend(sth_diagnostics)
    try:
        tree_size = int(receipt.get("tree_size"))
        leaf_index = int(receipt.get("leaf_index"))
    except (TypeError, ValueError):
        tree_size = -1
        leaf_index = -1
        diagnostics.append("Transparency receipt has invalid tree_size or leaf_index.")

    if sth.get("tree_size") != tree_size:
        diagnostics.append("Transparency receipt tree_size does not match signed tree head.")
    if receipt.get("log_id") != sth.get("log_id"):
        diagnostics.append("Transparency receipt log_id does not match signed tree head.")

    leaf_bytes = leaf_bytes_for_attestation(attestation)
    expected_leaf_hash = leaf_hash(leaf_bytes).hex()
    if receipt.get("leaf_hash") != expected_leaf_hash:
        diagnostics.append("Transparency receipt leaf hash does not match attestation.")
    expected_attestation_digest = hashlib.sha256(canonical_json(attestation)).hexdigest()
    if receipt.get("attestation_digest_sha256") and receipt.get("attestation_digest_sha256") != expected_attestation_digest:
        diagnostics.append("Transparency receipt attestation digest does not match attestation.")

    try:
        root = bytes.fromhex(str(sth.get("root_hash") or ""))
        proof = [bytes.fromhex(str(item)) for item in (receipt.get("inclusion_proof") or [])]
    except ValueError as exc:
        root = b""
        proof = []
        diagnostics.append(f"Transparency proof contains invalid hex: {exc}")

    if root and tree_size >= 0:
        if not verify_inclusion(leaf_bytes, leaf_index, tree_size, proof, root):
            diagnostics.append("Transparency inclusion proof does not verify against the signed tree head.")

    accepted = not diagnostics and sth_ok
    return ReceiptVerificationResult(
        accepted=accepted,
        diagnostics=diagnostics,
        log_id=str(receipt.get("log_id") or sth.get("log_id") or "") or None,
        tree_size=tree_size if tree_size >= 0 else None,
        root_hash=str(sth.get("root_hash") or "") or None,
        leaf_hash=str(receipt.get("leaf_hash") or "") or None,
        signatures=statuses,
    )


def proof_to_hex(proof: list[bytes]) -> list[str]:
    return [item.hex() for item in proof]


def _inclusion_path(leaves: list[bytes], index: int) -> list[bytes]:
    if len(leaves) == 1:
        return []
    split = _largest_power_of_two_less_than(len(leaves))
    if index < split:
        return _inclusion_path(leaves[:split], index) + [merkle_root(leaves[split:])]
    return _inclusion_path(leaves[split:], index - split) + [merkle_root(leaves[:split])]


def _calculate_inclusion_root(
    current_hash: bytes,
    index: int,
    tree_size: int,
    proof: list[bytes],
    proof_index: int,
) -> tuple[bytes, int]:
    if tree_size == 1:
        return current_hash, proof_index
    split = _largest_power_of_two_less_than(tree_size)
    if index < split:
        left, consumed = _calculate_inclusion_root(current_hash, index, split, proof, proof_index)
        if consumed >= len(proof):
            raise ValueError("proof exhausted")
        return node_hash(left, proof[consumed]), consumed + 1
    right, consumed = _calculate_inclusion_root(current_hash, index - split, tree_size - split, proof, proof_index)
    if consumed >= len(proof):
        raise ValueError("proof exhausted")
    return node_hash(proof[consumed], right), consumed + 1


def _consistency_path(old_tree_size: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    if old_tree_size == len(leaves):
        return [] if complete else [merkle_root(leaves)]
    split = _largest_power_of_two_less_than(len(leaves))
    if old_tree_size <= split:
        return _consistency_path(old_tree_size, leaves[:split], complete) + [merkle_root(leaves[split:])]
    return _consistency_path(old_tree_size - split, leaves[split:], complete=False) + [merkle_root(leaves[:split])]


def _largest_power_of_two_less_than(value: int) -> int:
    if value <= 1:
        raise ValueError("value must be greater than one")
    return 1 << ((value - 1).bit_length() - 1)


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0
