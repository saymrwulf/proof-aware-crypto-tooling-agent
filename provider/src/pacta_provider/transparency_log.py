from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pacta.signing import canonical_json
from pacta.transparency import (
    HASH_ALGORITHM,
    RECEIPT_TYPE,
    attestation_leaf,
    consistency_proof,
    inclusion_proof,
    leaf_bytes_for_attestation,
    leaf_hash,
    make_signed_tree_head,
    merkle_root,
    proof_to_hex,
)
from pacta.yamlio import dump_data, load_data


@dataclass(slots=True)
class LogEntry:
    index: int
    leaf: dict[str, Any]
    leaf_hash: str

    def leaf_bytes(self) -> bytes:
        return canonical_json(self.leaf)


class TransparencyLog:
    def __init__(self, log_dir: str | Path) -> None:
        self.log_dir = Path(log_dir)
        self.metadata_path = self.log_dir / "metadata.json"
        self.entries_path = self.log_dir / "entries.jsonl"
        self.sth_path = self.log_dir / "sth.yaml"

    def init(self, provider: str, public_key_path: str | Path) -> dict[str, Any]:
        if self.metadata_path.exists() or self.entries_path.exists():
            raise ValueError(f"Transparency log already exists: {self.log_dir}")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        public_key = Path(public_key_path).read_bytes()
        log_id = hashlib.sha256(b"pacta-log-v1\0" + provider.encode("utf-8") + b"\0" + public_key).hexdigest()
        metadata = {
            "schema_version": 1,
            "type": "pacta.transparency.log_metadata.v1",
            "provider": provider,
            "log_id": log_id,
            "hash_algorithm": HASH_ALGORITHM,
            "ed25519_public_key_fingerprint_sha256": hashlib.sha256(public_key).hexdigest(),
            "created_at": _now(),
            "standards": [
                "RFC 9162 Merkle tree hash and inclusion/consistency proof algorithms",
                "RFC 8032 Ed25519 signature verification via OpenSSL",
                "FIPS 204 ML-DSA signature slot; must be required by policy only when a backend is configured",
            ],
        }
        self.metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.entries_path.write_text("", encoding="utf-8")
        return metadata

    def metadata(self) -> dict[str, Any]:
        if not self.metadata_path.exists():
            raise ValueError(f"Transparency log is not initialized: {self.log_dir}")
        raw = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"Invalid transparency log metadata: {self.metadata_path}")
        return raw

    def entries(self) -> list[LogEntry]:
        if not self.entries_path.exists():
            return []
        entries: list[LogEntry] = []
        for line_number, line in enumerate(self.entries_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError(f"Invalid log entry at line {line_number}: {self.entries_path}")
            leaf = raw.get("leaf")
            if not isinstance(leaf, dict):
                raise ValueError(f"Invalid leaf at line {line_number}: {self.entries_path}")
            entries.append(LogEntry(index=int(raw["index"]), leaf=leaf, leaf_hash=str(raw["leaf_hash"])))
        return entries

    def latest_sth(
        self,
        private_key_path: str | Path,
        public_key_path: str | Path,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        metadata = self.metadata()
        leaves = [entry.leaf_bytes() for entry in self.entries()]
        sth = make_signed_tree_head(
            metadata["log_id"],
            len(leaves),
            merkle_root(leaves).hex(),
            timestamp or _now(),
            private_key_path,
            public_key_path,
        )
        dump_data(sth, self.sth_path)
        return sth

    def append_attestation(
        self,
        attestation_path: str | Path,
        private_key_path: str | Path,
        public_key_path: str | Path,
        receipt_out: str | Path | None = None,
    ) -> dict[str, Any]:
        metadata = self.metadata()
        attestation = load_data(attestation_path)
        if not isinstance(attestation, dict):
            raise ValueError(f"Attestation must be a mapping: {attestation_path}")
        entries = self.entries()
        previous_size = len(entries)
        previous_root = merkle_root([entry.leaf_bytes() for entry in entries]).hex()
        leaf = attestation_leaf(attestation)
        leaf_bytes = leaf_bytes_for_attestation(attestation)
        computed_leaf_hash = leaf_hash(leaf_bytes).hex()
        existing = next((entry for entry in entries if entry.leaf_hash == computed_leaf_hash), None)
        if existing:
            index = existing.index
            appended = False
        else:
            index = len(entries)
            record = {"index": index, "leaf_hash": computed_leaf_hash, "leaf": leaf}
            with self.entries_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            entries.append(LogEntry(index=index, leaf=leaf, leaf_hash=computed_leaf_hash))
            appended = True

        leaves = [entry.leaf_bytes() for entry in entries]
        sth = make_signed_tree_head(
            metadata["log_id"],
            len(leaves),
            merkle_root(leaves).hex(),
            _now(),
            private_key_path,
            public_key_path,
        )
        dump_data(sth, self.sth_path)
        consistency = []
        if appended and previous_size > 0:
            consistency = proof_to_hex(consistency_proof(leaves, previous_size))
        receipt = {
            "schema_version": 1,
            "type": RECEIPT_TYPE,
            "log_id": metadata["log_id"],
            "hash_algorithm": HASH_ALGORITHM,
            "attestation_path": str(attestation_path),
            "attestation_digest_sha256": hashlib.sha256(canonical_json(attestation)).hexdigest(),
            "leaf_index": index,
            "leaf_hash": computed_leaf_hash,
            "tree_size": len(leaves),
            "inclusion_proof": proof_to_hex(inclusion_proof(leaves, index)),
            "consistency": {
                "from_tree_size": previous_size,
                "from_root_hash": previous_root,
                "proof": consistency,
                "status": "not_applicable" if previous_size == 0 or not appended else "included",
            },
            "sth": sth,
        }
        if receipt_out:
            Path(receipt_out).parent.mkdir(parents=True, exist_ok=True)
            dump_data(receipt, receipt_out)
        return receipt


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
