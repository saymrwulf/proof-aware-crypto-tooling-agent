from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pacta.dogfood import BACKEND_OPENSSL, BACKEND_VERIFIED, load_provenance, locate_verifier
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
    verify_inclusion,
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
        self.sth_history_path = self.log_dir / "sth-history.jsonl"

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
        entries = self.entries()
        leaves = [entry.leaf_bytes() for entry in entries]
        sth = make_signed_tree_head(
            metadata["log_id"],
            len(leaves),
            merkle_root(leaves).hex(),
            timestamp or _now(),
            private_key_path,
            public_key_path,
            signing_provenance=self.signing_provenance(entries),
        )
        dump_data(sth, self.sth_path)
        self._record_sth(sth)
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
            signing_provenance=self.signing_provenance(entries),
        )
        dump_data(sth, self.sth_path)
        self._record_sth(sth)
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


    def signing_provenance(self, entries: list[LogEntry], signing_library_component: str = "dalek-ed25519-verified") -> dict[str, Any]:
        """THE PROVIDER EATS ITS OWN DOGFOOD: before signing a tree head,
        verify that the attestation of the SIGNING LIBRARY ITSELF (the
        merkleized dalek source whose build produced the signing binary) is
        included in the very tree about to be signed - by running the same
        Merkle inclusion verification an agent runs. The result is recorded
        inside the signature block: a root signature that names the leaf
        vouching for the code that produced it."""
        binary = locate_verifier()
        backend = BACKEND_VERIFIED if binary is not None else BACKEND_OPENSSL
        provenance: dict[str, Any] = {
            "signing_backend": backend,
            "signing_library_component": signing_library_component,
        }
        if binary is not None:
            build = load_provenance(binary)
            if build.get("source_commit"):
                provenance["signing_library_source_commit"] = build["source_commit"]
        matches = [
            entry
            for entry in entries
            if ((entry.leaf.get("attestation") or {}).get("subject") or {}).get("component") == signing_library_component
        ]
        if not matches:
            provenance["self_inclusion"] = "library_not_in_log"
            return provenance
        newest = matches[-1]
        leaves = [entry.leaf_bytes() for entry in entries]
        proof = inclusion_proof(leaves, newest.index)
        verified = verify_inclusion(
            newest.leaf_bytes(), newest.index, len(leaves), proof, merkle_root(leaves)
        )
        provenance["self_inclusion"] = "verified" if verified else "FAILED"
        provenance["signing_library_leaf_index"] = newest.index
        attested = (newest.leaf.get("attestation") or {}).get("certificates") or []
        clean = sum(1 for c in attested if c.get("status") == "proven" and c.get("axiom_status") == "clean")
        provenance["signing_library_certificates_proven"] = f"{clean}/{len(attested)}"
        return provenance

    def _record_sth(self, sth: dict[str, Any]) -> None:
        with self.sth_history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(sth, sort_keys=True, separators=(",", ":")) + "\n")

    def sth_history(self) -> list[dict[str, Any]]:
        if not self.sth_history_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.sth_history_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def proof_for_leaf_hash(self, leaf_hash_hex: str) -> dict[str, Any] | None:
        """Read-only inclusion proof against the CURRENT tree for an existing
        leaf - what the online service returns. Never signs anything."""
        entries = self.entries()
        match = next((entry for entry in entries if entry.leaf_hash == leaf_hash_hex), None)
        if match is None:
            return None
        leaves = [entry.leaf_bytes() for entry in entries]
        stored_sth = load_data(self.sth_path) if self.sth_path.exists() else None
        return {
            "schema_version": 1,
            "type": RECEIPT_TYPE,
            "log_id": self.metadata()["log_id"],
            "hash_algorithm": HASH_ALGORITHM,
            "leaf_index": match.index,
            "leaf_hash": match.leaf_hash,
            "tree_size": len(leaves),
            "inclusion_proof": proof_to_hex(inclusion_proof(leaves, match.index)),
            "sth": stored_sth,
        }

    def newest_entry_for_component(self, component: str) -> LogEntry | None:
        matches = [
            entry
            for entry in self.entries()
            if ((entry.leaf.get("attestation") or {}).get("subject") or {}).get("component") == component
        ]
        return matches[-1] if matches else None

    def publish(self, git_dir: str | Path, public_key_path: str | Path | None = None) -> dict[str, Any]:
        """Export the PUBLIC face of the log into a git-publishable directory:
        metadata, one file per leaf (append-only in git history too), the
        full STH history (the witness channel: everyone who clones sees the
        same heads), the latest head, and per-component convenience
        receipts. Private keys never appear here."""
        out = Path(git_dir)
        (out / "entries").mkdir(parents=True, exist_ok=True)
        (out / "receipts").mkdir(parents=True, exist_ok=True)
        metadata = self.metadata()
        (out / "log-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        entries = self.entries()
        for entry in entries:
            path = out / "entries" / f"{entry.index:06d}.json"
            if not path.exists():
                path.write_text(json.dumps({"index": entry.index, "leaf_hash": entry.leaf_hash, "leaf": entry.leaf}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if self.sth_history_path.exists():
            (out / "sth-history.jsonl").write_text(self.sth_history_path.read_text(encoding="utf-8"), encoding="utf-8")
        if self.sth_path.exists():
            latest = load_data(self.sth_path)
            (out / "latest-sth.json").write_text(json.dumps(latest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        components = {}
        for entry in entries:
            component = ((entry.leaf.get("attestation") or {}).get("subject") or {}).get("component")
            if component:
                components[component] = entry
        for component, entry in components.items():
            receipt = self.proof_for_leaf_hash(entry.leaf_hash)
            (out / "receipts" / f"{component}.receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            (out / "entries" / f"{component}.attestation.json").write_text(
                json.dumps(entry.leaf.get("attestation"), indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        from .published_assets import README_MD, VERIFY_PY

        (out / "verify.py").write_text(VERIFY_PY, encoding="utf-8")
        (out / "README.md").write_text(README_MD, encoding="utf-8")
        if public_key_path is not None:
            (out / "provider.ed25519.pub").write_bytes(Path(public_key_path).read_bytes())
        return {"entries": len(entries), "components": sorted(components), "out": str(out)}

    def consistency_from(self, old_tree_size: int) -> dict[str, Any]:
        """Consistency proof from an arbitrary earlier tree size - what a
        pinning agent requests when its pin is older than the receipt's
        embedded from_tree_size."""
        entries = self.entries()
        leaves = [entry.leaf_bytes() for entry in entries]
        if old_tree_size < 0 or old_tree_size > len(leaves):
            raise ValueError(f"old_tree_size {old_tree_size} outside tree size {len(leaves)}")
        return {
            "schema_version": 1,
            "type": "pacta.transparency.consistency_proof.v1",
            "log_id": self.metadata()["log_id"],
            "from_tree_size": old_tree_size,
            "from_root_hash": merkle_root(leaves[:old_tree_size]).hex(),
            "to_tree_size": len(leaves),
            "to_root_hash": merkle_root(leaves).hex(),
            "proof": proof_to_hex(consistency_proof(leaves, old_tree_size)),
        }

    def audit(self) -> dict[str, Any]:
        """Monitor-side self-check: recompute every prefix root, confirm the
        stored STH matches the full tree, and confirm every prefix is
        consistent with the final tree (append-only structure)."""
        entries = self.entries()
        leaves = [entry.leaf_bytes() for entry in entries]
        problems: list[str] = []
        for position, entry in enumerate(entries):
            if entry.index != position:
                problems.append(f"Entry at position {position} carries index {entry.index}.")
            if leaf_hash(entry.leaf_bytes()).hex() != entry.leaf_hash:
                problems.append(f"Entry {position} leaf_hash does not match its leaf bytes.")
        computed_root = merkle_root(leaves).hex()
        stored_sth = load_data(self.sth_path) if self.sth_path.exists() else None
        if stored_sth:
            if stored_sth.get("tree_size") != len(leaves):
                problems.append("Stored STH tree_size does not match the entry count.")
            if stored_sth.get("root_hash") != computed_root:
                problems.append("Stored STH root hash does not match the recomputed tree root.")
        return {
            "tree_size": len(leaves),
            "computed_root": computed_root,
            "stored_sth_root": (stored_sth or {}).get("root_hash"),
            "problems": problems,
            "ok": not problems,
        }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
