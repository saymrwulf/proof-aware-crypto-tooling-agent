"""Witness audit over the PUBLISHED log repository.

The git-published log (entries/ + sth-history.jsonl + provider key) turns
every cloner into a witness: since all leaves are public, a witness does
not need consistency proofs at all - it recomputes the root of every
prefix directly and checks every historical Signed Tree Head against its
prefix root and its signature. Two different clones agreeing on the git
history and both passing this audit have PROOF the provider never
equivocated within it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .signing import canonical_json
from .transparency import leaf_hash, merkle_root, verify_signed_tree_head


@dataclass(slots=True)
class WitnessReport:
    ok: bool
    tree_size: int
    heads_checked: int
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def audit_published_log(
    published_dir: str | Path,
    log_public_key_path: str | Path | None = None,
) -> WitnessReport:
    root_dir = Path(published_dir)
    problems: list[str] = []
    notes: list[str] = []

    entry_files = sorted((root_dir / "entries").glob("[0-9]*.json"))
    leaves: list[bytes] = []
    for position, path in enumerate(entry_files):
        record = json.loads(path.read_text(encoding="utf-8"))
        if int(record.get("index", -1)) != position:
            problems.append(f"{path.name}: index {record.get('index')} at position {position} (gap or reorder).")
        leaf_bytes = canonical_json(record["leaf"])
        if leaf_hash(leaf_bytes).hex() != record.get("leaf_hash"):
            problems.append(f"{path.name}: leaf_hash does not match the leaf content.")
        leaves.append(leaf_bytes)

    history_path = root_dir / "sth-history.jsonl"
    heads = [
        json.loads(line)
        for line in history_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if history_path.exists() else []
    if not heads:
        notes.append("No sth-history.jsonl; only the latest head can be checked.")
        latest_path = root_dir / "latest-sth.json"
        if latest_path.exists():
            heads = [json.loads(latest_path.read_text(encoding="utf-8"))]

    previous_size = -1
    for position, head in enumerate(heads):
        size = int(head.get("tree_size", -1))
        if size < previous_size:
            problems.append(f"STH #{position}: tree_size {size} SHRANK from {previous_size} (rollback in history).")
        previous_size = max(previous_size, size)
        if size < 0 or size > len(leaves):
            problems.append(f"STH #{position}: tree_size {size} outside published entries ({len(leaves)}).")
            continue
        expected_root = merkle_root(leaves[:size]).hex()
        if head.get("root_hash") != expected_root:
            problems.append(
                f"STH #{position} (size {size}): signed root {str(head.get('root_hash'))[:16]}… does not match "
                f"the recomputed prefix root {expected_root[:16]}… - EQUIVOCATION or tampered entries."
            )
        if log_public_key_path is not None:
            ok, diagnostics, _statuses = verify_signed_tree_head(head, log_public_key_path)
            if not ok:
                problems.append(f"STH #{position} (size {size}): signature check failed: {'; '.join(diagnostics)}")

    if log_public_key_path is None:
        notes.append("No public key supplied; structural audit only (signatures unchecked).")
    return WitnessReport(
        ok=not problems,
        tree_size=len(leaves),
        heads_checked=len(heads),
        problems=problems,
        notes=notes,
    )
