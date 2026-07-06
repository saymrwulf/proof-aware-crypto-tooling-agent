from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .transparency import verify_consistency

STORE_TYPE = "pacta.transparency.sth_store.v1"


@dataclass(slots=True)
class SthCheckResult:
    ok: bool
    diagnostics: list[str] = field(default_factory=list)
    action: str = "none"  # pinned_first_use | matched | advanced | rejected

    def evidence(self) -> dict[str, Any]:
        return {
            "transparency_sth_store_status": self.action if self.ok else "rejected",
            "transparency_sth_store_diagnostics": self.diagnostics,
        }


def load_store(path: str | Path) -> dict[str, Any]:
    store_path = Path(path)
    if not store_path.exists():
        return {"schema_version": 1, "type": STORE_TYPE, "logs": {}}
    raw = json.loads(store_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("type") != STORE_TYPE:
        raise ValueError(f"Not an STH store: {store_path}")
    raw.setdefault("logs", {})
    return raw


def save_store(store: dict[str, Any], path: str | Path) -> None:
    store_path = Path(path)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_sth_against_store(
    sth: dict[str, Any],
    store_path: str | Path,
    consistency_proof_hex: list[str] | None = None,
    consistency_from: dict[str, Any] | None = None,
    update: bool = True,
    now: datetime | None = None,
) -> SthCheckResult:
    """Split-view / rollback defense: compare a signed tree head against the
    locally pinned view of the same log.

    Policy:
    - unknown log_id: pin it (trust-on-first-use, recorded as such);
    - same tree_size: the root hash must match the pin exactly - two
      different roots at one size is EQUIVOCATION, a hard, unrecoverable
      rejection;
    - larger tree_size: a consistency proof from the PINNED size is
      required and must verify; only then does the pin advance;
    - smaller tree_size: log rollback - hard rejection.

    The consistency proof may come from the receipt itself (when the pinned
    size equals the receipt's from_tree_size) or from the provider's
    log-consistency command for older pins.
    """
    diagnostics: list[str] = []
    log_id = str(sth.get("log_id") or "")
    if not log_id:
        return SthCheckResult(False, ["Signed tree head has no log_id."], "rejected")
    try:
        tree_size = int(sth.get("tree_size"))
        root_hash = str(sth.get("root_hash") or "")
        assert root_hash
    except (TypeError, ValueError, AssertionError):
        return SthCheckResult(False, ["Signed tree head has invalid tree_size or root_hash."], "rejected")

    store = load_store(store_path)
    pinned = store["logs"].get(log_id)
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    if pinned is None:
        store["logs"][log_id] = {
            "tree_size": tree_size,
            "root_hash": root_hash,
            "sth_timestamp": sth.get("timestamp"),
            "first_seen": stamp,
            "last_updated": stamp,
            "trust_origin": "trust_on_first_use",
        }
        if update:
            save_store(store, store_path)
        return SthCheckResult(
            True,
            [f"Log {log_id[:16]}… pinned on first use at tree_size {tree_size} (trust-on-first-use)."],
            "pinned_first_use",
        )

    pinned_size = int(pinned["tree_size"])
    pinned_root = str(pinned["root_hash"])

    if tree_size == pinned_size:
        if root_hash == pinned_root:
            return SthCheckResult(True, [], "matched")
        return SthCheckResult(
            False,
            [
                "EQUIVOCATION: the log presented a different root hash at the pinned tree size "
                f"{pinned_size} (pinned {pinned_root[:16]}…, presented {root_hash[:16]}…). "
                "This log is maintaining a split view and must not be trusted again."
            ],
            "rejected",
        )

    if tree_size < pinned_size:
        return SthCheckResult(
            False,
            [
                f"LOG ROLLBACK: presented tree_size {tree_size} is smaller than the pinned size "
                f"{pinned_size}. Append-only logs never shrink. If this receipt is simply STALE "
                "(issued before the log grew), request a freshly issued receipt for the same "
                "leaf - the provider's log-append is idempotent and re-issues an inclusion "
                "proof against the current tree."
            ],
            "rejected",
        )

    # tree grew: demand a consistency proof from the pinned size
    proof_hex = None
    if consistency_from is not None:
        from_size = int(consistency_from.get("from_tree_size", -1))
        from_root = str(consistency_from.get("from_root_hash") or "")
        if from_size == pinned_size:
            if from_root != pinned_root:
                return SthCheckResult(
                    False,
                    [
                        "EQUIVOCATION: the receipt's consistency anchor disagrees with the pinned root at "
                        f"tree_size {pinned_size}."
                    ],
                    "rejected",
                )
            proof_hex = list(consistency_from.get("proof") or [])
    if proof_hex is None and consistency_proof_hex is not None:
        proof_hex = list(consistency_proof_hex)
    if proof_hex is None:
        return SthCheckResult(
            False,
            [
                f"The log grew from pinned size {pinned_size} to {tree_size} but no consistency proof "
                "from the pinned size was supplied. Obtain one (provider: log-consistency "
                f"--from-size {pinned_size}) - growth without proof is indistinguishable from a split view."
            ],
            "rejected",
        )
    try:
        proof = [bytes.fromhex(item) for item in proof_hex]
        old_root = bytes.fromhex(pinned_root)
        new_root = bytes.fromhex(root_hash)
    except ValueError as exc:
        return SthCheckResult(False, [f"Consistency proof contains invalid hex: {exc}"], "rejected")
    if not verify_consistency(pinned_size, tree_size, old_root, new_root, proof):
        return SthCheckResult(
            False,
            [
                f"Consistency proof from pinned size {pinned_size} to {tree_size} does NOT verify: "
                "the new tree is not an append-only extension of the pinned tree."
            ],
            "rejected",
        )
    pinned.update(
        {
            "tree_size": tree_size,
            "root_hash": root_hash,
            "sth_timestamp": sth.get("timestamp"),
            "last_updated": stamp,
        }
    )
    if update:
        save_store(store, store_path)
    return SthCheckResult(
        True,
        [f"Pin advanced {pinned_size} → {tree_size} with a verified consistency proof."],
        "advanced",
    )


def check_sth_freshness(
    sth: dict[str, Any],
    max_age_seconds: int,
    now: datetime | None = None,
) -> tuple[bool, str | None]:
    """Stale-root defense: an old-but-valid STH can hide later log entries
    (or later revocations). Policies that require freshness reject tree
    heads older than max_age_seconds."""
    raw = sth.get("timestamp")
    if not raw:
        return False, "Signed tree head has no timestamp; freshness policy cannot be evaluated."
    try:
        stamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return False, f"Signed tree head timestamp is not ISO 8601: {raw!r}"
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age = (current - stamp).total_seconds()
    if age < 0:
        return False, f"Signed tree head timestamp is {int(-age)}s in the future; clock skew or forgery."
    if age > max_age_seconds:
        return False, (
            f"Signed tree head is {int(age)}s old, beyond the freshness policy of {max_age_seconds}s. "
            "Request a fresh tree head from the provider."
        )
    return True, None
