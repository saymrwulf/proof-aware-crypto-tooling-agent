from datetime import datetime, timezone

from pacta.sthstore import check_sth_against_store, check_sth_freshness
from pacta.transparency import consistency_proof, merkle_root, proof_to_hex


def _sth(size, root, log_id="log-1", timestamp="2026-07-06T00:00:00Z"):
    return {"log_id": log_id, "tree_size": size, "root_hash": root, "timestamp": timestamp}


def _tree(n):
    return [f"leaf-{i}".encode() for i in range(n)]


def test_first_use_pins_then_same_size_must_match(tmp_path):
    store = tmp_path / "sth.json"
    root = merkle_root(_tree(3)).hex()
    first = check_sth_against_store(_sth(3, root), store)
    assert first.ok and first.action == "pinned_first_use"
    again = check_sth_against_store(_sth(3, root), store)
    assert again.ok and again.action == "matched"
    evil = check_sth_against_store(_sth(3, merkle_root(_tree(4)).hex()), store)
    assert not evil.ok
    assert any("EQUIVOCATION" in d for d in evil.diagnostics)


def test_growth_requires_consistency_proof_and_advances(tmp_path):
    store = tmp_path / "sth.json"
    leaves = _tree(5)
    old_root = merkle_root(leaves[:2]).hex()
    new_root = merkle_root(leaves).hex()
    assert check_sth_against_store(_sth(2, old_root), store).ok
    # growth without proof: rejected
    bare = check_sth_against_store(_sth(5, new_root), store)
    assert not bare.ok and any("consistency proof" in d for d in bare.diagnostics)
    # growth with a valid proof: pin advances
    proof = proof_to_hex(consistency_proof(leaves, 2))
    good = check_sth_against_store(_sth(5, new_root), store, consistency_proof_hex=proof)
    assert good.ok and good.action == "advanced"
    # and the pin really moved
    assert check_sth_against_store(_sth(5, new_root), store).action == "matched"


def test_receipt_embedded_consistency_anchor_is_checked(tmp_path):
    store = tmp_path / "sth.json"
    leaves = _tree(4)
    old_root = merkle_root(leaves[:3]).hex()
    new_root = merkle_root(leaves).hex()
    assert check_sth_against_store(_sth(3, old_root), store).ok
    # anchor size matches the pin but anchor ROOT lies about history
    lying_anchor = {
        "from_tree_size": 3,
        "from_root_hash": merkle_root(_tree(9)).hex(),
        "proof": proof_to_hex(consistency_proof(leaves, 3)),
    }
    out = check_sth_against_store(_sth(4, new_root), store, consistency_from=lying_anchor)
    assert not out.ok and any("EQUIVOCATION" in d for d in out.diagnostics)
    honest_anchor = dict(lying_anchor, from_root_hash=old_root)
    assert check_sth_against_store(_sth(4, new_root), store, consistency_from=honest_anchor).ok


def test_rollback_is_rejected(tmp_path):
    store = tmp_path / "sth.json"
    assert check_sth_against_store(_sth(7, merkle_root(_tree(7)).hex()), store).ok
    rolled = check_sth_against_store(_sth(3, merkle_root(_tree(3)).hex()), store)
    assert not rolled.ok and any("ROLLBACK" in d for d in rolled.diagnostics)


def test_freshness_policy():
    now = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)
    fresh, _ = check_sth_freshness(_sth(1, "aa", timestamp="2026-07-06T11:59:30Z"), 60, now=now)
    assert fresh
    stale, error = check_sth_freshness(_sth(1, "aa", timestamp="2026-07-06T10:00:00Z"), 60, now=now)
    assert not stale and "freshness policy" in error
    future, error = check_sth_freshness(_sth(1, "aa", timestamp="2026-07-06T13:00:00Z"), 60, now=now)
    assert not future and "future" in error
    missing, error = check_sth_freshness({"log_id": "x"}, 60, now=now)
    assert not missing
