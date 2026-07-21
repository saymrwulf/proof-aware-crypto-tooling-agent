"""Wallet core: ledger chaining, outbound firewall, latch, refusals.

Most tests seal a wallet by hand with fake verifier binaries so the
custody logic (hash-chained ledger, firewall quarantine, latch,
machine-actionable refusals) is exercised without cargo or the pinned
sources. A live integration test does the real R4 init against the built
quorum + fetched evidence when both are present, and skips otherwise.
"""

import hashlib
import json
import stat
from pathlib import Path

import pytest

from pacta.quorum import binary_path
from pacta.signing import generate_ed25519_keypair
from pacta.wallet import AirgapSigner, PendingAirgap, Refusal, Wallet


def _fake_member(path: Path, verdict: str) -> None:
    code = {"accept": 0, "reject": 1}[verdict]
    out = {"accept": "OK", "reject": "INVALID"}[verdict]
    path.write_text(f"#!/bin/sh\necho {out}\nexit {code}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _seal_wallet(tmp_path: Path, verdicts: dict[str, str], state_dir: Path) -> Wallet:
    """Create a wallet directory by hand: fake quorum members + a capsule
    that pins their hashes, bypassing the (separately tested) R4 gate."""
    state_dir.mkdir(parents=True, exist_ok=True)
    members = []
    for name, verdict in verdicts.items():
        binary = binary_path(name, state_dir)
        _fake_member(binary, verdict)
        members.append({
            "backend": name,
            "component": f"{name}-ed25519-verified",
            "semantics": "test",
            "entry_point": "test",
            "source_commit": "deadbeef" * 5,
            "repo_commit": "cafe" * 10,
            "binary_sha256": _sha256(binary.read_bytes()),
            "backend_cfg": "test",
            "risk_tier": "R4",
            "evidence": {"leaf_hash": "00", "leaf_index": 0, "tree_size": 1,
                         "inclusion_proof": [], "sth": {"timestamp": "2099-01-01T00:00:00Z"}},
        })
    wallet_dir = tmp_path / "w"
    wallet = Wallet(wallet_dir)
    for sub in (wallet.keys_dir, wallet.incidents_dir, wallet.receipts_dir,
                wallet.quarantine_dir, wallet.airgap_dir / "outbox", wallet.airgap_dir / "inbox"):
        sub.mkdir(parents=True, exist_ok=True)
    capsule = {
        "type": "pacta.wallet.custody_capsule.v1",
        "created_at": "2026-07-06T00:00:00Z",
        "members": members,
        "policy": {"require_unanimity": True, "min_members": 2, "require_tier": "R4",
                   "freshness_max_age_days": 0},
        "signing": {"backend": "test"},
        "problems_at_init": [],
    }
    capsule_bytes = json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode()
    wallet.capsule_path.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n")
    wallet._append_ledger("genesis", {"type": "pacta.wallet.ledger_genesis.v1",
                                       "capsule_sha256": _sha256(capsule_bytes)})
    generate_ed25519_keypair(wallet.keys_dir / "warden.key.pem", wallet.keys_dir / "warden.pub.pem")
    wallet._test_state_dir = state_dir  # type: ignore[attr-defined]
    return wallet


def _payload_intent(payload: bytes) -> dict:
    return {"purpose": "test signature", "payload_sha256": _sha256(payload)}


def test_ledger_is_hash_chained(tmp_path):
    from pacta.dogfood import locate_verifier

    if locate_verifier() is None:
        pytest.skip("dogfood signer not built")
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    payload = b"hello"
    wallet.request_signature(_payload_intent(payload), payload, state_dir=wallet._test_state_dir)
    ok, problems = wallet.verify_ledger()
    assert ok, problems
    # tamper with a middle entry and prove the chain catches it
    lines = wallet.ledger_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["body"]["intent"] = {"purpose": "SNEAKY"}
    lines[1] = json.dumps(entry, sort_keys=True)
    wallet.ledger_path.write_text("\n".join(lines) + "\n")
    ok2, problems2 = wallet.verify_ledger()
    assert not ok2 and problems2


def test_ledger_survives_concurrent_appends(tmp_path):
    # The single-flight lock must keep the chain intact under parallel writers
    # (two threads racing on the same wallet's ledger).
    import threading

    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    start = threading.Barrier(8)

    def worker(n):
        start.wait()
        for i in range(6):
            wallet._append_ledger("stress", {"worker": n, "i": i})

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok, problems = wallet.verify_ledger()
    assert ok, problems
    # genesis + 48 appends, all with unique strictly-increasing indices
    entries = wallet._ledger_entries()
    indices = [e["index"] for e in entries]
    assert indices == list(range(len(entries)))
    assert len(entries) == 1 + 8 * 6


def test_outbound_firewall_releases_when_quorum_agrees(tmp_path):
    from pacta.dogfood import locate_verifier

    if locate_verifier() is None:
        pytest.skip("dogfood signer not built")
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    payload = b"release me"
    result = wallet.request_signature(_payload_intent(payload), payload, state_dir=wallet._test_state_dir)
    assert not isinstance(result, Refusal)
    assert result["firewall"]["classification"] == "unanimous-accept"


def test_outbound_firewall_quarantines_and_latches(tmp_path):
    from pacta.dogfood import locate_verifier

    if locate_verifier() is None:
        pytest.skip("dogfood signer not built")
    # Members disagree on the produced signature -> quarantine + latch.
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "reject"}, tmp_path / "state")
    payload = b"tampered path"
    result = wallet.request_signature(_payload_intent(payload), payload, state_dir=wallet._test_state_dir)
    assert isinstance(result, Refusal)
    assert result.code == "FIREWALL_QUARANTINE"
    assert wallet.latch_state()["latched"]
    assert list(wallet.quarantine_dir.glob("*.json"))
    # once latched, further outbound is refused with CUSTODY_LATCHED
    again = wallet.request_signature(_payload_intent(b"x"), b"x", state_dir=wallet._test_state_dir)
    assert isinstance(again, Refusal) and again.code == "CUSTODY_LATCHED"
    # and the latched refusal is honestly unsigned
    assert again.receipt["signature"]["status"] == "unsigned"


def test_unlatch_records_note(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "reject"}, tmp_path / "state")
    wallet._latch("test latch", "0000")
    assert wallet.latch_state()["latched"]
    wallet.unlatch("operator reviewed incident 0000, false alarm")
    assert not wallet.latch_state()["latched"]
    entries = [e for e in wallet._ledger_entries() if e["entry_type"] == "unlatch"]
    assert entries and "false alarm" in entries[-1]["body"]["operator_note"]


def test_malformed_intent_refused(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    result = wallet.request_signature({"purpose": ""}, b"data", state_dir=wallet._test_state_dir)
    assert isinstance(result, Refusal)
    assert result.code == "MALFORMED_INTENT"


def test_intent_must_bind_payload(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    bad = {"purpose": "ok", "payload_sha256": "wrong"}
    result = wallet.request_signature(bad, b"data", state_dir=wallet._test_state_dir)
    assert isinstance(result, Refusal) and result.code == "MALFORMED_INTENT"


def test_binary_hash_change_is_detected(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    # Swap a member binary for a different one; the capsule pin must catch it.
    _fake_member(binary_path("a", wallet._test_state_dir), "reject")
    from pacta.wallet import WalletError

    with pytest.raises(WalletError):
        wallet.quorum(state_dir=wallet._test_state_dir)


def test_airgap_signer_parks_then_completes(tmp_path):
    airgap = AirgapSigner(tmp_path / "airgap", wait_seconds=0.0)
    payload = b"cross the gap"
    with pytest.raises(PendingAirgap) as excinfo:
        airgap.sign(payload, tmp_path / "unused.pem", request_id="req1")
    assert (tmp_path / "airgap" / "outbox" / "req1.request.json").exists()
    # simulate the device dropping a response
    (tmp_path / "airgap" / "inbox" / "req1.response.json").write_text(
        json.dumps({"signature_hex": "ab" * 64})
    )
    sig = airgap.sign(payload, tmp_path / "unused.pem", request_id="req1")
    assert len(sig) == 64
    assert excinfo.value.request_id == "req1"


def test_real_wallet_init_r4_gate(tmp_path):
    """The showcase: real R4 init against built binaries + example evidence."""
    if not all(binary_path(b).exists() for b in ("dalek", "anza", "risc0", "betrusted")):
        pytest.skip("real quorum not built")
    evidence = Path("examples") / "wallet-evidence"
    log_key = evidence / "log.pub"
    if not evidence.exists() or not log_key.exists():
        pytest.skip("example wallet evidence / log key not present")
    wallet = Wallet.init(
        tmp_path / "w",
        evidence,
        log_key,
        trusted_provider="local-pacta-provider",
    )
    capsule = wallet.capsule()
    assert len(capsule["members"]) >= 2
    assert all(m["risk_tier"] == "R4" for m in capsule["members"])
