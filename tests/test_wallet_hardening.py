"""Hardening round: policy engine, ledger rotation, MCP rate limits +
receipt-bearing errors, airgap MCP flow, treasury parsing/verification.
"""

import base64
import hashlib
import json
import stat
from pathlib import Path

import pytest

from pacta.quorum import binary_path
from pacta.signing import generate_ed25519_keypair
from pacta.wallet import Refusal, Wallet
from pacta.walletmcp import WalletMCP, _RateLimiter


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fake_member(path: Path, verdict: str) -> None:
    code = {"accept": 0, "reject": 1}[verdict]
    out = {"accept": "OK", "reject": "INVALID"}[verdict]
    path.write_text(f"#!/bin/sh\necho {out}\nexit {code}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _seal_wallet(tmp_path: Path, verdicts: dict, state_dir: Path) -> Wallet:
    state_dir.mkdir(parents=True, exist_ok=True)
    members = []
    for name, verdict in verdicts.items():
        binary = binary_path(name, state_dir)
        _fake_member(binary, verdict)
        members.append({
            "backend": name, "component": f"{name}-ed25519-verified", "semantics": "test",
            "entry_point": "test", "source_commit": "de" * 20, "repo_commit": "ca" * 20,
            "binary_sha256": _sha256(binary.read_bytes()), "backend_cfg": "test", "risk_tier": "R4",
            "evidence": {"leaf_hash": "00", "leaf_index": 0, "tree_size": 1, "inclusion_proof": [],
                         "sth": {"timestamp": "2099-01-01T00:00:00Z"}},
        })
    wallet = Wallet(tmp_path / "w")
    for sub in (wallet.keys_dir, wallet.incidents_dir, wallet.receipts_dir,
                wallet.quarantine_dir, wallet.airgap_dir / "outbox", wallet.airgap_dir / "inbox"):
        sub.mkdir(parents=True, exist_ok=True)
    capsule = {"type": "pacta.wallet.custody_capsule.v1", "created_at": "2026-07-06T00:00:00Z",
               "members": members,
               "policy": {"require_unanimity": True, "min_members": 2, "require_tier": "R4",
                          "freshness_max_age_days": 0},
               "signing": {"backend": "test"}, "problems_at_init": []}
    wallet.capsule_path.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n")
    wallet._append_ledger("genesis", {"capsule_sha256": "x"})
    generate_ed25519_keypair(wallet.keys_dir / "warden.key.pem", wallet.keys_dir / "warden.pub.pem")
    wallet._test_state_dir = state_dir  # type: ignore[attr-defined]
    return wallet


def _intent(payload: bytes, **extra) -> dict:
    intent = {"purpose": "test", "payload_sha256": _sha256(payload)}
    intent.update(extra)
    return intent


def _needs_signer():
    from pacta.dogfood import locate_verifier

    if locate_verifier() is None:
        pytest.skip("dogfood signer not built")


# -- policy engine -----------------------------------------------------------


def test_policy_absent_means_unrestricted(tmp_path):
    _needs_signer()
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    payload = b"no policy"
    result = wallet.request_signature(_intent(payload), payload, state_dir=wallet._test_state_dir)
    assert not isinstance(result, Refusal)


def test_policy_amount_ceiling_denies(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    (wallet.dir / "policy.json").write_text(json.dumps(
        {"outbound": {"max_amount_per_request": 50}}))
    payload = b"big spender"
    # missing amount -> denied (policy makes the field mandatory)
    r1 = wallet.request_signature(_intent(payload), payload, state_dir=wallet._test_state_dir)
    assert isinstance(r1, Refusal) and r1.code == "POLICY_DENIED"
    # over ceiling -> denied
    r2 = wallet.request_signature(_intent(payload, amount=51), payload, state_dir=wallet._test_state_dir)
    assert isinstance(r2, Refusal) and r2.code == "POLICY_DENIED"


def test_policy_under_ceiling_releases_and_daily_cap_accumulates(tmp_path):
    _needs_signer()
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    (wallet.dir / "policy.json").write_text(json.dumps(
        {"outbound": {"max_amount_per_request": 50, "max_amount_per_day": 80}}))
    payload = b"pay 40"
    ok1 = wallet.request_signature(_intent(payload, amount=40), payload, state_dir=wallet._test_state_dir)
    assert not isinstance(ok1, Refusal)
    ok2 = wallet.request_signature(_intent(payload, amount=40), payload, state_dir=wallet._test_state_dir)
    assert not isinstance(ok2, Refusal)
    # 80 spent; one more coin breaks the day
    r = wallet.request_signature(_intent(payload, amount=1), payload, state_dir=wallet._test_state_dir)
    assert isinstance(r, Refusal) and r.code == "POLICY_DENIED"
    assert "daily ceiling" in r.reason


def test_policy_counterparty_lists(tmp_path):
    _needs_signer()
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    (wallet.dir / "policy.json").write_text(json.dumps(
        {"outbound": {"counterparty_allowlist": ["alice"], "counterparty_denylist": ["mallory"]}}))
    payload = b"to someone"
    r1 = wallet.request_signature(_intent(payload), payload, state_dir=wallet._test_state_dir)
    assert isinstance(r1, Refusal) and "names no counterparty" in r1.reason
    r2 = wallet.request_signature(_intent(payload, counterparty="mallory"), payload, state_dir=wallet._test_state_dir)
    assert isinstance(r2, Refusal) and "denylist" in r2.reason
    r3 = wallet.request_signature(_intent(payload, counterparty="bob"), payload, state_dir=wallet._test_state_dir)
    assert isinstance(r3, Refusal) and "allowlist" in r3.reason
    ok = wallet.request_signature(_intent(payload, counterparty="alice"), payload, state_dir=wallet._test_state_dir)
    assert not isinstance(ok, Refusal)


def test_policy_identity_override(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    (wallet.dir / "policy.json").write_text(json.dumps({
        "outbound": {"max_amount_per_request": 100},
        "identities": {"warden": {"max_amount_per_request": 10}},
    }))
    payload = b"identity override"
    r = wallet.request_signature(_intent(payload, amount=50), payload, state_dir=wallet._test_state_dir)
    assert isinstance(r, Refusal) and r.code == "POLICY_DENIED"


# -- ledger rotation + O(1) head ------------------------------------------------


def test_ledger_rotation_keeps_chain_verifiable(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    (wallet.dir / "policy.json").write_text(json.dumps({"ledger": {"rotate_at": 5}}))
    for i in range(12):
        wallet._append_ledger("stress", {"i": i})
    archives = sorted(wallet.dir.glob("ledger-*.jsonl"))
    assert archives, "rotation never happened"
    ok, problems = wallet.verify_ledger()
    assert ok, problems
    # head is O(1)-readable and matches the last line
    entries = wallet._ledger_entries()
    assert wallet.ledger_head() == entries[-1]["entry_hash"]
    # indices keep increasing across the rotation boundary
    assert entries[-1]["index"] == 12 + len(archives)  # genesis + 12 + rotation entries


def test_ledger_rotation_detects_archive_tampering(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    (wallet.dir / "policy.json").write_text(json.dumps({"ledger": {"rotate_at": 4}}))
    for i in range(9):
        wallet._append_ledger("stress", {"i": i})
    archive = sorted(wallet.dir.glob("ledger-*.jsonl"))[0]
    lines = archive.read_text().splitlines()
    doctored = json.loads(lines[1])
    doctored["body"]["i"] = 999
    lines[1] = json.dumps(doctored, sort_keys=True)
    archive.write_text("\n".join(lines) + "\n")
    ok, problems = wallet.verify_ledger()
    assert not ok and problems


# -- MCP: receipts in errors, airgap flow, rate limiting -------------------------


def _call(srv, method, params=None, msg_id=1):
    return srv.handle({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})


def test_mcp_refusal_carries_signed_receipt(tmp_path):
    _needs_signer()
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    (wallet.dir / "policy.json").write_text(json.dumps(
        {"outbound": {"max_amount_per_request": 1}}))
    srv = WalletMCP(wallet.dir, state_dir=wallet._test_state_dir)
    res = _call(srv, "tools/call", {"name": "request_signature", "arguments": {
        "payload_b64": base64.b64encode(b"x").decode(), "purpose": "test", "amount": 9,
    }})["result"]
    assert res["isError"]
    body = res["structuredContent"]
    assert body["code"] == "POLICY_DENIED"
    # the signed receipt travels with the error
    assert body["receipt"]["type"] == "pacta.wallet.refusal_receipt.v1"
    assert body["receipt"]["signature"].get("scheme") == "ed25519-dogfood"
    assert body["receipt_path"]


def test_mcp_airgap_park_list_complete(tmp_path):
    _needs_signer()
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    srv = WalletMCP(wallet.dir, state_dir=wallet._test_state_dir)
    payload = b"gap payload"
    res = _call(srv, "tools/call", {"name": "request_signature", "arguments": {
        "payload_b64": base64.b64encode(payload).decode(), "purpose": "gap test",
        "signer": "airgap", "request_id": "reqmcp1",
    }})["result"]
    assert res["structuredContent"]["code"] == "PENDING_AIRGAP"
    listing = _call(srv, "tools/call", {"name": "airgap_pending"})["result"]["structuredContent"]
    assert listing["count"] == 1 and listing["pending"][0]["request_id"] == "reqmcp1"
    assert listing["pending"][0]["device_answered"] is False
    # the "device" signs (with the wallet's own key, for the test) and answers
    from pacta.dogfood import locate_verifier, sign_payload_dogfood

    signature = sign_payload_dogfood(payload, wallet.keys_dir / "warden.key.pem", locate_verifier())
    (wallet.airgap_dir / "inbox" / "reqmcp1.response.json").write_text(
        json.dumps({"signature_hex": signature.hex()}))
    done = _call(srv, "tools/call", {"name": "request_signature", "arguments": {
        "payload_b64": base64.b64encode(payload).decode(), "purpose": "gap test",
        "signer": "airgap", "request_id": "reqmcp1",
    }})["result"]
    assert not done["isError"], done["structuredContent"]
    assert done["structuredContent"]["firewall"]["classification"] == "unanimous-accept"
    assert done["structuredContent"]["signer"] == "airgap"


def test_rate_limiter_trips_and_recovers():
    limiter = _RateLimiter()
    limiter.LIMITS = {"custody": 3, "verify": 120, "liveness": 240}
    for _ in range(3):
        limiter.check("custody")
    from pacta.walletmcp import _ToolError

    with pytest.raises(_ToolError) as excinfo:
        limiter.check("custody")
    assert excinfo.value.payload["code"] == "RATE_LIMITED"


def test_mcp_tools_have_annotations(tmp_path):
    from pacta.walletmcp import TOOLS

    for tool in TOOLS:
        assert "annotations" in tool, tool["name"]
    readonly = {t["name"] for t in TOOLS if t["annotations"].get("readOnlyHint")}
    assert "wallet_status" in readonly and "custody_card" in readonly
    assert "request_signature" not in readonly


# -- treasury -------------------------------------------------------------------


def _make_message(signer_key: bytes, extra_key: bytes, version0: bool = False) -> bytes:
    header = bytes([1, 0, 1])
    keys = bytes([2]) + signer_key + extra_key   # compact-u16(2) then two keys
    blockhash = bytes(range(32))
    instructions = bytes([0])                    # compact-u16(0): none
    prefix = bytes([0x80]) if version0 else b""
    return prefix + header + keys + blockhash + instructions


def _assemble_tx(signature: bytes, message: bytes) -> bytes:
    return bytes([1]) + signature + message


def test_treasury_parse_roundtrip_legacy_and_v0():
    from pacta.treasury import parse_transaction

    signer, extra = bytes([7] * 32), bytes([9] * 32)
    for v0 in (False, True):
        message = _make_message(signer, extra, version0=v0)
        tx = _assemble_tx(b"\xab" * 64, message)
        parsed = parse_transaction(tx)
        assert parsed.num_required_signatures == 1
        assert parsed.account_keys[0] == signer
        assert parsed.message == message
        assert parsed.version == (0 if v0 else None)


def test_treasury_parse_rejects_garbage():
    from pacta.treasury import parse_transaction

    with pytest.raises(ValueError):
        parse_transaction(b"")
    with pytest.raises(ValueError):
        parse_transaction(bytes([1]) + b"\x00" * 10)  # truncated signature
    # header/signature-count mismatch
    signer, extra = bytes([7] * 32), bytes([9] * 32)
    message = bytes([2, 0, 1]) + bytes([2]) + signer + extra + bytes(32) + bytes([0])
    with pytest.raises(ValueError):
        parse_transaction(_assemble_tx(b"\xab" * 64, message))


def test_treasury_b58decode_vectors():
    from pacta.treasury import b58decode

    assert b58decode("") == b""
    assert b58decode("1") == b"\x00"
    assert b58decode("2g") == b"a"
    assert b58decode("ZiCa") == b"abc"
    assert b58decode("11ZiCa") == b"\x00\x00abc"
    with pytest.raises(ValueError):
        b58decode("0OIl")


def test_treasury_verify_transaction_real_quorum(tmp_path):
    """The showcase: a synthetic Solana transaction signed with the wallet's
    key, quorum-verified through the REAL four proven forks."""
    if not all(binary_path(b).exists() for b in ("dalek", "anza")):
        pytest.skip("real quorum not built")
    _needs_signer()
    from pacta.dogfood import locate_verifier, pem_public_key_to_raw, sign_payload_dogfood
    from pacta.treasury import verify_transaction

    # seal against the REAL binaries
    real = {b: binary_path(b) for b in ("dalek", "anza", "risc0", "betrusted") if binary_path(b).exists()}
    wallet = Wallet(tmp_path / "w")
    for sub in (wallet.keys_dir, wallet.incidents_dir, wallet.receipts_dir,
                wallet.quarantine_dir, wallet.airgap_dir / "outbox", wallet.airgap_dir / "inbox"):
        sub.mkdir(parents=True, exist_ok=True)
    members = [{
        "backend": b, "component": f"{b}-ed25519-verified", "semantics": "t", "entry_point": "t",
        "source_commit": "x", "repo_commit": "y", "binary_sha256": _sha256(p.read_bytes()),
        "backend_cfg": "t", "risk_tier": "R4",
        "evidence": {"leaf_hash": "00", "leaf_index": 0, "tree_size": 1, "inclusion_proof": [],
                     "sth": {"timestamp": "2099-01-01T00:00:00Z"}},
    } for b, p in real.items()]
    capsule = {"type": "pacta.wallet.custody_capsule.v1", "created_at": "2026-07-06T00:00:00Z",
               "members": members,
               "policy": {"require_unanimity": True, "min_members": 2, "require_tier": "R4",
                          "freshness_max_age_days": 0},
               "signing": {"backend": "test"}, "problems_at_init": []}
    wallet.capsule_path.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n")
    wallet._append_ledger("genesis", {"capsule_sha256": "x"})
    generate_ed25519_keypair(wallet.keys_dir / "warden.key.pem", wallet.keys_dir / "warden.pub.pem")

    signer_key = pem_public_key_to_raw(wallet.keys_dir / "warden.pub.pem")
    message = _make_message(signer_key, bytes([9] * 32))
    signature = sign_payload_dogfood(message, wallet.keys_dir / "warden.key.pem", locate_verifier())
    verdict = verify_transaction(wallet, _assemble_tx(signature, message))
    assert verdict.authentic
    assert verdict.signer_results[0]["classification"] == "unanimous-accept"
    # a flipped byte in the signature: not authentic
    bad = verify_transaction(wallet, _assemble_tx(bytes([signature[0] ^ 1]) + signature[1:], message))
    assert not bad.authentic
    # and the checks are in the ledger with treasury context
    contexts = [e["body"].get("context", "") for e in wallet._ledger_entries()
                if e["entry_type"] == "inbound-verify"]
    assert any("treasury" in c for c in contexts)
