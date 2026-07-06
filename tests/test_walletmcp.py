"""The agent-native MCP surface: JSON-RPC plumbing + structured errors.

Protocol plumbing and read-only tools are tested with a hand-sealed
wallet (no live quorum needed). The crypto tools (verify_inbound,
request_signature, posture_challenge) are covered by the live end-to-end
test when the real quorum + dogfood signer are present.
"""

import base64
import hashlib
import json
import stat
from pathlib import Path

import pytest

from pacta.quorum import binary_path
from pacta.signing import generate_ed25519_keypair
from pacta.wallet import Wallet
from pacta.walletmcp import TOOLS, WalletMCP


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


def _mcp(tmp_path):
    wallet = _seal_wallet(tmp_path, {"a": "accept", "b": "accept"}, tmp_path / "state")
    srv = WalletMCP(wallet.dir)
    return srv, wallet


def _call(srv, method, params=None, msg_id=1):
    return srv.handle({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})


def test_initialize_advertises_server(tmp_path):
    srv, _ = _mcp(tmp_path)
    res = _call(srv, "initialize")["result"]
    assert res["serverInfo"]["name"] == "warden"
    assert "protocolVersion" in res


def test_initialized_notification_has_no_response(tmp_path):
    srv, _ = _mcp(tmp_path)
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_tools_list_matches_declared(tmp_path):
    srv, _ = _mcp(tmp_path)
    names = {t["name"] for t in _call(srv, "tools/list")["result"]["tools"]}
    assert names == {t["name"] for t in TOOLS}
    assert "request_signature" in names


def test_every_tool_has_a_strict_schema():
    for tool in TOOLS:
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema.get("additionalProperties") is False, tool["name"]


def test_unknown_tool_is_jsonrpc_error(tmp_path):
    srv, _ = _mcp(tmp_path)
    res = _call(srv, "tools/call", {"name": "nope", "arguments": {}})
    assert res["error"]["code"] == -32602


def test_wallet_status_tool(tmp_path):
    srv, _ = _mcp(tmp_path)
    res = _call(srv, "tools/call", {"name": "wallet_status"})["result"]
    assert not res["isError"]
    assert res["structuredContent"]["type"] == "pacta.wallet.posture.v1"


def test_custody_card_is_self_proving_shape(tmp_path):
    srv, _ = _mcp(tmp_path)
    card = _call(srv, "tools/call", {"name": "custody_card"})["result"]["structuredContent"]
    assert card["type"] == "pacta.wallet.custody_card.v1"
    for member in card["quorum"]["members"]:
        assert "transparency_evidence" in member


def test_structured_error_on_bad_base64(tmp_path):
    srv, _ = _mcp(tmp_path)
    res = _call(srv, "tools/call", {
        "name": "verify_inbound",
        "arguments": {"payload_b64": "x", "signature_b64": "!!!", "public_key_b64": "!!!"},
    })["result"]
    assert res["isError"]
    body = res["structuredContent"]
    assert set(body) >= {"code", "reason", "missing", "remediation"}
    assert body["code"] == "MALFORMED_INTENT"


def test_explain_refusal_when_none(tmp_path):
    srv, _ = _mcp(tmp_path)
    res = _call(srv, "tools/call", {"name": "explain_refusal"})["result"]
    assert res["isError"]
    assert res["structuredContent"]["code"] == "EVIDENCE_REQUIRED"


def test_server_never_crashes_on_garbage(tmp_path):
    srv, _ = _mcp(tmp_path)
    # missing method
    res = _call(srv, "does/not/exist")
    assert res["error"]["code"] == -32601


def test_request_signature_and_verify_roundtrip_live(tmp_path):
    if not all(binary_path(b).exists() for b in ("dalek", "anza")):
        pytest.skip("real quorum not built")
    from pacta.dogfood import locate_verifier

    if locate_verifier() is None:
        pytest.skip("dogfood signer not built")
    # seal against the REAL default-location binaries
    real_hashes = {b: _sha256(binary_path(b).read_bytes()) for b in ("dalek", "anza", "risc0", "betrusted")
                   if binary_path(b).exists()}
    wallet = Wallet(tmp_path / "w")
    for sub in (wallet.keys_dir, wallet.incidents_dir, wallet.receipts_dir,
                wallet.quarantine_dir, wallet.airgap_dir / "outbox", wallet.airgap_dir / "inbox"):
        sub.mkdir(parents=True, exist_ok=True)
    members = [{
        "backend": b, "component": f"{b}-ed25519-verified", "semantics": "t", "entry_point": "t",
        "source_commit": "x", "repo_commit": "y", "binary_sha256": h, "backend_cfg": "t",
        "risk_tier": "R4",
        "evidence": {"leaf_hash": "00", "leaf_index": 0, "tree_size": 1, "inclusion_proof": [],
                     "sth": {"timestamp": "2099-01-01T00:00:00Z"}},
    } for b, h in real_hashes.items()]
    capsule = {"type": "pacta.wallet.custody_capsule.v1", "created_at": "2026-07-06T00:00:00Z",
               "members": members,
               "policy": {"require_unanimity": True, "min_members": 2, "require_tier": "R4",
                          "freshness_max_age_days": 0},
               "signing": {"backend": "test"}, "problems_at_init": []}
    wallet.capsule_path.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n")
    wallet._append_ledger("genesis", {"capsule_sha256": "x"})
    generate_ed25519_keypair(wallet.keys_dir / "warden.key.pem", wallet.keys_dir / "warden.pub.pem")

    srv = WalletMCP(wallet.dir)
    payload = b"live mcp roundtrip"
    res = _call(srv, "tools/call", {
        "name": "request_signature",
        "arguments": {"payload_b64": base64.b64encode(payload).decode(), "purpose": "test"},
    })["result"]
    assert not res["isError"], res["structuredContent"]
    sig = bytes.fromhex(res["structuredContent"]["signature_hex"])
    pub = bytes.fromhex(res["structuredContent"]["public_key_hex"])
    vi = _call(srv, "tools/call", {
        "name": "verify_inbound",
        "arguments": {
            "payload_b64": base64.b64encode(payload).decode(),
            "signature_b64": base64.b64encode(sig).decode(),
            "public_key_b64": base64.b64encode(pub).decode(),
        },
    })["result"]
    assert vi["structuredContent"]["classification"] == "unanimous-accept"
