"""Cockpit tests: the design law is testable — every panel renders
recomputed evidence with provenance, failures render loud, and the HTTP
surface cannot mutate wallet state (asserted by hashing the wallet
directory before and after a full request sweep, including a POST)."""

import hashlib
import json
import stat
import threading
import urllib.request
import urllib.parse
from pathlib import Path

import pytest

from pacta.quorum import binary_path
from pacta.signing import generate_ed25519_keypair
from pacta.wallet import Wallet
from pacta.walletui import (collect, collect_airgap, collect_incidents,
                            collect_refusals, inspect_receipt, render_incidents,
                            render_inspect, render_posture, render_queue, serve)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fake_member(path: Path, verdict: str) -> None:
    code = {"accept": 0, "reject": 1}[verdict]
    out = {"accept": "OK", "reject": "INVALID"}[verdict]
    path.write_text(f"#!/bin/sh\necho {out}\nexit {code}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _seal_wallet(tmp_path: Path) -> Wallet:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    members = []
    for name in ("dalek", "anza"):
        binary = binary_path(name, state_dir)
        _fake_member(binary, "accept")
        members.append({
            "backend": name,
            "component": f"{name}-ed25519-verified",
            "semantics": "test", "entry_point": "test",
            "source_commit": "deadbeef" * 5, "repo_commit": "cafe" * 10,
            "binary_sha256": _sha256(binary.read_bytes()),
            "backend_cfg": "test", "risk_tier": "R4",
            "evidence": {"leaf_hash": "00", "leaf_index": 0, "tree_size": 1,
                         "inclusion_proof": [],
                         "sth": {"timestamp": "2099-01-01T00:00:00Z"}},
        })
    wallet = Wallet(tmp_path / "w")
    for sub in (wallet.keys_dir, wallet.incidents_dir, wallet.receipts_dir,
                wallet.quarantine_dir, wallet.airgap_dir / "outbox",
                wallet.airgap_dir / "inbox"):
        sub.mkdir(parents=True, exist_ok=True)
    capsule = {
        "type": "pacta.wallet.custody_capsule.v1",
        "created_at": "2026-07-06T00:00:00Z", "members": members,
        "policy": {"require_unanimity": True, "min_members": 2,
                   "require_tier": "R4", "freshness_max_age_days": 0},
        "signing": {"backend": "test"}, "problems_at_init": [],
    }
    capsule_bytes = json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode()
    wallet.capsule_path.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n")
    wallet._append_ledger("genesis", {"type": "pacta.wallet.ledger_genesis.v1",
                                      "capsule_sha256": _sha256(capsule_bytes)})
    generate_ed25519_keypair(wallet.keys_dir / "warden.key.pem",
                             wallet.keys_dir / "warden.pub.pem")
    return wallet


def _dir_fingerprint(root: Path) -> dict[str, str]:
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[str(path.relative_to(root))] = _sha256(path.read_bytes())
    return out


def test_posture_renders_recomputed_evidence(tmp_path):
    wallet = _seal_wallet(tmp_path)
    html = render_posture(collect("Wallet.posture()", wallet.posture))
    assert "CUSTODY HEALTHY" in html  # the verdict, in words, before any evidence
    assert "chain verified" in html
    assert "unlatched" in html
    assert "dalek-ed25519-verified" in html and "anza-ed25519-verified" in html
    assert "recomputed" in html and "Wallet.verify_ledger()" in html
    # the panel states its own honesty boundary
    assert "does NOT" in html and "reproducible builds" in html.lower()


def test_broken_ledger_renders_red(tmp_path):
    wallet = _seal_wallet(tmp_path)
    ledger = wallet.dir / "ledger.jsonl"
    ledger.write_text(ledger.read_text().replace("genesis", "gene-sis"), encoding="utf-8")
    html = render_posture(collect("Wallet.posture()", wallet.posture))
    assert "CHAIN BROKEN" in html
    assert "CUSTODY EVIDENCE BROKEN" in html  # verdict banner states it in words


def test_collector_failure_is_loud_not_gray(tmp_path):
    def boom():
        raise RuntimeError("evidence unavailable")
    html = render_posture(collect("Wallet.posture()", boom))
    assert "FAILED TO VERIFY" in html and "evidence unavailable" in html
    assert "pill ok" not in html  # no green anywhere on a failed panel


def test_latched_state_renders_frozen():
    posture = {"ok": True, "via": "x", "data": {
        "capsule_sha256": "ab" * 32,
        "members": [], "policy": {}, "spending_policy": {},
        "latch": {"latched": True, "reason": "quorum divergence",
                  "incident": "incident-1.json", "at": "2026-07-19T00:00:00Z"},
        "ledger": {"entries": 1, "head": "cd" * 32, "chain_ok": True, "problems": []},
        "incidents": 1, "refusal_receipts": 0, "generated_at": "now"}}
    html = render_posture(posture)
    assert "CUSTODY FROZEN" in html  # verdict banner states it in words
    assert "LATCHED" in html and "outbound custody frozen" in html
    assert "quorum divergence" in html and "runbook-latch" in html


def test_queue_lists_airgap_requests(tmp_path):
    wallet = _seal_wallet(tmp_path)
    outbox = wallet.airgap_dir / "outbox"
    (outbox / "req-1.request.json").write_text(json.dumps(
        {"created_at": "2026-07-19T00:00:00Z", "payload_sha256": "aa" * 32}))
    html = render_queue(collect_airgap(wallet))
    assert "req-1" in html and "awaiting device" in html
    (wallet.airgap_dir / "inbox" / "req-1.response.json").write_text("{}")
    html = render_queue(collect_airgap(wallet))
    assert "answered" in html
    # observed, never operated
    assert "OBSERVED" in html


def test_incidents_and_refusals_render_verbatim(tmp_path):
    wallet = _seal_wallet(tmp_path)
    (wallet.incidents_dir / "incident-1.json").write_text(json.dumps(
        {"severity": "tamper", "detail": "member disagreement on payload"}))
    (wallet.receipts_dir / "refusal-1.json").write_text(json.dumps(
        {"code": "CUSTODY_LATCHED", "remediation": "see runbook"}))
    html = render_incidents(collect_incidents(wallet), collect_refusals(wallet))
    assert "incident-1.json" in html and "member disagreement" in html
    assert "refusal-1.json" in html and "CUSTODY_LATCHED" in html


def test_inspect_garbage_fails_closed():
    result = inspect_receipt("not json at all", "{}", "")
    assert result["ok"] is False
    html = render_inspect(result)
    assert "FAILED TO VERIFY" in html
    assert "ACCEPTED" not in html


def test_inspect_real_evidence_roundtrip():
    evidence = Path("examples") / "wallet-evidence"
    key = evidence / "log.pub"
    attestations = sorted(evidence.glob("*attestation*.json")) if evidence.exists() else []
    receipts = sorted(evidence.glob("*receipt*.json")) if evidence.exists() else []
    if not (key.exists() and attestations and receipts):
        pytest.skip("example wallet evidence not present")
    result = inspect_receipt(attestations[0].read_text(), receipts[0].read_text(),
                             key.read_text())
    assert result["ok"] is True
    html = render_inspect(result)
    assert ("ACCEPTED" in html) or ("REJECTED" in html)
    assert "verify_receipt" in html  # provenance names the deployed verifier


def test_server_routes_and_read_only_guarantee(tmp_path):
    wallet = _seal_wallet(tmp_path)
    before = _dir_fingerprint(wallet.dir)
    server = serve(wallet.dir, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for route in ("/", "/queue", "/incidents", "/inspect", "/guide"):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{route}") as resp:
                body = resp.read().decode()
                assert resp.status == 200
                assert "READ-ONLY" in body
        data = urllib.parse.urlencode(
            {"attestation": "junk", "receipt": "junk", "pubkey": "junk"}).encode()
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/inspect", data=data) as resp:
            assert resp.status == 200
            assert "FAILED TO VERIFY" in resp.read().decode()
    finally:
        server.shutdown()
        thread.join(timeout=5)
    # the whole sweep, POST included, changed not one byte of wallet state
    assert _dir_fingerprint(wallet.dir) == before


def test_serve_refuses_non_wallet(tmp_path):
    with pytest.raises(Exception):
        serve(tmp_path / "empty")


def test_estate_view_served_with_runtime_dimension(tmp_path):
    wallet = _seal_wallet(tmp_path)
    server = serve(wallet.dir, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/estate") as resp:
            body = resp.read().decode()
        assert resp.status == 200
        assert "ALWAYS ON" in body and "ON-DEMAND" in body and "NOT RUNNING" in body
        assert "Runtime:" in body  # dossier panel wiring
        assert "lean-transparency-log" in body and "ltl-accumulator-verified" in body
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_estate_view_and_estate_md_do_not_drift():
    """Name-level sync guard between the cockpit estate page and ESTATE.md
    (the published_assets lesson: two renderings of one model need a
    tripwire)."""
    from pacta.estateview import ESTATE_HTML
    estate_md = Path("ESTATE.md").read_text(encoding="utf-8")
    for name in ("lean-transparency-log", "ltl-accumulator-verified",
                 "proof-aware-crypto-tooling-agent", "verifying-crypto-with-lean",
                 "dalek-ed25519-verified", "pasta-pallas-verified",
                 "ltl.zkdefi.org", "Forgejo"):
        assert name in ESTATE_HTML, f"estate view lost: {name}"
        assert name in estate_md, f"ESTATE.md lost: {name}"
    # the runtime dimension must exist in BOTH renderings
    assert "What is running" in estate_md
    assert "ALWAYS ON" in ESTATE_HTML


def test_demo_wallet_seals_and_serves(tmp_path):
    from pacta.walletui import seal_demo_wallet
    wallet_dir = seal_demo_wallet(tmp_path)
    server = serve(wallet_dir, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            body = resp.read().decode()
        assert resp.status == 200
        assert "dalek-ed25519-verified" in body and "4 pinned" in body
        assert "chain verified" in body
    finally:
        server.shutdown()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# UX contract: the cockpit never leaves a human in the dark. Every view must
# explain itself in plain language, every verdict must be stated in words,
# every page must carry navigation and interpretation help.
# ---------------------------------------------------------------------------

def _serve(wallet_dir):
    server = serve(wallet_dir, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address[1]


def _get(port, route):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{route}") as resp:
        return resp.status, resp.read().decode()


def test_guide_view_explains_every_term(tmp_path):
    wallet = _seal_wallet(tmp_path)
    server, thread, port = _serve(wallet.dir)
    try:
        status, body = _get(port, "/guide")
        assert status == 200
        assert "renders evidence" in body  # the design law, in the user's face
        for term in ("custody capsule", "quorum member", "hash chain",
                     "custody latch", "refusal receipt", "air-gap",
                     "evidence grade", "DEMO wallet",
                     "What this cockpit cannot tell you",
                     "A five-minute tour"):
            assert term in body, f"guide is missing: {term}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_every_view_carries_lead_nav_and_explainers(tmp_path):
    wallet = _seal_wallet(tmp_path)
    server, thread, port = _serve(wallet.dir)
    try:
        for route in ("/", "/queue", "/incidents", "/inspect"):
            status, body = _get(port, route)
            assert status == 200
            assert 'href="/guide"' in body, f"{route}: no path to the guide"
            assert 'class="lead"' in body, f"{route}: no plain-language lead"
            assert "<details" in body, f"{route}: no interpretation expander"
            assert 'class="navsub"' in body, f"{route}: tabs do not say what they answer"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_empty_states_are_explained(tmp_path):
    """A blank table is a UX failure; every empty list must say what empty
    means and whether it is good news."""
    wallet = _seal_wallet(tmp_path)
    q = render_queue(collect_airgap(wallet))
    assert "No signing requests are waiting" in q
    inc = render_incidents(collect_incidents(wallet), collect_refusals(wallet))
    assert "Empty is the good state" in inc
    assert "nothing has been refused" in inc


def test_estate_page_links_back_to_cockpit(tmp_path):
    wallet = _seal_wallet(tmp_path)
    server, thread, port = _serve(wallet.dir)
    try:
        status, body = _get(port, "/estate")
        assert status == 200
        assert "Back to cockpit" in body
    finally:
        server.shutdown()
        thread.join(timeout=5)
