import json
import threading
import urllib.request
from pathlib import Path

from pacta.signing import generate_ed25519_keypair
from pacta.transparency import leaf_bytes_for_attestation, verify_inclusion
from pacta.witness import audit_published_log
from pacta_provider.transparency_log import TransparencyLog
from pacta_provider.web import serve


def _make_log(tmp_path, n=3):
    generate_ed25519_keypair(tmp_path / "k.key", tmp_path / "k.pub")
    log = TransparencyLog(tmp_path / "log")
    log.init("test-provider", tmp_path / "k.pub")
    from pacta.yamlio import dump_data

    for i in range(n):
        att = {
            "schema_version": 1,
            "provider": "test-provider",
            "issued_at": "2026-07-07T00:00:00Z",
            "subject": {"component": f"component-{i}", "repo_commit": f"commit-{i}"},
            "certificates": [{"name": "T.cert", "status": "proven", "axiom_status": "clean"}],
        }
        dump_data(att, tmp_path / f"a{i}.yaml")
        log.append_attestation(tmp_path / f"a{i}.yaml", tmp_path / "k.key", tmp_path / "k.pub")
    return log


def test_web_endpoints_and_online_proof_roundtrip(tmp_path):
    # root mount: the production shape (ltl.zkdefi.org serves from /)
    import shutil

    _make_log(tmp_path)
    # trust anchor present at render time: front page must display it in full
    shutil.copy2(tmp_path / "k.pub", tmp_path / "log" / "provider.ed25519.pub")
    server = serve(str(tmp_path / "log"), port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        def get(path):
            with urllib.request.urlopen(base + path, timeout=10) as r:
                return json.loads(r.read())

        assert get("/healthz")["tree_size"] == 3
        sth = get("/v1/sth")
        assert sth["tree_size"] == 3
        att = get("/v1/attestation?component=component-1")["attestation"]
        proof = get("/v1/proof?component=component-1")
        ok = verify_inclusion(
            leaf_bytes_for_attestation(att), proof["leaf_index"], proof["tree_size"],
            [bytes.fromhex(h) for h in proof["inclusion_proof"]],
            bytes.fromhex(proof["sth"]["root_hash"]),
        )
        assert ok
        consistency = get("/v1/sth-consistency?first=2")
        assert consistency["from_tree_size"] == 2 and consistency["proof"]
        history = get("/v1/sth-history")["sth_history"]
        assert len(history) == 3  # one head per append
        with urllib.request.urlopen(base + "/paper", timeout=10) as r:
            assert r.headers["Content-Type"] == "application/pdf"
            assert r.read(5) == b"%PDF-"
        with urllib.request.urlopen(base + "/paper/ltl.pdf", timeout=10) as r:
            assert r.read(5) == b"%PDF-"
        # superseded drafts were retired from the site 2026-08-15 (git
        # history retains them); every old variant route must 404
        for gone in ("/paper/v0.0", "/paper/v0.1", "/paper/v0.2"):
            try:
                urllib.request.urlopen(base + gone, timeout=10)
                raise AssertionError(f"expected 404 for retired {gone}")
            except urllib.error.HTTPError as exc:
                assert exc.code == 404, gone
        # the site's copy of the trust anchor (TOFU: two independent locations)
        with urllib.request.urlopen(base + "/log-public-key", timeout=10) as r:
            assert r.read() == (tmp_path / "k.pub").read_bytes()
        # and the front page displays the key IN FULL, above the fold
        with urllib.request.urlopen(base + "/docs", timeout=10) as r:
            page = r.read().decode()
        assert "BEGIN PUBLIC KEY" in page
        assert "pin these keys" in page.lower()
        # operator-dropped documents: served by bare name, absent from the
        # endpoint index, traversal-safe
        site = tmp_path / "log" / "site"
        site.mkdir()
        (site / "extra.pdf").write_bytes(b"%PDF-1.4 dummy")
        with urllib.request.urlopen(base + "/extra", timeout=10) as r:
            assert r.read().startswith(b"%PDF-")
            assert r.headers["X-Robots-Tag"].startswith("noindex")
        try:
            urllib.request.urlopen(base + "/nope-not-there", timeout=10)
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as exc:
            listing = json.loads(exc.read())
            assert exc.code == 404
            assert not any("extra" in e for e in listing["endpoints"])  # unlisted
        try:
            urllib.request.urlopen(base + "/..%2fsth", timeout=10)
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()


def test_logclient_fetch_and_refresh_pin(tmp_path):
    # path mount still supported for anyone proxying under a prefix
    _make_log(tmp_path)
    server = serve(str(tmp_path / "log"), base_path="lean-transparency-log", port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/lean-transparency-log"
    try:
        from pacta.logclient import fetch_evidence, refresh_pin

        paths = fetch_evidence(base, "component-2", tmp_path / "fetched")
        assert paths["attestation"].exists() and paths["receipt"].exists()
        ok, diagnostics = refresh_pin(base, tmp_path / "pins.json", tmp_path / "k.pub")
        assert ok, diagnostics
        # second refresh: matched, still ok
        ok, _ = refresh_pin(base, tmp_path / "pins.json", tmp_path / "k.pub")
        assert ok
    finally:
        server.shutdown()


def test_publish_and_witness_audit_catches_tampering(tmp_path):
    log = _make_log(tmp_path)
    published = tmp_path / "published"
    report = log.publish(published, public_key_path=tmp_path / "k.pub")
    assert report["entries"] == 3
    assert (published / "verify.py").exists() and (published / "README.md").exists()
    assert (published / "verify_selftest.py").exists()

    clean = audit_published_log(published, tmp_path / "k.pub")
    assert clean.ok and clean.heads_checked == 3

    # tamper one entry: structural audit must fail loudly
    victim = published / "entries" / "000001.json"
    record = json.loads(victim.read_text())
    record["leaf"]["attestation"]["subject"]["repo_commit"] = "EVIL"
    victim.write_text(json.dumps(record))
    dirty = audit_published_log(published, tmp_path / "k.pub")
    assert not dirty.ok
    assert any("leaf_hash" in problem for problem in dirty.problems)
    assert any("EQUIVOCATION or tampered" in problem for problem in dirty.problems)


def test_standalone_verify_py_runs(tmp_path):
    import subprocess
    import sys

    log = _make_log(tmp_path)
    published = tmp_path / "published"
    log.publish(published, public_key_path=tmp_path / "k.pub")
    result = subprocess.run([sys.executable, "verify.py", "--all"], cwd=published, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    # hardened verifier: full mode (signatures verified) must report exactly this
    assert "RESULT: OK [full]" in result.stdout


def test_webdocs_source_carries_no_stale_paper_claims():
    # Regression for the 2026-08-16 operator finding: the paper card said
    # "23 pages" and the July-snapshot card survived a silently failed
    # replace (an invisible NBSP defeated the pattern). Guard the shipped
    # STRINGS, not just version markers.
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "provider" / "src" / "pacta_provider" / "webdocs.py"
    text = source.read_text(encoding="utf-8")
    for stale in ("snapshot", "thirteen leaves", "16 July", "16&nbsp;July",
                  "16\xa0July", "v0.9", "v0.10", "23 pages"):
        assert stale not in text, f"stale marker {stale!r} in webdocs"
    # printed commands must work as printed: curl needs the scheme
    # (http->https redirect yields empty output), the clone one-liner
    # needs the cd into the cloned directory
    assert "curl -s ltl.zkdefi.org" not in text
    assert "cd lean-transparency-log" in text
    # first-use glosses the page promised: STH and axiom cones
    assert "Signed Tree Head (STH)" in text
    assert "axiom cones (the exact set of assumptions" in text


def test_svg_tree_boxes_never_overlap_or_spill():
    # Regression for 2026-08-16: fixed-width leaf boxes shingled once the
    # log outgrew the 8-leaf design, and a fixed head box let its caption
    # spill. Render the tree at several sizes and assert geometry.
    import re

    from pacta_provider.webdocs import _svg_tree

    class _E:
        def __init__(self, i):
            self.leaf_hash = f"{i:02x}" * 32
            self.leaf = {"attestation": {"subject": {"component": "betrusted-ed25519-verified"},
                                         "certificates": [{"status": "proven", "axiom_status": "clean"}]}}

    for n in (8, 19, 33):
        svg = _svg_tree([_E(i) for i in range(n)], "ab" * 32, "verified-dalek-serial")
        rects = [(float(m.group(1)), float(m.group(2)), float(m.group(3)))
                 for m in re.finditer(r'<rect x="([-0-9.]+)" y="([0-9.]+)" width="([0-9.]+)"', svg)]
        leaf_y = max(y for _, y, _ in rects)
        leaves = sorted((x, w) for x, y, w in rects if y == leaf_y)
        assert len(leaves) == n
        for (x1, w1), (x2, _w2) in zip(leaves, leaves[1:]):
            assert x1 + w1 <= x2 + 0.01, f"leaf boxes overlap at n={n}"
        # head caption must fit its box: longest line estimated at 5.3px/char
        head = re.search(r'<rect x="[-0-9.]+" y="[0-9.]+" width="([0-9.]+)" height="46"', svg)
        title = re.search(r'font-weight="bold">([^<]+)</text>', svg).group(1)
        assert len(title) * 7.0 <= float(head.group(1)), "head title spills"
