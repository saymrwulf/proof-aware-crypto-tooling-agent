"""walletui - the warden custody cockpit (local, read-only).

A localhost web surface over an existing wallet directory, for the human
operator who ultimately answers for the money. Four views: posture, the
pending-signature queue (airgap outbox), the incident & refusal browser,
and a receipt inspector.

Design law: THE COCKPIT RENDERS EVIDENCE, IT NEVER ASSERTS IT. Every
panel is recomputed from wallet state or submitted artifacts at request
time by the same functions the wallet itself uses, and every panel names
the function and timestamp that produced it. Anything that cannot be
recomputed renders as a loud FAILED-TO-VERIFY panel - there is no cached
green and no neutral gray.

Read-only guarantee: this module calls only read paths (``Wallet.posture``,
``verify_ledger``, directory listings) and ``transparency.verify_receipt``
on submitted artifacts (parsed in memory / temp files outside the wallet).
It cannot approve, sign, unlatch, or modify custody state; the HTTP surface
exposes no mutating route. Human approve/deny is deliberately NOT here -
that would be a custody-semantics change, which belongs to a separate,
explicitly reviewed milestone.

The server binds 127.0.0.1 by default and is not meant to be exposed.
"""
from __future__ import annotations

import html
import json
import tempfile
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .attestation import load_attestation
from .transparency import load_receipt, verify_receipt
from .wallet import Wallet

_STYLE = """
 :root{--ink:#1c2430;--ink2:#5a6675;--line:#dde2e9;--ok:#1e7f4f;--okbg:#e2f2e9;
       --bad:#a3242c;--badbg:#fbe4e6;--warn:#a86a10;--warnbg:#fdf0da;
       --accent:#3b4d8f;--accentbg:#eef0f7;--bg:#f8f9fa}
 *{box-sizing:border-box}
 body{font-family:system-ui,sans-serif;max-width:62rem;margin:0 auto;
      padding:1.4rem 1.2rem 4rem;color:var(--ink);line-height:1.55;background:var(--bg)}
 h1{font-size:1.35rem;margin:.2rem 0 0}
 h2{font-size:1.05rem;margin:1.6rem 0 .5rem}
 code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#eef0f3;
      border-radius:4px;padding:.08rem .3rem;font-size:.88em}
 nav{margin:.7rem 0 1rem;display:flex;gap:.5rem;flex-wrap:wrap}
 nav a{color:var(--accent);text-decoration:none;border:1px solid var(--line);
      background:#fff;border-radius:6px;padding:.25rem .7rem;font-size:.85rem}
 nav a.here{border-color:var(--accent);font-weight:600}
 .banner{background:var(--warnbg);border:1px solid var(--warn);color:var(--warn);
      border-radius:6px;padding:.45rem .8rem;font-size:.82rem;font-weight:600}
 .panel{background:#fff;border:1px solid var(--line);border-radius:8px;
      padding:.9rem 1.1rem;margin:.7rem 0}
 .panel.bad{border-color:var(--bad);background:var(--badbg)}
 .prov{color:var(--ink2);font-size:.72rem;margin-top:.6rem;border-top:1px dashed var(--line);
      padding-top:.35rem}
 .pill{display:inline-block;border-radius:9px;padding:.06rem .55rem;font-size:.76rem;
      font-weight:700}
 .pill.ok{background:var(--okbg);color:var(--ok)}
 .pill.bad{background:var(--badbg);color:var(--bad)}
 .pill.warn{background:var(--warnbg);color:var(--warn)}
 table{border-collapse:collapse;width:100%;font-size:.88rem;background:#fff}
 td,th{border:1px solid var(--line);padding:.4rem .6rem;text-align:left;vertical-align:top}
 th{background:var(--accentbg)}
 ul.diag{margin:.4rem 0 0;padding-left:1.2rem}
 ul.diag li{font-size:.85rem;margin:.2rem 0}
 textarea{width:100%;min-height:7.5rem;font-family:ui-monospace,monospace;font-size:.8rem;
      border:1px solid var(--line);border-radius:6px;padding:.5rem}
 button{background:var(--accent);color:#fff;border:0;border-radius:6px;
      padding:.5rem 1.1rem;font-size:.9rem;cursor:pointer}
 .muted{color:var(--ink2);font-size:.85rem}
 .mono{font-family:ui-monospace,monospace}
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _provenance(via: str) -> str:
    return f'<div class="prov">recomputed {_esc(_now())} via <code>{_esc(via)}</code> — nothing on this panel is cached or asserted.</div>'


def _failed_panel(what: str, via: str, error: Exception) -> str:
    return (
        f'<div class="panel bad"><span class="pill bad">FAILED TO VERIFY</span> '
        f"<strong>{_esc(what)}</strong> could not be recomputed: "
        f"<code>{_esc(f'{type(error).__name__}: {error}')}</code>. "
        f"A cockpit that cannot verify shows red, never a stale green."
        f"{_provenance(via)}</div>"
    )


# ---------------------------------------------------------------------------
# collectors - read-only, one wallet function each, exceptions contained
# ---------------------------------------------------------------------------

def collect(via: str, fn: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"ok": True, "via": via, "data": fn()}
    except Exception as error:  # noqa: BLE001 - fail-closed rendering is the point
        return {"ok": False, "via": via, "error": error}


def collect_incidents(wallet: Wallet) -> dict[str, Any]:
    def read() -> list[dict[str, Any]]:
        items = []
        for path in sorted(wallet.incidents_dir.glob("*.json"), reverse=True):
            record = json.loads(path.read_text(encoding="utf-8"))
            record["_file"] = path.name
            items.append(record)
        return items
    return collect("incidents/*.json (verbatim files)", read)


def collect_refusals(wallet: Wallet) -> dict[str, Any]:
    def read() -> list[dict[str, Any]]:
        items = []
        for path in sorted(wallet.receipts_dir.glob("*.json"), reverse=True):
            record = json.loads(path.read_text(encoding="utf-8"))
            record["_file"] = path.name
            items.append(record)
        return items
    return collect("receipts/*.json (refusal receipts, verbatim)", read)


def collect_airgap(wallet: Wallet) -> dict[str, Any]:
    def read() -> list[dict[str, Any]]:
        pending = []
        outbox = wallet.airgap_dir / "outbox"
        inbox = wallet.airgap_dir / "inbox"
        for req in sorted(outbox.glob("*.request.json")):
            request_id = req.name.removesuffix(".request.json")
            body = json.loads(req.read_text(encoding="utf-8"))
            pending.append({
                "request_id": request_id,
                "created_at": body.get("created_at"),
                "payload_sha256": body.get("payload_sha256"),
                "answered": (inbox / f"{request_id}.response.json").exists(),
            })
        return pending
    return collect("airgap/outbox + inbox listing", read)


def inspect_receipt(attestation_text: str, receipt_text: str,
                    public_key_pem: str) -> dict[str, Any]:
    """Run the SAME verification the wallet and CLI use on pasted artifacts.

    Nothing is written anywhere near the wallet; artifacts live in a
    throwaway temp directory for the duration of the call.
    """
    try:
        with tempfile.TemporaryDirectory() as tmp:
            att_path = Path(tmp) / "attestation.json"
            rec_path = Path(tmp) / "receipt.json"
            key_path = Path(tmp) / "log.pub"
            att_path.write_text(attestation_text, encoding="utf-8")
            rec_path.write_text(receipt_text, encoding="utf-8")
            key_path.write_text(public_key_pem, encoding="utf-8")
            attestation = load_attestation(att_path)
            receipt = load_receipt(rec_path)
            result = verify_receipt(attestation, receipt, key_path,
                                    require_signatures="ed25519")
        return {
            "ok": True,
            "via": "pacta.transparency.verify_receipt (the deployed verifier itself)",
            "accepted": bool(result.accepted),
            "signatures": dict(result.signatures),
            "diagnostics": list(result.diagnostics),
        }
    except Exception as error:  # noqa: BLE001
        return {"ok": False,
                "via": "pacta.transparency.verify_receipt",
                "error": f"{type(error).__name__}: {error}"}


# ---------------------------------------------------------------------------
# renderers - pure string builders over collector output
# ---------------------------------------------------------------------------

_VIEWS = [("/", "Posture"), ("/queue", "Signature queue"),
          ("/incidents", "Incidents & refusals"), ("/inspect", "Receipt inspector"),
          ("/estate", "Estate map")]


def _page(title: str, active: str, body: str, wallet_dir: str) -> str:
    nav = "".join(
        f'<a href="{href}"{" class=here" if href == active else ""}>{label}</a>'
        for href, label in _VIEWS)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>warden cockpit — {_esc(title)}</title>"
        f"<style>{_STYLE}</style></head><body>"
        f"<h1>warden cockpit <span class='muted mono'>{_esc(wallet_dir)}</span></h1>"
        "<div class='banner'>READ-ONLY. This cockpit observes and recomputes; it cannot "
        "approve, sign, unlatch, or modify custody state.</div>"
        f"<nav>{nav}</nav>{body}</body></html>"
    )


def render_posture(posture: dict[str, Any]) -> str:
    if not posture["ok"]:
        return _failed_panel("Custody posture", posture["via"], posture["error"])
    p = posture["data"]
    latch = p["latch"]
    ledger = p["ledger"]
    latch_pill = ('<span class="pill bad">LATCHED — outbound custody frozen</span>'
                  if latch.get("latched") else '<span class="pill ok">unlatched</span>')
    chain_pill = ('<span class="pill ok">chain verified</span>' if ledger["chain_ok"]
                  else '<span class="pill bad">CHAIN BROKEN</span>')
    members = "".join(
        f"<tr><td><code>{_esc(m['backend'])}</code></td>"
        f"<td class='mono'>{_esc(m['component'])}</td>"
        f"<td>{_esc(m['risk_tier'])}</td>"
        f"<td class='mono'>{_esc(m['source_commit'][:12])}…</td>"
        f"<td class='mono'>{_esc(m['binary_sha256'][:16])}…</td></tr>"
        for m in p["members"])
    problems = "".join(f"<li>{_esc(x)}</li>" for x in ledger["problems"]) or "<li>none</li>"
    latch_detail = ""
    if latch.get("latched"):
        latch_detail = (f"<p>reason: <code>{_esc(latch.get('reason'))}</code> · "
                        f"incident: <code>{_esc(latch.get('incident'))}</code> · "
                        f"since {_esc(latch.get('at'))} — see the "
                        f"<a href='/incidents'>incident browser</a> and docs/runbook-latch.md.</p>")
    spending = p.get("spending_policy") or {}
    return (
        f"<div class='panel'><h2 style='margin-top:0'>Custody latch {latch_pill}</h2>"
        f"{latch_detail}{_provenance('Wallet.latch_state()')}</div>"
        f"<div class='panel'><h2 style='margin-top:0'>Ledger {chain_pill}</h2>"
        f"<p>{ledger['entries']} entries · head <code>{_esc(ledger['head'][:24])}…</code></p>"
        f"<ul class='diag'>{problems}</ul>"
        f"{_provenance('Wallet.verify_ledger() — full hash-chain recomputation')}</div>"
        f"<div class='panel'><h2 style='margin-top:0'>Quorum members "
        f"<span class='pill ok'>{len(p['members'])} pinned</span></h2>"
        "<table><tr><th>backend</th><th>component</th><th>tier</th>"
        "<th>source commit</th><th>binary sha256</th></tr>"
        f"{members}</table>"
        "<p class='muted'>Every member is pinned by binary hash in the capsule; the capsule "
        f"hash is <code>{_esc(p['capsule_sha256'][:24])}…</code>. What this table does NOT "
        "prove: that the binaries correspond to the attested sources (reproducible builds "
        "are out of scope, stated in the paper and the claim cards)."
        f"{_provenance('Wallet.capsule() / Wallet.posture()')}</div>"
        f"<div class='panel'><h2 style='margin-top:0'>Spending policy</h2>"
        f"<pre style='margin:0;font-size:.8rem'>{_esc(json.dumps(spending, indent=2, sort_keys=True))}</pre>"
        f"{_provenance('Wallet.policy() (policy.json, verbatim)')}</div>"
        f"<div class='panel'><h2 style='margin-top:0'>Counters</h2>"
        f"<p>incidents: <strong>{p['incidents']}</strong> · refusal receipts: "
        f"<strong>{p['refusal_receipts']}</strong> — browse them under "
        "<a href='/incidents'>Incidents &amp; refusals</a>.</p>"
        f"{_provenance('directory counts, recomputed')}</div>"
    )


def render_queue(airgap: dict[str, Any]) -> str:
    if not airgap["ok"]:
        return _failed_panel("Signature queue", airgap["via"], airgap["error"])
    rows = "".join(
        f"<tr><td class='mono'>{_esc(r['request_id'])}</td>"
        f"<td>{_esc(r.get('created_at'))}</td>"
        f"<td class='mono'>{_esc((r.get('payload_sha256') or '')[:24])}…</td>"
        f"<td>{'<span class=\"pill ok\">answered</span>' if r['answered'] else '<span class=\"pill warn\">awaiting device</span>'}</td></tr>"
        for r in airgap["data"])
    body = (f"<table><tr><th>request</th><th>created</th><th>payload sha256</th>"
            f"<th>state</th></tr>{rows}</table>" if airgap["data"]
            else "<p class='muted'>No parked signing requests.</p>")
    return (
        "<div class='panel'><h2 style='margin-top:0'>Pending airgap signatures</h2>"
        + body +
        "<p class='muted'>This queue is OBSERVED, not operated: completing or refusing a "
        "request happens through the wallet's own channels (<code>request_signature</code> "
        "over MCP, or the airgap device flow), never from this page.</p>"
        + _provenance("airgap outbox/inbox listing") + "</div>"
    )


def render_incidents(incidents: dict[str, Any], refusals: dict[str, Any]) -> str:
    def block(title: str, coll: dict[str, Any], via_note: str) -> str:
        if not coll["ok"]:
            return _failed_panel(title, coll["via"], coll["error"])
        items = coll["data"]
        if not items:
            body = "<p class='muted'>none recorded</p>"
        else:
            body = "".join(
                f"<div class='panel' style='margin:.5rem 0'><code>{_esc(i['_file'])}</code>"
                f"<pre style='font-size:.76rem;overflow-x:auto'>{_esc(json.dumps({k: v for k, v in i.items() if k != '_file'}, indent=2, sort_keys=True))}</pre></div>"
                for i in items[:50])
        return (f"<div class='panel'><h2 style='margin-top:0'>{_esc(title)}</h2>{body}"
                f"{_provenance(via_note)}</div>")
    return (block("Incidents (quorum divergences, quarantines)", incidents,
                  "incidents/*.json, verbatim, newest first")
            + block("Refusal receipts (signed, machine-actionable)", refusals,
                    "receipts/*.json, verbatim, newest first"))


def render_inspect(result: dict[str, Any] | None,
                   defaults: dict[str, str] | None = None) -> str:
    d = defaults or {}
    verdict = ""
    if result is not None:
        if not result["ok"]:
            verdict = _failed_panel("Receipt verification", result["via"],
                                    RuntimeError(result["error"]))
        else:
            pill = ('<span class="pill ok">ACCEPTED</span>' if result["accepted"]
                    else '<span class="pill bad">REJECTED</span>')
            sigs = "".join(f"<tr><td><code>{_esc(k)}</code></td><td>{_esc(v)}</td></tr>"
                           for k, v in sorted(result["signatures"].items()))
            diags = "".join(f"<li>{_esc(x)}</li>" for x in result["diagnostics"]) or "<li>none</li>"
            verdict = (
                f"<div class='panel'><h2 style='margin-top:0'>Verdict {pill}</h2>"
                f"<table><tr><th>signature check</th><th>result</th></tr>{sigs}</table>"
                f"<h2>Diagnostics</h2><ul class='diag'>{diags}</ul>"
                f"{_provenance(result['via'])}</div>")
    return (
        verdict +
        "<div class='panel'><h2 style='margin-top:0'>Inspect a receipt</h2>"
        "<p class='muted'>Paste an attestation, its transparency receipt, and the log's "
        "public key. The verdict is produced by the wallet's own deployed verifier — "
        "this page adds nothing and hides nothing; the diagnostics list is verbatim.</p>"
        "<form method='post' action='/inspect'>"
        f"<p><strong>attestation.json</strong><br><textarea name='attestation'>{_esc(d.get('attestation', ''))}</textarea></p>"
        f"<p><strong>receipt.json</strong><br><textarea name='receipt'>{_esc(d.get('receipt', ''))}</textarea></p>"
        f"<p><strong>log public key (PEM)</strong><br><textarea name='pubkey' style='min-height:4rem'>{_esc(d.get('pubkey', ''))}</textarea></p>"
        "<button type='submit'>Verify (read-only)</button></form></div>"
    )


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

def make_handler(wallet_dir: Path):
    class CockpitHandler(BaseHTTPRequestHandler):
        server_version = "warden-cockpit/1"

        def _send(self, body: str, status: int = 200) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _wallet(self) -> Wallet:
            return Wallet(wallet_dir)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            route = urllib.parse.urlparse(self.path).path
            wd = str(wallet_dir)
            if route == "/":
                wallet = self._wallet()
                body = render_posture(collect("Wallet.posture()", wallet.posture))
                self._send(_page("posture", "/", body, wd))
            elif route == "/queue":
                body = render_queue(collect_airgap(self._wallet()))
                self._send(_page("signature queue", "/queue", body, wd))
            elif route == "/incidents":
                wallet = self._wallet()
                body = render_incidents(collect_incidents(wallet), collect_refusals(wallet))
                self._send(_page("incidents", "/incidents", body, wd))
            elif route == "/inspect":
                self._send(_page("receipt inspector", "/inspect", render_inspect(None), wd))
            elif route == "/estate":
                from .estateview import ESTATE_HTML
                self._send(ESTATE_HTML)
            else:
                self._send(_page("not found", "", "<div class='panel bad'>No such view.</div>", wd), 404)

        def do_POST(self) -> None:  # noqa: N802
            route = urllib.parse.urlparse(self.path).path
            if route != "/inspect":
                self._send("<div class='panel bad'>No such action.</div>", 404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            fields = {k: form.get(k, [""])[0] for k in ("attestation", "receipt", "pubkey")}
            result = inspect_receipt(fields["attestation"], fields["receipt"], fields["pubkey"])
            self._send(_page("receipt inspector", "/inspect",
                             render_inspect(result, fields), str(wallet_dir)))

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            return

    return CockpitHandler


def serve(wallet_dir: str | Path, host: str = "127.0.0.1", port: int = 8471) -> ThreadingHTTPServer:
    wallet_dir = Path(wallet_dir).resolve()
    Wallet(wallet_dir).capsule()  # fail fast if this is not a wallet
    server = ThreadingHTTPServer((host, port), make_handler(wallet_dir))
    return server
