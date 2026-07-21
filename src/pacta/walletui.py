"""walletui - the warden custody cockpit (local, read-only).

A localhost web surface over an existing wallet directory, for the human
operator who ultimately answers for the money. Six views: posture, the
pending-signature queue (airgap outbox), the incident & refusal browser,
a receipt inspector, the estate map, and a plain-language guide.

Design law: THE COCKPIT RENDERS EVIDENCE, IT NEVER ASSERTS IT. Every
panel is recomputed from wallet state or submitted artifacts at request
time by the same functions the wallet itself uses, and every panel names
the function and timestamp that produced it. Anything that cannot be
recomputed renders as a loud FAILED-TO-VERIFY panel - there is no cached
green and no neutral gray.

UX law (the design law's twin): THE COCKPIT NEVER LEAVES A HUMAN IN THE
DARK. Every page opens with a plain-language statement of what it shows;
every verdict is stated in words, not just color; every panel carries a
"how to read this" explainer; every piece of jargon links to the /guide
glossary. A person who has never heard of warden must be able to read
every screen.

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
 .sub{color:var(--ink2);font-size:.85rem;margin:.3rem 0 .6rem}
 nav{margin:.7rem 0 1rem;display:flex;gap:.5rem;flex-wrap:wrap}
 nav a{color:var(--accent);text-decoration:none;border:1px solid var(--line);
      background:#fff;border-radius:6px;padding:.3rem .7rem;font-size:.85rem;
      display:flex;flex-direction:column;line-height:1.25;min-width:7.5rem}
 nav a.here{border-color:var(--accent);font-weight:600;background:var(--accentbg)}
 nav a .navsub{font-size:.67rem;color:var(--ink2);font-weight:400}
 .banner{background:var(--warnbg);border:1px solid var(--warn);color:var(--warn);
      border-radius:6px;padding:.45rem .8rem;font-size:.82rem;font-weight:600}
 .banner a{color:var(--warn)}
 .lead{font-size:.92rem;margin:.9rem 0 .2rem}
 .verdict{border-radius:8px;padding:.8rem 1.1rem;margin:.8rem 0;border:1px solid}
 .verdict strong{font-size:1.05rem;letter-spacing:.02em}
 .verdict p{margin:.3rem 0 0;font-size:.88rem;font-weight:400}
 .verdict.ok{background:var(--okbg);border-color:var(--ok);color:var(--ok)}
 .verdict.warn{background:var(--warnbg);border-color:var(--warn);color:var(--warn)}
 .verdict.bad{background:var(--badbg);border-color:var(--bad);color:var(--bad)}
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
 a.help{display:inline-block;width:1.05rem;height:1.05rem;line-height:1.05rem;text-align:center;
      border-radius:50%;background:var(--accentbg);color:var(--accent);font-size:.72rem;
      font-weight:700;text-decoration:none;vertical-align:.15em}
 details.explain{margin-top:.55rem;font-size:.82rem}
 details.explain summary{cursor:pointer;color:var(--accent);font-weight:600;font-size:.78rem}
 details.explain .expl{color:var(--ink2);margin:.4rem 0 0;padding:.5rem .7rem;
      background:var(--accentbg);border-radius:6px}
 details.explain .expl ul{margin:.3rem 0;padding-left:1.1rem}
 details.explain .expl li{margin:.15rem 0}
 .plain{font-size:.88rem;margin:.3rem 0 .6rem}
 .empty{color:var(--ink2);font-size:.88rem;background:var(--accentbg);border-radius:6px;
      padding:.5rem .8rem}
 pre{overflow-x:auto}
 .tablewrap{overflow-x:auto}
 table{border-collapse:collapse;width:100%;font-size:.88rem;background:#fff}
 td,th{border:1px solid var(--line);padding:.4rem .6rem;text-align:left;vertical-align:top}
 th{background:var(--accentbg)}
 ul.diag{margin:.4rem 0 0;padding-left:1.2rem}
 ul.diag li{font-size:.85rem;margin:.2rem 0}
 dl.gloss dt{font-weight:700;margin-top:.8rem}
 dl.gloss dd{margin:.15rem 0 0 0;font-size:.88rem;color:var(--ink)}
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


def _help(anchor: str) -> str:
    """A small ? that jumps to the glossary entry for a term."""
    return (f'<a class="help" href="/guide#{anchor}" '
            f'title="what does this mean? — explained in the guide">?</a>')


def _explain(body: str) -> str:
    """The per-panel interpretation aid: always present, opt-in detail."""
    return (f'<details class="explain"><summary>How to read this panel</summary>'
            f'<div class="expl">{body}</div></details>')


def _provenance(via: str) -> str:
    return f'<div class="prov">recomputed {_esc(_now())} via <code>{_esc(via)}</code> — nothing on this panel is cached or asserted.</div>'


def _failed_panel(what: str, via: str, error: Exception) -> str:
    return (
        f'<div class="panel bad"><span class="pill bad">FAILED TO VERIFY</span> '
        f"<strong>{_esc(what)}</strong> could not be recomputed: "
        f"<code>{_esc(f'{type(error).__name__}: {error}')}</code>. "
        f"A cockpit that cannot verify shows red, never a stale green. "
        f"<span class='muted'>What to do: check that the wallet directory still exists and is "
        f"readable, then reload. If this persists, inspect from the command line with "
        f"<code>pacta wallet posture</code>.</span>"
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
# page shell - one navigation, one lead paragraph, on every view
# ---------------------------------------------------------------------------

_VIEWS = [
    ("/", "Posture", "is custody healthy right now?"),
    ("/queue", "Queue", "what awaits the offline signer?"),
    ("/incidents", "Incidents", "what has ever gone wrong?"),
    ("/inspect", "Inspect", "check a receipt yourself"),
    ("/estate", "Estate map", "the whole system, drawn"),
    ("/guide", "Guide", "every term, explained"),
]

_LEADS = {
    "/": ('This page answers one question: <strong>is custody healthy right now?</strong> '
          'The verdict comes first, the evidence behind it below. Every panel ends with a '
          'dashed provenance line naming the exact function that just recomputed it — '
          'and every small <a class="help" href="/guide#glossary">?</a> jumps to a '
          'plain-language explanation.'),
    "/queue": ('The wallet’s signing key can live on an <em>air-gapped</em> device — a '
               'computer with no network connection. To get something signed, the wallet '
               'parks a request file in an outbox; a human carries it to the device; the '
               'answer lands in an inbox. This page watches those two folders. It cannot '
               'approve, refuse, or move anything.'),
    "/incidents": ('The wallet’s paper trail. An <strong>incident</strong> is the wallet '
                   'noticing something wrong and writing it down on the spot. A '
                   '<strong>refusal receipt</strong> is the wallet saying <em>no</em> in '
                   'writing — with the rule it applied and what would fix the request. '
                   'An empty page here is good news.'),
    "/inspect": ('Paste verification artifacts below and this page re-runs the wallet’s '
                 'own verifier on them, on your machine, without writing anything to the '
                 'wallet. Use it to check evidence somebody handed you before trusting it.'),
    "/guide": ('Plain-language explanations for everything this cockpit shows. Nothing on '
               'this page is live data — this is the manual. The other five tabs are the '
               'instruments.'),
}


def _page(title: str, active: str, body: str, wallet_dir: str) -> str:
    nav = "".join(
        f'<a href="{href}"{" class=here" if href == active else ""}>{label}'
        f'<span class="navsub">{sub}</span></a>'
        for href, label, sub in _VIEWS)
    demo_badge = ('<span class="pill warn" title="sealed by --demo; fake members; can sign '
                  'nothing real">DEMO WALLET — custody-inert</span> '
                  if "DEMO" in wallet_dir else "")
    lead = _LEADS.get(active, "")
    lead_html = f'<p class="lead">{lead}</p>' if lead else ""
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>warden cockpit — {_esc(title)}</title>"
        f"<style>{_STYLE}</style></head><body>"
        f"<h1>warden custody cockpit {demo_badge}</h1>"
        f"<p class='sub'>Watching wallet <code>{_esc(wallet_dir)}</code> — everything below is "
        "recomputed live from that directory each time a page loads; nothing is cached, "
        "nothing is taken on trust.</p>"
        "<div class='banner'>READ-ONLY. This cockpit observes and recomputes; it cannot "
        "approve, sign, unlatch, or modify custody state. First time here? Start with the "
        "<a href='/guide'>Guide</a> — every term on these pages is explained there.</div>"
        f"<nav>{nav}</nav>{lead_html}{body}</body></html>"
    )


# ---------------------------------------------------------------------------
# renderers - pure string builders over collector output
# ---------------------------------------------------------------------------

def _posture_verdict(p: dict[str, Any]) -> str:
    """The one-glance answer, in words, before any evidence."""
    ledger = p["ledger"]
    if not ledger["chain_ok"] or ledger["problems"]:
        return ("<div class='verdict bad'><strong>CUSTODY EVIDENCE BROKEN</strong>"
                "<p>The ledger — the wallet's tamper-evident history — did not recompute "
                "cleanly. Until you know why, treat this wallet as compromised: do not "
                "trust its history and do not sign with it. The Ledger panel below shows "
                "exactly which check failed.</p></div>")
    if p["latch"].get("latched"):
        return ("<div class='verdict warn'><strong>CUSTODY FROZEN (LATCHED)</strong>"
                "<p>The wallet detected a problem and pulled its own emergency brake: all "
                "outbound signing is frozen until a human investigates and deliberately "
                "clears the latch. Nothing can be signed right now. The latch panel below "
                "names the trigger; <code>docs/runbook-latch.md</code> is the step-by-step "
                "recovery guide.</p></div>")
    return ("<div class='verdict ok'><strong>CUSTODY HEALTHY</strong>"
            "<p>History intact, quorum sealed, signing unfrozen. Each of those three claims "
            "is re-checked — not remembered — in the panels below.</p></div>")


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
    problems = "".join(f"<li>{_esc(x)}</li>" for x in ledger["problems"]) or (
        "<li>none — every link in the chain held</li>")
    latch_detail = ""
    if latch.get("latched"):
        latch_detail = (f"<p class='plain'>Trigger: <code>{_esc(latch.get('reason'))}</code> · "
                        f"recorded as incident <code>{_esc(latch.get('incident'))}</code> · "
                        f"frozen since {_esc(latch.get('at'))}. Read the incident in the "
                        f"<a href='/incidents'>incident browser</a>, then follow "
                        f"<code>docs/runbook-latch.md</code> to recover.</p>")
    spending = p.get("spending_policy") or {}
    no_rules = (not spending) or ("note" in spending and len(spending) == 1)
    spending_note = (
        "<p class='empty'>No spending rules are configured for this wallet: beyond the "
        "quorum gate and the latch, outbound signing is unrestricted — the wallet's own "
        "words below say so. A real deployment would define limits and allowlists in "
        "<code>policy.json</code>.</p>" if no_rules else
        "<p class='plain'>These rules are enforced by the signing firewall before anything "
        "is signed. Shown verbatim from <code>policy.json</code>.</p>")
    return (
        _posture_verdict(p)
        # --- latch ---------------------------------------------------------
        + f"<div class='panel'><h2 style='margin-top:0'>Custody latch {_help('latch')} {latch_pill}</h2>"
        "<p class='plain'>The latch is the wallet's emergency brake. It trips when the "
        "quorum disagrees or tampering is suspected, and freezes all outbound signing "
        "until an operator clears it through the wallet's own channels — never from "
        "this page.</p>"
        f"{latch_detail}"
        + _explain(
            "<ul><li><span class='pill ok'>unlatched</span> — the brake is off; signing is "
            "allowed (subject to quorum and policy).</li>"
            "<li><span class='pill bad'>LATCHED</span> — the brake is on; every signing "
            "request is refused with a receipt until a human resolves the trigger. "
            "Recovery steps live in <code>docs/runbook-latch.md</code>.</li></ul>")
        + f"{_provenance('Wallet.latch_state()')}</div>"
        # --- ledger --------------------------------------------------------
        f"<div class='panel'><h2 style='margin-top:0'>Ledger — has history been tampered with? {_help('ledger')} {chain_pill}</h2>"
        "<p class='plain'>The ledger is the wallet's append-only journal: every custody "
        "event, in order, each entry carrying the hash of the one before it. Editing, "
        "deleting, or reordering anything in the past breaks the chain visibly.</p>"
        f"<p>{ledger['entries']} entries · newest-entry hash (the «head»): "
        f"<code>{_esc(ledger['head'][:24])}…</code></p>"
        f"<ul class='diag'>{problems}</ul>"
        + _explain(
            "<ul><li><span class='pill ok'>chain verified</span> — the cockpit just "
            "re-hashed every entry from the first to the newest and every link held. This "
            "happens again on every reload.</li>"
            "<li><span class='pill bad'>CHAIN BROKEN</span> — at least one link failed: "
            "history was altered, truncated, or corrupted. The list above names the first "
            "entry that failed.</li></ul>")
        + f"{_provenance('Wallet.verify_ledger() — full hash-chain recomputation')}</div>"
        # --- quorum --------------------------------------------------------
        f"<div class='panel'><h2 style='margin-top:0'>Quorum — who must agree before anything is trusted? {_help('member')} "
        f"<span class='pill ok'>{len(p['members'])} pinned</span></h2>"
        f"<p class='plain'>These are the {len(p['members'])} verifier programs this wallet "
        "trusts, each built from a <em>different</em> formally verified codebase. Before "
        "the wallet accepts a cryptographic component, every member must independently "
        "reach the same verdict — a single dissenter freezes custody instead.</p>"
        "<div class='tablewrap'><table><tr><th>member</th><th>built from</th>"
        f"<th>evidence grade {_help('tier')}</th><th>source commit</th>"
        f"<th>binary fingerprint {_help('pinned')}</th></tr>"
        f"{members}</table></div>"
        + _explain(
            "<ul><li><strong>member</strong> — short name of the verifier backend.</li>"
            "<li><strong>built from</strong> — the formally verified repository the member "
            "binary was compiled from.</li>"
            "<li><strong>evidence grade</strong> — R0–R5 scale of the formal evidence behind "
            "the member: R0 = no usable evidence, R4 = machine-checked proofs covering the "
            "full documented boundary, R5 would add reproducible builds and side-channel "
            "assurance. This capsule requires R4.</li>"
            "<li><strong>source commit</strong> — the exact git commit of those verified "
            "sources (first 12 characters shown).</li>"
            "<li><strong>binary fingerprint</strong> — SHA-256 hash of the member "
            "executable (first 16 characters shown). The capsule pins the full value; a "
            "swapped or modified binary fails the comparison and is rejected.</li></ul>")
        + "<p class='muted'>Everything above is sealed in the "
        f"<a href='/guide#capsule'>custody capsule</a> — the wallet's founding document, "
        f"fingerprint <code>{_esc(p['capsule_sha256'][:24])}…</code>, anchored in the "
        "ledger's first entry so it cannot be quietly swapped. What this table does NOT "
        "prove: that the binaries correspond to the attested sources (reproducible builds "
        "are out of scope — that gap is grade R5 — stated in the paper and the claim cards)."
        f"{_provenance('Wallet.capsule() / Wallet.posture()')}</div>"
        # --- signing rules -------------------------------------------------
        f"<div class='panel'><h2 style='margin-top:0'>Signing rules (spending policy)</h2>"
        f"{spending_note}"
        f"<pre style='margin:0;font-size:.8rem'>{_esc(json.dumps(spending, indent=2, sort_keys=True))}</pre>"
        f"{_provenance('Wallet.policy() (policy.json, verbatim)')}</div>"
        # --- recorded history ----------------------------------------------
        f"<div class='panel'><h2 style='margin-top:0'>Recorded history</h2>"
        f"<p class='plain'>Incidents on file: <strong>{p['incidents']}</strong> · refusal "
        f"receipts on file: <strong>{p['refusal_receipts']}</strong> — read every one, "
        "verbatim, under <a href='/incidents'>Incidents</a>. An incident is the wallet "
        "noticing something wrong; a refusal receipt is the wallet saying no, in writing.</p>"
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
    body = (f"<div class='tablewrap'><table><tr><th>request</th><th>created</th>"
            f"<th>payload fingerprint</th><th>state</th></tr>{rows}</table></div>"
            if airgap["data"]
            else "<p class='empty'>No signing requests are waiting. The moment the wallet "
                 "parks one for the offline signer, it appears here.</p>")
    return (
        f"<div class='panel'><h2 style='margin-top:0'>Waiting for the offline signer {_help('airgap')}</h2>"
        + body
        + _explain(
            "<ul><li><span class='pill warn'>awaiting device</span> — the request file is "
            "parked in the outbox; the offline signer has not answered yet.</li>"
            "<li><span class='pill ok'>answered</span> — a response file for this request "
            "has arrived in the inbox.</li>"
            "<li><strong>payload fingerprint</strong> — SHA-256 of the exact bytes to be "
            "signed (first 24 characters shown). The device signs those bytes and nothing "
            "else, so you can compare fingerprints on both machines before approving.</li></ul>")
        + "<p class='muted'>This queue is OBSERVED, not operated: completing or refusing a "
        "request happens through the wallet's own channels (<code>request_signature</code> "
        "over MCP, or the airgap device flow), never from this page.</p>"
        + _provenance("airgap outbox/inbox listing") + "</div>"
    )


def render_incidents(incidents: dict[str, Any], refusals: dict[str, Any]) -> str:
    def block(title: str, coll: dict[str, Any], intro: str, empty: str,
              explain: str, via_note: str) -> str:
        if not coll["ok"]:
            return _failed_panel(title, coll["via"], coll["error"])
        items = coll["data"]
        if not items:
            body = f"<p class='empty'>{empty}</p>"
        else:
            body = "".join(
                f"<div class='panel' style='margin:.5rem 0'>"
                f"<span class='muted'>file</span> <code>{_esc(i['_file'])}</code>"
                f"<span class='muted'> — shown verbatim:</span>"
                f"<pre style='font-size:.76rem;overflow-x:auto'>{_esc(json.dumps({k: v for k, v in i.items() if k != '_file'}, indent=2, sort_keys=True))}</pre></div>"
                for i in items[:50])
        return (f"<div class='panel'><h2 style='margin-top:0'>{title}</h2>"
                f"<p class='plain'>{intro}</p>{body}{_explain(explain)}"
                f"{_provenance(via_note)}</div>")
    return (
        block(f"Incidents — what the wallet noticed {_help('incident')}", incidents,
              "Each file below is the wallet recording, at the moment it happened, that "
              "something did not add up. The most serious kind is a <em>quorum "
              "divergence</em>: the verifier members disagreed about the same input, "
              "which must never happen if all of them are honest and intact.",
              "None recorded — the wallet has never detected a divergence or tamper "
              "event. Empty is the good state here.",
              "<ul><li><strong>severity</strong> — how bad: a <code>divergence</code> or "
              "<code>tamper</code> incident also trips the custody latch.</li>"
              "<li><strong>detail</strong> — what exactly was observed, in the wallet's "
              "own words.</li>"
              "<li><strong>at</strong> — when it was recorded (UTC).</li>"
              "<li><strong>payload_sha256</strong> — fingerprint of the input the members "
              "disagreed about, so the case can be replayed later.</li>"
              "<li>Incident files are never deleted; they are the permanent record.</li></ul>",
              "incidents/*.json, verbatim, newest first")
        + block(f"Refusal receipts — every «no», in writing {_help('refusal')}", refusals,
                "When the wallet declines to do something, it answers with a signed, "
                "machine-readable receipt instead of a bare error: the rule it applied "
                "(<code>code</code>), what was missing, and what would fix it "
                "(<code>remediation</code>). An agent — or you — can read it, correct the "
                "problem, and retry. No guessing.",
                "None recorded — nothing has been refused yet.",
                "<ul><li><strong>code</strong> — the rule that fired, e.g. "
                "<code>POLICY_DENIED</code> (a spending rule) or <code>CUSTODY_LATCHED</code> "
                "(the emergency brake is on).</li>"
                "<li><strong>missing</strong> — the concrete precondition that was not "
                "met.</li>"
                "<li><strong>remediation</strong> — what would make the same request "
                "succeed.</li></ul>",
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
                "<p class='plain'>A green verdict means every check passed: the "
                "signatures are valid and the attestation really is recorded in the log "
                "under the signed head. A red verdict means at least one check failed — "
                "the diagnostics below name each check verbatim, so you can see exactly "
                "which one.</p>"
                f"<div class='tablewrap'><table><tr><th>signature check</th>"
                f"<th>result</th></tr>{sigs}</table></div>"
                f"<h2>Diagnostics</h2><ul class='diag'>{diags}</ul>"
                f"{_provenance(result['via'])}</div>")
    return (
        verdict +
        f"<div class='panel'><h2 style='margin-top:0'>Check a receipt yourself {_help('attestation')}</h2>"
        "<p class='plain'>An <strong>attestation</strong> is a signed statement that a "
        "verification run happened — on an exact commit, with an exact toolchain, with a "
        "stated result. Its <strong>transparency receipt</strong> proves that statement "
        "is permanently recorded in the public Lean Transparency Log. The <strong>log "
        "public key</strong> is what the log signs with. The verdict is produced by the "
        "wallet's own deployed verifier — this page adds nothing and hides nothing.</p>"
        + _explain(
            "<ul><li><strong>Where do I get these?</strong> For the live log: attestation "
            "and receipt from <code>ltl.zkdefi.org/v1/attestation?component=…</code>, the "
            "public key (<code>log.pub</code>) from the log's mirror repository. This "
            "repository also ships samples under <code>examples/wallet-evidence/</code> — "
            "paste those to see the verifier work.</li>"
            "<li><strong>Is this safe?</strong> Yes: nothing you paste is stored. The "
            "artifacts live in a throwaway temp folder outside the wallet for the "
            "duration of the check, and the wallet directory is never written.</li>"
            "<li><strong>If the input is malformed</strong>, the page shows FAILED TO "
            "VERIFY rather than guessing.</li></ul>")
        + "<form method='post' action='/inspect'>"
        f"<p><strong>attestation.json</strong> <span class='muted'>— the signed verification statement</span><br>"
        f"<textarea name='attestation'>{_esc(d.get('attestation', ''))}</textarea></p>"
        f"<p><strong>receipt.json</strong> <span class='muted'>— the log's proof that the statement is recorded</span><br>"
        f"<textarea name='receipt'>{_esc(d.get('receipt', ''))}</textarea></p>"
        f"<p><strong>log public key (PEM)</strong> <span class='muted'>— starts with "
        f"<code>-----BEGIN PUBLIC KEY-----</code></span><br>"
        f"<textarea name='pubkey' style='min-height:4rem'>{_esc(d.get('pubkey', ''))}</textarea></p>"
        "<button type='submit'>Verify (read-only)</button></form></div>"
    )


def render_guide() -> str:
    """The manual: static plain-language explanations, no live data."""
    return (
        # --- what is warden ------------------------------------------------
        "<div class='panel'><h2 style='margin-top:0' id='what'>What is warden?</h2>"
        "<p class='plain'>warden is a prototype custody wallet built on one idea: "
        "<strong>no single program is trusted</strong>. Four verifier programs, each "
        "built from a different formally verified codebase, must independently agree "
        "before the wallet trusts a cryptographic component. If they ever disagree, the "
        "wallet freezes itself and writes down what happened. Every decision leaves a "
        "tamper-evident trace.</p></div>"
        # --- what is the cockpit -------------------------------------------
        "<div class='panel'><h2 style='margin-top:0' id='cockpit'>What is this cockpit?</h2>"
        "<p class='plain'>A local, read-only window onto one wallet directory, for the "
        "human who ultimately answers for the money. Its design law: <strong>the cockpit "
        "renders evidence, it never asserts it</strong>. Every page is recomputed from "
        "the wallet's files at the moment you load it, by the same functions the wallet "
        "itself uses. It cannot approve, sign, unlatch, or change anything — the server "
        "has no writing routes, and the test suite proves a full click-through changes "
        "not one byte of wallet state.</p></div>"
        # --- how to read ---------------------------------------------------
        "<div class='panel'><h2 style='margin-top:0' id='reading'>How to read any page here</h2>"
        "<ol>"
        "<li><strong>Verdict first.</strong> The top of a page states the conclusion in "
        "words — e.g. CUSTODY HEALTHY or CUSTODY FROZEN. If you read nothing else, read "
        "that.</li>"
        "<li><strong>Evidence below.</strong> Each panel shows the recomputed facts "
        "behind the verdict. Every panel has a «How to read this panel» expander, and "
        "every jargon term carries a small <a class='help' href='#glossary'>?</a> that "
        "jumps here.</li>"
        "<li><strong>Provenance last.</strong> The dashed line at the bottom of every "
        "panel names the exact function and time that produced it — your proof that "
        "nothing was cached.</li>"
        "</ol>"
        "<p class='plain'>Colors mean one thing each: "
        "<span class='pill ok'>green</span> = re-checked just now and passed · "
        "<span class='pill warn'>amber</span> = waiting, or needs your attention · "
        "<span class='pill bad'>red</span> = re-checked and failed, or could not be "
        "checked at all. A red <strong>FAILED TO VERIFY</strong> panel is the cockpit "
        "being honest: it refuses to show a green it cannot back up right now. There is "
        "no neutral gray anywhere.</p></div>"
        # --- tour ----------------------------------------------------------
        "<div class='panel'><h2 style='margin-top:0' id='tour'>A five-minute tour</h2>"
        "<ol>"
        "<li>Open <a href='/'>Posture</a> — read the verdict banner, then the panels top "
        "to bottom: latch, ledger, quorum, signing rules, recorded history.</li>"
        "<li>Open <a href='/incidents'>Incidents</a> — on a healthy wallet both lists are "
        "empty, and the page says why that is the good state.</li>"
        "<li>Open <a href='/queue'>Queue</a> — empty unless a signature is waiting for "
        "the offline device.</li>"
        "<li>Open <a href='/inspect'>Inspect</a> — paste the sample artifacts from "
        "<code>examples/wallet-evidence/</code> and watch the deployed verifier run.</li>"
        "<li>Open the <a href='/estate'>Estate map</a> — where this wallet sits in the "
        "wider verified-crypto estate, and what is actually running where.</li>"
        "</ol></div>"
        # --- glossary ------------------------------------------------------
        "<div class='panel'><h2 style='margin-top:0' id='glossary'>Glossary</h2>"
        "<dl class='gloss'>"
        "<dt id='capsule'>custody capsule</dt>"
        "<dd>The wallet's founding document: which verifier members it trusts, their "
        "pinned binary fingerprints, and the policy (unanimity, minimum members, required "
        "evidence grade). Sealed when the wallet is created; its SHA-256 is anchored in "
        "the ledger's first entry, so it cannot be quietly swapped later.</dd>"
        "<dt id='member'>quorum member</dt>"
        "<dd>One of the verifier programs the capsule names. Each is built from a "
        "different formally verified Ed25519 codebase (dalek, anza, risc0, betrusted), so "
        "a bug — or a backdoor — would have to exist in all of them independently for a "
        "wrong verdict to slip through unanimously.</dd>"
        "<dt id='pinned'>pinned (binary fingerprint)</dt>"
        "<dd>The capsule stores the SHA-256 hash of each member executable. Before use, "
        "the file on disk is re-hashed and compared; a modified or swapped binary fails "
        "the comparison and is rejected. Pinning proves the file is <em>unchanged</em> — "
        "not that it was honestly <em>built</em> (see the limits section below).</dd>"
        "<dt id='tier'>evidence grade (R0–R5)</dt>"
        "<dd>This project's scale for how strong the formal evidence behind a component "
        "is. R0 = no usable evidence; R4 = machine-checked proofs covering the component's "
        "full documented boundary; R5 would add reproducible builds and side-channel "
        "assurance — nothing holds R5 yet, and the gap is stated rather than hidden. This "
        "wallet's capsule requires R4 of every member.</dd>"
        "<dt id='ledger'>ledger / hash chain</dt>"
        "<dd>The wallet's append-only journal of custody events. Every entry contains the "
        "hash of the previous entry; the newest hash is called the «head». Rewriting, "
        "deleting, or reordering anything in the past changes the hashes and breaks the "
        "chain visibly — that is what «chain verified» re-checks on every page load.</dd>"
        "<dt id='latch'>custody latch</dt>"
        "<dd>The wallet's emergency brake. It trips on quorum divergence or suspected "
        "tampering; while latched, all outbound signing is frozen and every request is "
        "refused with a receipt. Only a deliberate operator action through the wallet's "
        "own channels can clear it — never this cockpit. Recovery steps: "
        "<code>docs/runbook-latch.md</code>.</dd>"
        "<dt id='incident'>incident</dt>"
        "<dd>A file the wallet writes the moment it notices something wrong — for "
        "example, one member answering INVALID while the others answer OK. Incidents are "
        "never deleted; serious ones also trip the latch.</dd>"
        "<dt id='refusal'>refusal receipt</dt>"
        "<dd>When the wallet declines to act, it answers in writing: a machine-readable "
        "receipt naming the rule (<code>code</code>), what was missing, and what would "
        "fix it (<code>remediation</code>). An agent can read it, correct the problem, "
        "and retry — no guessing at error messages.</dd>"
        "<dt id='airgap'>air-gap outbox / inbox</dt>"
        "<dd>The signing key may live on a device that never touches a network. Signing "
        "requests are parked as files in an outbox and carried across by a human; "
        "responses come back through an inbox. The Queue page watches both folders and "
        "touches neither.</dd>"
        "<dt id='attestation'>attestation &amp; transparency receipt</dt>"
        "<dd>An attestation is a signed statement that a verification run happened: which "
        "repository, which exact commit, which toolchain, what result. Its transparency "
        "receipt proves the statement is permanently recorded in the public Lean "
        "Transparency Log — so it can never be quietly edited, backdated, or denied "
        "later. The Inspect tab re-verifies both.</dd>"
        "<dt id='provenance'>provenance line</dt>"
        "<dd>The dashed footer on every panel, naming the exact function that recomputed "
        "the panel and when. It is the cockpit's signature move: evidence of freshness "
        "attached to every claim.</dd>"
        "<dt id='demo'>DEMO wallet</dt>"
        "<dd>A throwaway wallet sealed by <code>pacta wallet cockpit --demo</code> so you "
        "can explore this cockpit before creating a real wallet. Its members are fake "
        "shell stubs, every label says DEMO, and it can sign nothing real. Real wallets "
        "are sealed with <code>pacta wallet init</code>.</dd>"
        "</dl></div>"
        # --- limits --------------------------------------------------------
        "<div class='panel'><h2 style='margin-top:0' id='limits'>What this cockpit cannot tell you</h2>"
        "<ul class='diag'>"
        "<li>Whether the pinned binaries were honestly <em>built</em> from their attested "
        "sources — reproducible builds are out of scope (the R5 gap), stated in the paper "
        "and the claim cards rather than hidden.</li>"
        "<li>Whether the machine this cockpit runs on is itself clean — a compromised "
        "operating system can lie to any dashboard, including this one.</li>"
        "<li>Anything it could not recompute just now — that renders as a red FAILED TO "
        "VERIFY panel, never as a guess and never as a stale green.</li>"
        "</ul></div>"
    )


# ---------------------------------------------------------------------------
# demo wallet - custody-inert, for exploring the cockpit from zero
# ---------------------------------------------------------------------------

def seal_demo_wallet(root: str | Path | None = None) -> Path:
    """Seal a throwaway DEMO wallet: four fake quorum members (shell stubs,
    NOT the verified binaries), a genesis ledger, a fresh keypair, and one
    sample incident / refusal / airgap request so every view has content.

    Custody-inert by construction: nothing here can sign anything real,
    and the wallet lives in a throwaway directory whose name says DEMO.
    """
    import stat

    from .quorum import binary_path
    from .signing import generate_ed25519_keypair

    if root is None:
        root = Path(tempfile.mkdtemp(prefix="warden-DEMO-"))
    root = Path(root)
    state_dir = root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    def _sha(data: bytes) -> str:
        import hashlib
        return hashlib.sha256(data).hexdigest()

    members = []
    for name in ("dalek", "anza", "risc0", "betrusted"):
        binary = binary_path(name, state_dir)
        binary.write_text("#!/bin/sh\necho OK\nexit 0\n")
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        members.append({
            "backend": name, "component": f"{name}-ed25519-verified",
            "semantics": "DEMO", "entry_point": "DEMO",
            "source_commit": "deadbeef" * 5, "repo_commit": "cafe" * 10,
            "binary_sha256": _sha(binary.read_bytes()),
            "backend_cfg": "DEMO", "risk_tier": "R4",
            "evidence": {"leaf_hash": "00", "leaf_index": 0, "tree_size": 1,
                         "inclusion_proof": [],
                         "sth": {"timestamp": "2099-01-01T00:00:00Z"}},
        })
    wallet = Wallet(root / "wallet")
    for sub in (wallet.keys_dir, wallet.incidents_dir, wallet.receipts_dir,
                wallet.quarantine_dir, wallet.airgap_dir / "outbox",
                wallet.airgap_dir / "inbox"):
        sub.mkdir(parents=True, exist_ok=True)
    capsule = {
        "type": "pacta.wallet.custody_capsule.v1",
        "created_at": _now(), "members": members,
        "policy": {"require_unanimity": True, "min_members": 4,
                   "require_tier": "R4", "freshness_max_age_days": 0},
        "signing": {"backend": "DEMO"}, "problems_at_init": [],
    }
    wallet.capsule_path.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n")
    wallet._append_ledger("genesis", {
        "type": "pacta.wallet.ledger_genesis.v1",
        "capsule_sha256": _sha(json.dumps(capsule, sort_keys=True,
                                          separators=(",", ":")).encode())})
    generate_ed25519_keypair(wallet.keys_dir / "warden.key.pem",
                             wallet.keys_dir / "warden.pub.pem")
    (wallet.incidents_dir / "incident-0001.json").write_text(json.dumps(
        {"type": "pacta.wallet.incident.v1", "severity": "divergence",
         "detail": "DEMO sample: member risc0 returned INVALID where the "
                   "other three returned OK",
         "at": _now(), "payload_sha256": "ab" * 32}, indent=2))
    (wallet.receipts_dir / "refusal-0001.json").write_text(json.dumps(
        {"type": "pacta.wallet.refusal.v1", "code": "POLICY_DENIED",
         "missing": ["allowlisted destination"],
         "remediation": "DEMO sample: add destination to policy.json allowlist",
         "at": _now()}, indent=2))
    (wallet.airgap_dir / "outbox" / "req-demo.request.json").write_text(json.dumps(
        {"created_at": _now(), "payload_sha256": "cd" * 32}))
    return wallet.dir


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

_ESTATE_BACK_CHIP = (
    '<a href="/" style="position:fixed;left:14px;bottom:14px;z-index:999;'
    'background:#1c2430;color:#fff;padding:.45rem .8rem;border-radius:8px;'
    'font:600 .8rem system-ui;text-decoration:none;'
    'box-shadow:0 2px 8px rgba(0,0,0,.25)">← Back to cockpit</a>')


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
            elif route == "/guide":
                self._send(_page("guide", "/guide", render_guide(), wd))
            elif route == "/estate":
                from .estateview import ESTATE_HTML
                self._send(ESTATE_HTML + _ESTATE_BACK_CHIP)
            else:
                self._send(_page("not found", "",
                                 "<div class='panel bad'>No such view. The tabs above list "
                                 "everything this cockpit can show.</div>", wd), 404)

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
