"""walletui - the warden custody cockpit (local, read-only): a bridge
with six role stations over shared evidence instruments.

Information architecture (control-room style, four levels):
  1. BRIDGE (/)            - whole-system verdict + the crew of six roles
  2. STATIONS (/station/*) - one console per role: mission, duties as
                             runnable commands, live instruments, the
                             never-list, explicit handoffs
  3. INSTRUMENTS           - shared evidence views: posture, queue,
                             incidents, inspect, estate, guide
  4. RAW                   - the wallet files and the CLI themselves

Three laws, each enforced by tests:

DESIGN LAW - THE COCKPIT RENDERS EVIDENCE, IT NEVER ASSERTS IT. Every
panel is recomputed from wallet state or submitted artifacts at request
time by the same functions the wallet itself uses, and every panel names
the function and timestamp that produced it. Anything that cannot be
recomputed renders as a loud FAILED-TO-VERIFY panel - no cached green,
no neutral gray.

UX LAW - THE COCKPIT NEVER LEAVES A HUMAN IN THE DARK. Every page opens
with a plain-language lead; every verdict is stated in words; every
panel carries a "how to read this" explainer; every jargon term links to
the /guide glossary.

CREW LAW - ROLES ARE DISTINCT AND COOPERATE THROUGH HANDOFFS. The bridge
presents everything a human crew would need if no AI were around: six
stations (proposer, quorum bench, operator, cryptographer, architect,
newcomer), each with runnable duties and a "this station never" list.
Separation of duties is a custody control; the stations do not melt into
each other. (Role content lives in stations.py; liveness probes in
liveness.py; shared primitives in uikit.py.)

Read-only guarantee: this module calls only read paths (``Wallet.posture``,
``verify_ledger``, directory listings), ``transparency.verify_receipt`` on
submitted artifacts (parsed in memory / temp files outside the wallet),
and - only when the operator explicitly presses "Probe now" - outbound
liveness observations (HTTP GET, git queries). It cannot approve, sign,
unlatch, or modify custody state; the HTTP surface exposes no mutating
route. Human approve/deny is deliberately NOT here - that would be a
custody-semantics change, which belongs to a separate, explicitly
reviewed milestone. The mutating acts a human crew needs are provided as
exact CLI commands on the stations instead.

The server binds 127.0.0.1 by default and is not meant to be exposed.
"""
from __future__ import annotations

import json
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .attestation import load_attestation
from .deck import render_deck
from .liveness import collect_liveness, render_liveness
from .mdlite import render as render_markdown
from .stations import STATION_BY_ID, STATIONS, render_bridge, render_station
from .transparency import load_receipt, verify_receipt
from .uikit import (STYLE, esc as _esc, explain as _explain,
                    failed_panel as _failed_panel, help_link as _help,
                    now_utc as _now, provenance as _provenance)
from .wallet import Wallet


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


def _collect_drift() -> dict[str, Any]:
    """The Architect's live tripwire: do the two estate renderings agree?"""
    def read() -> dict[str, Any]:
        from .estateview import ESTATE_HTML
        estate_md = (Path(__file__).resolve().parents[2] / "ESTATE.md").read_text(
            encoding="utf-8")
        sentinels = ["lean-transparency-log", "ltl-accumulator-verified",
                     "proof-aware-crypto-tooling-agent", "verifying-crypto-with-lean",
                     "dalek-ed25519-verified", "pasta-pallas-verified",
                     "ltl.zkdefi.org", "Forgejo"]
        missing = ([f"{n} (estate view)" for n in sentinels if n not in ESTATE_HTML]
                   + [f"{n} (ESTATE.md)" for n in sentinels if n not in estate_md])
        return {"sentinels": len(sentinels), "missing": missing,
                "runtime_in_both": ("What is running" in estate_md
                                    and "ALWAYS ON" in ESTATE_HTML)}
    return collect("name-level comparison of estateview.ESTATE_HTML vs ESTATE.md", read)


# ---------------------------------------------------------------------------
# page shell - two-row navigation (stations / instruments), lead on every view
# ---------------------------------------------------------------------------

_STATION_TABS = [("/", "Bridge", "the whole system at a glance"),
                 ("/deck", "Deck", "all stations live, side by side")] + [
    (f"/station/{s['id']}", s["name"], sub) for s, sub in zip(STATIONS, [
        "ask for signatures", "four seats, one answer each",
        "liveness + latch recovery", "recompute everything",
        "map = territory", "start here"])]

_INSTRUMENT_TABS = [
    ("/posture", "Posture", "is custody healthy right now?"),
    ("/queue", "Queue", "what awaits the offline signer?"),
    ("/incidents", "Incidents", "what has ever gone wrong?"),
    ("/inspect", "Inspect", "check a receipt yourself"),
    ("/estate", "Estate map", "the territory, drawn"),
    ("/guide", "Guide", "every term, explained"),
    ("/manual", "Lab manual", "the full course, chair by chair"),
]

_LEADS: dict[str, str] = {
    "/": ('This is the <strong>bridge</strong>: the whole estate at one glance, then '
          'the crew. The verdict strip is recomputed on load; each crew card opens a '
          '<strong>station</strong> — one human role with its duties, commands, and '
          'handoffs. If no AI were around, these six stations are how people would '
          'run this system.'),
    "/posture": ('This page answers one question: <strong>is custody healthy right '
                 'now?</strong> The verdict comes first, the evidence behind it below. '
                 'Every panel ends with a dashed provenance line naming the exact '
                 'function that just recomputed it — and every small '
                 '<a class="help" href="/guide#glossary">?</a> jumps to a '
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
               'this page is live data — this is the reference. The Bridge and the stations '
               'are the working surfaces; the instruments are the shared evidence. For the '
               'full course, open the <a href="/manual">Lab manual</a>.'),
    "/manual": ('The full course: put this page on one monitor and the '
                '<a href="/deck">deck</a> on the other, then work it like a lab — session '
                'by session, chair by chair, from Newcomer to graduation. The table of '
                'contents below is your syllabus; your place is wherever your last '
                'checkpoint passed.'),
}
for _s in STATIONS:
    _LEADS[f"/station/{_s['id']}"] = _s["lead"]


def _tabs(items: list[tuple[str, str, str]], active: str) -> str:
    return "".join(
        f'<a href="{href}"{" class=here" if href == active else ""}>{label}'
        f'<span class="navsub">{sub}</span></a>'
        for href, label, sub in items)


def _pane_shell(title: str, body: str) -> str:
    """Chrome-stripped render for deck panes: same content, no h1/banner/nav.

    A tiny script keeps navigation inside the pane (every same-origin link
    and form submit re-carries ?pane=1), so a pane behaves like a tmux pane:
    an independent, self-contained viewport onto the cockpit.
    """
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_esc(title)} — pane</title>"
        f"<style>{STYLE} body{{max-width:none;padding:.6rem .8rem 2.2rem}}</style>"
        "</head><body>"
        f"{body}"
        "<div class='prov'>READ-ONLY pane — part of the "
        "<a href='/deck' target='_top'>deck</a>. Links stay inside this pane; "
        "use the pane header's ↗ for the full page.</div>"
        "<script>(function(){"
        "document.addEventListener('click',function(e){"
        "var a=e.target.closest('a');if(!a||a.target==='_top'){return;}"
        "try{var u=new URL(a.getAttribute('href'),location.href);"
        "if(u.origin===location.origin&&!u.searchParams.has('pane')){"
        "u.searchParams.set('pane','1');a.href=u.toString();}}catch(err){}});"
        "document.addEventListener('submit',function(e){"
        "try{var f=e.target;"
        "var u=new URL(f.getAttribute('action')||location.href,location.href);"
        "u.searchParams.set('pane','1');f.action=u.toString();}catch(err){}});"
        "})();</script>"
        "</body></html>")


def _load_sample_evidence() -> tuple[dict[str, str] | None, str]:
    """Pre-fill the inspector from examples/wallet-evidence (read-only)."""
    root = Path(__file__).resolve().parents[2] / "examples" / "wallet-evidence"
    attestations = sorted(root.glob("*.attestation.json"))
    receipts = sorted(root.glob("*.receipt.json"))
    key = root / "log.pub"
    fallback_note = (
        "<div class='panel'><p class='empty'>No sample evidence found on this "
        "machine (expected under <code>examples/wallet-evidence/</code>). Fetch "
        "real evidence from the live log instead: <code>pacta log-fetch --url "
        "https://ltl.zkdefi.org --component dalek-ed25519-verified</code>, then "
        "paste the two files and the log's <code>log.pub</code>.</p></div>")
    if not (attestations and receipts and key.exists()):
        return None, fallback_note
    by_stem = {p.name.removesuffix(".attestation.json"): p for p in attestations}
    for rec in receipts:
        stem = rec.name.removesuffix(".receipt.json")
        if stem in by_stem:
            note = (
                "<div class='panel'><p class='plain'>"
                "<span class='pill ok'>sample loaded</span> evidence for "
                f"<code>{_esc(stem)}</code> is pre-filled below — press «Verify "
                "(read-only)» to watch the deployed verifier run. Then delete one "
                "character from the receipt box and verify again: watch it refuse, "
                "and read which check failed.</p></div>")
            return ({"attestation": by_stem[stem].read_text(encoding="utf-8"),
                     "receipt": rec.read_text(encoding="utf-8"),
                     "pubkey": key.read_text(encoding="utf-8")}, note)
    return None, fallback_note


def _page(title: str, active: str, body: str, wallet_dir: str) -> str:
    nav = (f'<div class="navrow"><span class="navtag">STATIONS</span>'
           f'{_tabs(_STATION_TABS, active)}</div>'
           f'<div class="navrow"><span class="navtag">INSTRUMENTS</span>'
           f'{_tabs(_INSTRUMENT_TABS, active)}</div>')
    demo_badge = ('<span class="pill warn" title="sealed by --demo; fake members; can sign '
                  'nothing real">DEMO WALLET — custody-inert</span> '
                  if "DEMO" in wallet_dir else "")
    lead = _LEADS.get(active, "")
    lead_html = f'<p class="lead">{lead}</p>' if lead else ""
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>warden cockpit — {_esc(title)}</title>"
        f"<style>{STYLE}</style></head><body>"
        f"<h1>warden custody cockpit {demo_badge}</h1>"
        f"<p class='sub'>Watching wallet <code>{_esc(wallet_dir)}</code> — everything below is "
        "recomputed live from that directory each time a page loads; nothing is cached, "
        "nothing is taken on trust.</p>"
        "<div class='banner'>READ-ONLY. This cockpit observes and recomputes; it cannot "
        "approve, sign, unlatch, or modify custody state — the stations give you the "
        "exact commands for every act instead. First time here? Start with the "
        "<a href='/guide'>Guide</a> or the <a href='/station/newcomer'>Newcomer "
        "station</a>.</div>"
        f"{nav}{lead_html}{body}</body></html>"
    )


# ---------------------------------------------------------------------------
# posture instrument - verdict banner + five evidence panels
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


def _panel_latch(p: dict[str, Any]) -> str:
    latch = p["latch"]
    latch_pill = ('<span class="pill bad">LATCHED — outbound custody frozen</span>'
                  if latch.get("latched") else '<span class="pill ok">unlatched</span>')
    latch_detail = ""
    if latch.get("latched"):
        latch_detail = (f"<p class='plain'>Trigger: <code>{_esc(latch.get('reason'))}</code> · "
                        f"recorded as incident <code>{_esc(latch.get('incident'))}</code> · "
                        f"frozen since {_esc(latch.get('at'))}. Read the incident in the "
                        f"<a href='/incidents'>incident browser</a>, then follow "
                        f"<code>docs/runbook-latch.md</code> to recover.</p>")
    return (
        f"<div class='panel'><h2 style='margin-top:0'>Custody latch {_help('latch')} {latch_pill}</h2>"
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
        + f"{_provenance('Wallet.latch_state()')}</div>")


def _panel_ledger(p: dict[str, Any]) -> str:
    ledger = p["ledger"]
    chain_pill = ('<span class="pill ok">chain verified</span>' if ledger["chain_ok"]
                  else '<span class="pill bad">CHAIN BROKEN</span>')
    problems = "".join(f"<li>{_esc(x)}</li>" for x in ledger["problems"]) or (
        "<li>none — every link in the chain held</li>")
    return (
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
        + f"{_provenance('Wallet.verify_ledger() — full hash-chain recomputation')}</div>")


def _panel_quorum(p: dict[str, Any]) -> str:
    members = "".join(
        f"<tr><td><code>{_esc(m['backend'])}</code></td>"
        f"<td class='mono'>{_esc(m['component'])}</td>"
        f"<td>{_esc(m['risk_tier'])}</td>"
        f"<td class='mono'>{_esc(m['source_commit'][:12])}…</td>"
        f"<td class='mono'>{_esc(m['binary_sha256'][:16])}…</td></tr>"
        for m in p["members"])
    return (
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
        f"{_provenance('Wallet.capsule() / Wallet.posture()')}</div>")


def _panel_policy(p: dict[str, Any]) -> str:
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
        f"<div class='panel'><h2 style='margin-top:0'>Signing rules (spending policy)</h2>"
        f"{spending_note}"
        f"<pre style='margin:0;font-size:.8rem'>{_esc(json.dumps(spending, indent=2, sort_keys=True))}</pre>"
        f"{_provenance('Wallet.policy() (policy.json, verbatim)')}</div>")


def _panel_history(p: dict[str, Any]) -> str:
    return (
        f"<div class='panel'><h2 style='margin-top:0'>Recorded history</h2>"
        f"<p class='plain'>Incidents on file: <strong>{p['incidents']}</strong> · refusal "
        f"receipts on file: <strong>{p['refusal_receipts']}</strong> — read every one, "
        "verbatim, under <a href='/incidents'>Incidents</a>. An incident is the wallet "
        "noticing something wrong; a refusal receipt is the wallet saying no, in writing.</p>"
        f"{_provenance('directory counts, recomputed')}</div>")


def render_posture(posture: dict[str, Any]) -> str:
    if not posture["ok"]:
        return _failed_panel("Custody posture", posture["via"], posture["error"])
    p = posture["data"]
    return (_posture_verdict(p) + _panel_latch(p) + _panel_ledger(p)
            + _panel_quorum(p) + _panel_policy(p) + _panel_history(p))


# ---------------------------------------------------------------------------
# queue / incidents / inspect instruments
# ---------------------------------------------------------------------------

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
              explain_body: str, via_note: str) -> str:
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
                f"<p class='plain'>{intro}</p>{body}{_explain(explain_body)}"
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
        + "<p><a class='btnlink' href='/inspect?sample=1'>Load the sample evidence</a> "
        "<span class='muted'>from <code>examples/wallet-evidence/</code> — it fills the "
        "three boxes below so you can watch a real verification.</span></p>"
        "<form method='post' action='/inspect'>"
        f"<p><strong>attestation.json</strong> <span class='muted'>— the signed verification statement</span><br>"
        f"<textarea name='attestation'>{_esc(d.get('attestation', ''))}</textarea></p>"
        f"<p><strong>receipt.json</strong> <span class='muted'>— the log's proof that the statement is recorded</span><br>"
        f"<textarea name='receipt'>{_esc(d.get('receipt', ''))}</textarea></p>"
        f"<p><strong>log public key (PEM)</strong> <span class='muted'>— starts with "
        f"<code>-----BEGIN PUBLIC KEY-----</code></span><br>"
        f"<textarea name='pubkey' style='min-height:4rem'>{_esc(d.get('pubkey', ''))}</textarea></p>"
        "<button type='submit'>Verify (read-only)</button></form></div>"
    )


# ---------------------------------------------------------------------------
# bridge assembly - verdict strip + live crew snippets
# ---------------------------------------------------------------------------

def _bridge_strip(posture: dict[str, Any], airgap: dict[str, Any]) -> str:
    if not posture["ok"]:
        return _failed_panel("Custody verdict", posture["via"], posture["error"])
    p = posture["data"]
    ledger = p["ledger"]
    chain = ('<span class="pill ok">chain verified</span>' if ledger["chain_ok"]
             else '<span class="pill bad">CHAIN BROKEN</span>')
    pending: Any = "?"
    if airgap["ok"]:
        pending = sum(1 for r in airgap["data"] if not r["answered"])
    return (
        _posture_verdict(p)
        + "<div class='strip'>"
        f"<span class='chip'>quorum <b>{len(p['members'])} pinned</b></span>"
        f"<span class='chip'>ledger {chain}</span>"
        f"<span class='chip'>incidents <b>{p['incidents']}</b> · refusals "
        f"<b>{p['refusal_receipts']}</b></span>"
        f"<span class='chip'>queue <b>{pending} awaiting device</b></span>"
        "<span class='chip'>liveness — <a href='/station/operator?probe=1'>probe from "
        "the Operator station</a></span>"
        "<span class='chip'><a href='/deck'><b>Open the deck →</b></a> all six "
        "stations live, side by side, with the guided wizard</span>"
        "</div>"
        + _provenance("Wallet.posture() + airgap listing (liveness only on demand)")
    )


def _bridge_live(posture: dict[str, Any], airgap: dict[str, Any]) -> dict[str, str]:
    live: dict[str, str] = {
        "cryptographer": "<div class='live muted'>instrument ready: Inspect</div>",
        "architect": "<div class='live muted'>estate view + drift tripwire ready</div>",
        "newcomer": "<div class='live muted'>start: the Guide, then the demo</div>",
    }
    if posture["ok"]:
        p = posture["data"]
        seats = ", ".join(f"<span class='mono'>{_esc(m['component'])}</span>"
                          for m in p["members"])
        latch_word = ("LATCHED" if p["latch"].get("latched") else "unlatched")
        live["quorum"] = f"<div class='live'>seats: {seats}</div>"
        live["operator"] = (f"<div class='live'>incidents on file: <b>{p['incidents']}</b>"
                            f" · latch: <b>{latch_word}</b></div>")
    if airgap["ok"]:
        pending = sum(1 for r in airgap["data"] if not r["answered"])
        live["proposer"] = f"<div class='live'>queue: <b>{pending}</b> awaiting device</div>"
    return live


def _render_drift_panel() -> str:
    coll = _collect_drift()
    if not coll["ok"]:
        return _failed_panel("Estate drift tripwire", coll["via"], coll["error"])
    d = coll["data"]
    if d["missing"] or not d["runtime_in_both"]:
        missing = "".join(f"<li><code>{_esc(x)}</code></li>" for x in d["missing"]) or ""
        runtime = ("" if d["runtime_in_both"] else
                   "<li>the runtime dimension is missing from one rendering</li>")
        body = (f"<p class='plain'><span class='pill bad'>DRIFT</span> the two renderings "
                f"of the estate disagree:</p><ul class='diag'>{missing}{runtime}</ul>")
    else:
        body = (f"<p class='plain'><span class='pill ok'>renderings agree</span> all "
                f"{d['sentinels']} sentinel names present in both <code>ESTATE.md</code> "
                "and the cockpit estate view, and both carry the runtime dimension.</p>")
    return (
        "<div class='panel'><h3 style='margin-top:0'>Drift tripwire — map vs map</h3>"
        "<p class='plain'>The estate map exists twice: the committed "
        "<code>ESTATE.md</code> and the <a href='/estate'>estate view</a>. Two "
        "renderings of one model need a tripwire — this panel compares them live, "
        "name by name.</p>"
        + body
        + _explain(
            "<ul><li>The comparison is name-level (sentinel entities + the runtime "
            "dimension) — the same check the test suite runs.</li>"
            "<li>On DRIFT: fix the stale rendering AND check its generator — a "
            "published file that drifted from its source once will drift again.</li></ul>")
        + _provenance(coll["via"]) + "</div>")


# ---------------------------------------------------------------------------
# lab manual instrument - the course, rendered from its canonical Markdown
# ---------------------------------------------------------------------------

def render_manual() -> str:
    """The lab manual: docs/warden-lab-manual.md rendered with a syllabus.

    The Markdown file in the repository is canonical (readable on the
    mirror, diffable, committed); this route renders it so the course can
    sit on one monitor while the deck flies on the other."""
    def read() -> str:
        path = Path(__file__).resolve().parents[2] / "docs" / "warden-lab-manual.md"
        return path.read_text(encoding="utf-8")
    coll = collect("docs/warden-lab-manual.md (canonical file, rendered live)", read)
    if not coll["ok"]:
        return _failed_panel("Lab manual", coll["via"], coll["error"])
    body, toc = render_markdown(coll["data"])
    toc_items = "".join(
        f'<li class="toc{level}"><a href="#{anchor}">{_esc(text)}</a></li>'
        for level, text, anchor in toc if level == 2)
    return (
        "<div class='panel toc'><h2 style='margin-top:0'>Syllabus</h2>"
        f"<ol>{toc_items}</ol>"
        "<p class='muted'>Sessions build on each other; the capstone assumes "
        "all six chairs. Answers to every self-test are in Appendix B — "
        "attempt first, then check. Marks: ▶ do · ✔ checkpoint · ✎ write · "
        "⌂ optional.</p></div>"
        f"<div class='manual'>{body}</div>"
        f"{_provenance(coll['via'])}"
    )


# ---------------------------------------------------------------------------
# guide instrument - the reference
# ---------------------------------------------------------------------------

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
        "humans who ultimately answer for the money. Its design law: <strong>the cockpit "
        "renders evidence, it never asserts it</strong>. Every page is recomputed from "
        "the wallet's files at the moment you load it, by the same functions the wallet "
        "itself uses. It cannot approve, sign, unlatch, or change anything — the server "
        "has no writing routes, and the test suite proves a full click-through changes "
        "not one byte of wallet state. What it does provide is the <em>work</em>: the "
        "<a href='/'>Bridge</a> organizes everything a human crew would do if no AI were "
        "around, as six role stations with runnable commands.</p></div>"
        # --- the crew ------------------------------------------------------
        "<div class='panel'><h2 style='margin-top:0' id='crew'>The crew model</h2>"
        "<p class='plain'>Six roles run this estate: the <strong>Proposer</strong> asks "
        "for signatures; the <strong>Quorum bench</strong> holds four independent "
        "verifier seats; the <strong>Operator</strong> watches liveness and owns latch "
        "recovery; the <strong>Cryptographer</strong> recomputes every piece of "
        "evidence; the <strong>Architect</strong> keeps the estate map true; the "
        "<strong>Newcomer</strong> learns — and supplies fresh eyes. Roles cooperate "
        "through explicit handoffs and never blur: the one who proposes never approves, "
        "the one who verifies never proposes, the one who watches never overrides the "
        "bench. One person (or one agent) may hold several stations — explicitly, one "
        "at a time, with the handoffs still applying. Each station page states its "
        "mission, duties as commands, and what it <em>never</em> does.</p></div>"
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
        "<li>Open the <a href='/'>Bridge</a> — the verdict strip is the whole system in "
        "one line; the crew cards are who does what.</li>"
        "<li>Open <a href='/posture'>Posture</a> — read the verdict banner, then the "
        "panels top to bottom: latch, ledger, quorum, signing rules, recorded history.</li>"
        "<li>Open <a href='/incidents'>Incidents</a> — on a healthy wallet both lists are "
        "empty, and the page says why that is the good state.</li>"
        "<li>Open <a href='/queue'>Queue</a> — empty unless a signature is waiting for "
        "the offline device.</li>"
        "<li>Open <a href='/inspect'>Inspect</a> — paste the sample artifacts from "
        "<code>examples/wallet-evidence/</code> and watch the deployed verifier run.</li>"
        "<li>Open the <a href='/estate'>Estate map</a> — where this wallet sits in the "
        "wider verified-crypto estate, and what is actually running where.</li>"
        "<li>Then take the <a href='/station/newcomer'>Newcomer station</a> — your "
        "first hour, mapped out.</li>"
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
        "<dt id='station'>station</dt>"
        "<dd>One human role's console on the Bridge: mission, duties as runnable "
        "commands, live instruments, the never-list (separation of duties), and "
        "handoffs. Six stations: Proposer, Quorum bench, Operator, Cryptographer, "
        "Architect, Newcomer.</dd>"
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
        "<li>Whether a live service is <em>honest</em> — the liveness board checks "
        "pulses, not truth; truth is the Cryptographer's replay work.</li>"
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

        def _station_embeds(self, station_id: str, probe: bool) -> list[str]:
            wallet = self._wallet()
            if station_id == "proposer":
                return [render_queue(collect_airgap(wallet))]
            if station_id == "quorum":
                posture = collect("Wallet.posture()", wallet.posture)
                return ([_panel_quorum(posture["data"])] if posture["ok"] else
                        [_failed_panel("Quorum bench roster", posture["via"],
                                       posture["error"])])
            if station_id == "operator":
                live = render_liveness(collect_liveness() if probe else None)
                posture = collect("Wallet.posture()", wallet.posture)
                if posture["ok"]:
                    p = posture["data"]
                    return [live, _panel_latch(p), _panel_history(p)]
                return [live, _failed_panel("Custody posture", posture["via"],
                                            posture["error"])]
            if station_id == "cryptographer":
                return [render_inspect(None)]
            if station_id == "architect":
                return [_render_drift_panel()]
            return []

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            parsed = urllib.parse.urlparse(self.path)
            route = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            pane = query.get("pane", ["0"])[0] == "1"
            wd = str(wallet_dir)

            def page(title: str, active: str, body: str, status: int = 200) -> None:
                self._send(_pane_shell(title, body) if pane
                           else _page(title, active, body, wd), status)

            if route == "/":
                wallet = self._wallet()
                posture = collect("Wallet.posture()", wallet.posture)
                airgap = collect_airgap(wallet)
                body = render_bridge(_bridge_strip(posture, airgap),
                                     _bridge_live(posture, airgap))
                page("bridge", "/", body)
            elif route == "/deck":
                self._send(render_deck(wd))
            elif route == "/posture":
                wallet = self._wallet()
                body = render_posture(collect("Wallet.posture()", wallet.posture))
                page("posture", "/posture", body)
            elif route == "/queue":
                page("signature queue", "/queue",
                     render_queue(collect_airgap(self._wallet())))
            elif route == "/incidents":
                wallet = self._wallet()
                page("incidents", "/incidents",
                     render_incidents(collect_incidents(wallet),
                                      collect_refusals(wallet)))
            elif route == "/inspect":
                defaults, note = (None, "")
                if query.get("sample", ["0"])[0] == "1":
                    defaults, note = _load_sample_evidence()
                page("receipt inspector", "/inspect",
                     note + render_inspect(None, defaults))
            elif route == "/guide":
                page("guide", "/guide", render_guide())
            elif route == "/manual":
                page("lab manual", "/manual", render_manual())
            elif route == "/estate":
                from .estateview import ESTATE_HTML
                self._send(ESTATE_HTML + _ESTATE_BACK_CHIP)
            elif route.startswith("/station/"):
                station_id = route.removeprefix("/station/")
                station = STATION_BY_ID.get(station_id)
                if station is None:
                    page("not found", "",
                         "<div class='panel bad'>No such station. The STATIONS "
                         "row above lists the whole crew.</div>", 404)
                    return
                probe = query.get("probe", ["0"])[0] == "1"
                body = render_station(station,
                                      self._station_embeds(station_id, probe))
                page(f"{station['name']} station", route, body)
            else:
                page("not found", "",
                     "<div class='panel bad'>No such view. The tabs above list "
                     "everything this cockpit can show.</div>", 404)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            route = parsed.path
            pane = urllib.parse.parse_qs(parsed.query).get("pane", ["0"])[0] == "1"
            if route != "/inspect":
                self._send("<div class='panel bad'>No such action.</div>", 404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            fields = {k: form.get(k, [""])[0] for k in ("attestation", "receipt", "pubkey")}
            result = inspect_receipt(fields["attestation"], fields["receipt"], fields["pubkey"])
            body = render_inspect(result, fields)
            self._send(_pane_shell("receipt inspector", body) if pane
                       else _page("receipt inspector", "/inspect", body,
                                  str(wallet_dir)))

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            return

    return CockpitHandler


def serve(wallet_dir: str | Path, host: str = "127.0.0.1", port: int = 8471) -> ThreadingHTTPServer:
    wallet_dir = Path(wallet_dir).resolve()
    Wallet(wallet_dir).capsule()  # fail fast if this is not a wallet
    server = ThreadingHTTPServer((host, port), make_handler(wallet_dir))
    return server
