"""deck - the ops deck: every role station live in one tmux-style grid,
with the guided wizard rail.

The deck is the crew law made physical: six panes, one per role, all
live at the same time - because in real life the roles act in parallel,
they do not take turns existing. Each pane is an independent viewport
(iframe) onto that role's station in chrome-stripped "pane mode"; panes
reload and zoom independently, tmux-style.

On the right rides the WIZARD: a guided first watch that takes a
newcomer by the hand through every role's real actions on the live DEMO
wallet. Each step card is camouflaged in the color of the role being
lived, and the matching pane glows - instruction and instrument are
bound by hue, so the learner always knows where to act.

Pure presentation: this module renders strings from the station model;
all live evidence stays inside the panes, which are ordinary cockpit
routes and therefore inherit the read-only guarantee wholesale. The
~60 lines of vanilla JS here do layout only (zoom, reload, step
navigation, glow) - they never touch wallet data.
"""
from __future__ import annotations

from .stations import STATIONS
from .uikit import STYLE, esc

_DECK_EXTRA_STYLE = """
 body.deckbody{max-width:none;margin:0;padding:0;height:100vh;display:flex;
      flex-direction:column;overflow:hidden}
 .deckbar{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap;
      padding:.45rem .9rem;background:#1c2430;color:#e8ecf2;font-size:.82rem}
 .deckbar a{color:#aebcf0;text-decoration:none}
 .deckbar .mono{opacity:.75}
 .deckgrid{flex:1;display:grid;grid-template-columns:minmax(0,1fr) 21.5rem;
      min-height:0}
 .deckmain{display:grid;grid-template-columns:1fr 1fr;grid-auto-rows:1fr;
      gap:6px;padding:6px;min-height:0;overflow:auto}
 @media(min-width:1500px){.deckmain{grid-template-columns:1fr 1fr 1fr}}
 .pane{display:flex;flex-direction:column;border:1px solid var(--line);
      border-left:4px solid var(--role);border-radius:6px;background:#fff;
      min-height:13rem;min-width:0}
 .pane header{display:flex;align-items:center;gap:.45rem;padding:.22rem .5rem;
      font-size:.78rem;background:var(--roletint);border-radius:0 5px 0 0}
 .pane header .q{color:var(--ink2);font-size:.7rem;font-style:italic;
      overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
 .pane header .monogram{min-width:1.5rem;height:1.5rem;line-height:1.5rem;
      font-size:.68rem}
 .paneacts{display:flex;gap:.25rem}
 .paneacts button,.paneacts a{border:1px solid var(--line);background:#fff;
      color:var(--ink);border-radius:4px;font-size:.72rem;line-height:1.25;
      padding:.05rem .4rem;cursor:pointer;text-decoration:none}
 .pane iframe{flex:1;border:0;width:100%;min-height:0;border-radius:0 0 5px 5px}
 .pane.focus{outline:3px solid var(--role);outline-offset:-1px}
 .deckmain.zoom .pane{display:none}
 .deckmain.zoom .pane.zoomed{display:flex;grid-column:1/-1;grid-row:1/-1}
 .wizard{border-left:1px solid var(--line);background:#fff;overflow-y:auto;
      padding:.8rem .9rem;min-height:0}
 .wizard h2{margin:.1rem 0 .3rem;font-size:1rem}
 .wizlegend{display:flex;gap:.3rem;flex-wrap:wrap;margin:.4rem 0 .7rem}
 .wizlegend span{font-size:.66rem;font-weight:700;border-radius:5px;
      padding:.1rem .4rem;background:var(--roletint);color:var(--role)}
 .wizstep{display:none;border-left:4px solid var(--role);
      background:var(--roletint);border-radius:6px;padding:.65rem .8rem;
      font-size:.86rem}
 .wizstep.on{display:block}
 .wizstep .rolechip{display:inline-block;font-weight:800;font-size:.7rem;
      letter-spacing:.04em;color:var(--role);margin-bottom:.25rem}
 .wizstep h3{margin:.1rem 0 .35rem;font-size:.92rem}
 .wizstep .succ{margin:.45rem 0 0;font-size:.8rem}
 .wizstep .succ b{color:var(--ok)}
 .wizstep .learn{margin:.35rem 0 0;font-size:.8rem;color:var(--ink2);
      font-style:italic}
 .wizctl{display:flex;align-items:center;gap:.6rem;margin:.7rem 0 0}
 .wizctl button{padding:.35rem .8rem;font-size:.84rem}
 .wizctl button:disabled{opacity:.4;cursor:default}
 #wizprog{font-size:.78rem;color:var(--ink2)}
 @media(max-width:999px){
   body.deckbody{overflow:auto;height:auto}
   .deckgrid{display:flex;flex-direction:column-reverse}
   .deckmain{grid-template-columns:1fr}
   .pane{min-height:22rem}
   .wizard{border-left:0;border-bottom:2px solid var(--line)}
 }
"""

# The guided first watch. Each step: (role_id, title, do_html, success_html,
# learn_html). The step card wears the role's colors; the matching pane glows.
WIZARD_STEPS: list[tuple[str, str, str, str, str]] = [
    ("newcomer", "Welcome to the deck",
     "Six panes, six roles, all live at the same time — a real crew works in "
     "parallel, and so does this deck. The colors ARE the roles; this wizard "
     "wears the color of whoever you are acting as, and that role's pane "
     "glows. Nothing you do here can sign or change anything — every pane is "
     "read-only evidence.",
     "You can point at each pane and say what its role is for (the italic "
     "line in each pane header helps).",
     "One system, six distinct jobs — never one blurred job."),
    ("operator", "Morning watch: probe everything",
     "Act as the <strong>Operator</strong> (green pane): press "
     "<strong>«Probe now»</strong> on the liveness board. Watch the rows fill "
     "with live facts. Find the <code>log head</code> row and read its "
     "<code>tree_size</code> — that number is the public transparency log "
     "answering you, right now.",
     "Every service row says <b>alive</b> with observed facts and latency; "
     "the repo rows show HEAD commits.",
     "Liveness is checked on demand, never assumed — and never silently in "
     "the background."),
    ("operator", "Read the wallet's own pulse",
     "Still in green: scroll to <strong>Custody latch</strong> — it says "
     "<em>unlatched</em>, and the panel explains what the latch would do. "
     "Then <strong>Recorded history</strong>: this demo wallet carries "
     "<em>1 incident</em> and <em>1 refusal receipt</em> on file. You will "
     "meet both in the next steps.",
     "You found the latch state and the two counters without leaving the "
     "green pane.",
     "The operator reads state from evidence panels, not from memory."),
    ("proposer", "Live the proposer: find your request",
     "Switch hats — <strong>amber pane</strong>. One signing request sits in "
     "the queue, <em>awaiting device</em>. Read its <strong>payload "
     "fingerprint</strong>: that is the SHA-256 of the exact bytes the "
     "offline signer would sign — and nothing else.",
     "You can quote the first characters of the fingerprint of what would be "
     "signed.",
     "A proposal is precise, or it is nothing."),
    ("proposer", "Read a refusal like a to-do list",
     "Still amber: open <strong>Incidents (refusals)</strong> from the "
     "station's instrument links. The demo refusal says "
     "<code>POLICY_DENIED</code>, missing <em>allowlisted destination</em>, "
     "with a <code>remediation</code> naming exactly what would make the "
     "same request succeed.",
     "You can say, in one sentence, what the proposer would fix before "
     "retrying.",
     "warden never says a bare «no» — every refusal is machine-readable "
     "instructions."),
    ("quorum", "Sit on the bench: find the dissenter",
     "Now the <strong>indigo pane</strong>. Count the seats: four, each "
     "built from a different verified codebase. The demo incident (you saw "
     "its counter in step 3) records that <code>risc0</code> answered "
     "INVALID while the other three said OK — in a real wallet, that single "
     "dissent freezes custody on the spot.",
     "You found all four seats and can name the dissenting member.",
     "One honest dissenter beats three comfortable agreements — that is the "
     "whole bench."),
    ("cryptographer", "Recompute — never trust",
     "The <strong>purple pane</strong>: click <strong>«load the sample "
     "evidence»</strong>, then <strong>Verify (read-only)</strong>. The "
     "deployed verifier re-checks the signatures and the log inclusion in "
     "front of you. Then delete one character from the receipt box and "
     "verify again — watch it refuse, loudly.",
     "First run: <b>ACCEPTED</b> with a diagnostics list. Broken run: "
     "REJECTED, and the diagnostics name the exact failing check.",
     "You never trusted this page — you recomputed it. That is the "
     "cryptographer's entire posture."),
    ("architect", "Zoom out: map versus territory",
     "The <strong>slate pane</strong>: read the <strong>drift "
     "tripwire</strong> — it just compared the two renderings of the estate "
     "map, name by name, and they agree. Then open the <strong>Estate "
     "map</strong> link and find this wallet's place among the repos, "
     "services, and the two self-referential loops.",
     "You can say where warden sits on the map, and what the tripwire would "
     "catch.",
     "The map is recomputed, never remembered — or it lies."),
    ("operator", "The handoff lap — the team in one incident",
     "Watch the whole crew move once, in your head, across the panes: the "
     "<em>proposer</em> escalates a refusal → the <em>operator</em> "
     "investigates and probes → the <em>bench</em> defends its dissent → "
     "the <em>cryptographer</em> re-verifies the evidence → the "
     "<em>architect</em> records what changed. Five roles touched one "
     "incident — and not one of them did another's job.",
     "You can retell the lap naming who hands what to whom.",
     "Teamwork here is handoffs between distinct roles — never a blur."),
    ("newcomer", "Graduation",
     "Pick the station that felt most like you and open it full-size (the "
     "↗ in its pane header). Read its Mission, its Duties — every one a "
     "real command — and its «This station never…» list; the never-list is "
     "the fastest way to understand a role. When you are ready for a real "
     "wallet: <code>pacta wallet init</code>.",
     "You have a station — and you know what it never does.",
     "If any page confused you on this watch, that is a bug in the page, "
     "not in you. Report it — that is the newcomer's superpower."),
]


def render_deck(wallet_dir: str) -> str:
    """The full deck document: bar, pane grid, wizard rail, layout JS."""
    demo_badge = (' <span class="pill warn">DEMO WALLET — custody-inert</span>'
                  if "DEMO" in wallet_dir else "")
    panes = "".join(
        f'<section class="pane" data-role="{s["id"]}" '
        f'style="--role:{s["hue"]};--roletint:{s["tint"]}">'
        f'<header><span class="monogram">{s["monogram"]}</span>'
        f'<strong>{esc(s["name"])}</strong>'
        f'<span class="q">{esc(s["question"])}</span>'
        f'<span class="paneacts">'
        f'<button data-act="reload" title="reload this pane">⟳</button>'
        f'<button data-act="zoom" title="zoom this pane (tmux-style)">⤢</button>'
        f'<a href="/station/{s["id"]}" target="_top" title="open full page">↗</a>'
        f'</span></header>'
        f'<iframe src="/station/{s["id"]}?pane=1" loading="lazy" '
        f'title="{esc(s["name"])} station"></iframe>'
        f'</section>'
        for s in STATIONS)
    legend = "".join(
        f'<span style="--role:{s["hue"]};--roletint:{s["tint"]}">'
        f'{s["monogram"]} {esc(s["name"])}</span>'
        for s in STATIONS)
    role_by_id = {s["id"]: s for s in STATIONS}
    steps = "".join(
        f'<div class="wizstep" data-role="{role_id}" '
        f'style="--role:{role_by_id[role_id]["hue"]};'
        f'--roletint:{role_by_id[role_id]["tint"]}">'
        f'<span class="rolechip">{role_by_id[role_id]["monogram"]} · YOU ARE THE '
        f'{esc(role_by_id[role_id]["name"]).upper()}</span>'
        f'<h3>{title}</h3>'
        f'<div>{do}</div>'
        f'<p class="succ"><b>Success looks like:</b> {success}</p>'
        f'<p class="learn">{learn}</p>'
        f'</div>'
        for role_id, title, do, success, learn in WIZARD_STEPS)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>warden deck — all stations live</title>"
        f"<style>{STYLE}{_DECK_EXTRA_STYLE}</style></head>"
        "<body class='deckbody'>"
        "<div class='deckbar'><strong>warden deck</strong>"
        "<span>six stations, live in parallel</span>"
        "<a href='/'>← Bridge</a>"
        "<span class='pill warn'>READ-ONLY</span>"
        f"{demo_badge}"
        f"<span class='mono'>{esc(wallet_dir)}</span></div>"
        "<div class='deckgrid'>"
        f"<div class='deckmain'>{panes}</div>"
        "<aside class='wizard'>"
        "<h2>The wizard — your first watch</h2>"
        "<p class='plain' style='font-size:.8rem'>A guided lap through every "
        "role's real actions, on this live demo wallet. Each step wears the "
        "color of the role you are living, and that pane glows.</p>"
        f"<div class='wizlegend'>{legend}</div>"
        f"{steps}"
        "<div class='wizctl'>"
        "<button id='wizprev'>← Back</button>"
        "<button id='wiznext'>Next →</button>"
        "<span id='wizprog'></span></div>"
        "<p class='muted' style='margin-top:.8rem;font-size:.74rem'>Pane "
        "controls, tmux-style: ⟳ reload · ⤢ zoom one pane · ↗ open the full "
        "station page. Your step is remembered for this browser session.</p>"
        "</aside></div>"
        "<script>"
        "(function(){"
        "var panes=[].slice.call(document.querySelectorAll('.pane'));"
        "var main=document.querySelector('.deckmain');"
        "[].forEach.call(document.querySelectorAll('[data-act=reload]'),function(b){"
        "b.onclick=function(){var f=b.closest('.pane').querySelector('iframe');"
        "f.src=f.src;};});"
        "[].forEach.call(document.querySelectorAll('[data-act=zoom]'),function(b){"
        "b.onclick=function(){var p=b.closest('.pane');"
        "var was=p.classList.contains('zoomed');"
        "panes.forEach(function(x){x.classList.remove('zoomed');});"
        "main.classList.toggle('zoom',!was);"
        "if(!was){p.classList.add('zoomed');}};});"
        "var steps=[].slice.call(document.querySelectorAll('.wizstep'));"
        "var prev=document.getElementById('wizprev');"
        "var next=document.getElementById('wiznext');"
        "var prog=document.getElementById('wizprog');"
        "var i=parseInt(sessionStorage.getItem('warden-wiz')||'0',10)||0;"
        "function show(n){i=Math.max(0,Math.min(steps.length-1,n));"
        "sessionStorage.setItem('warden-wiz',String(i));"
        "steps.forEach(function(s,k){s.classList.toggle('on',k===i);});"
        "prog.textContent=(i+1)+' / '+steps.length;"
        "var role=steps[i].getAttribute('data-role');"
        "panes.forEach(function(p){"
        "p.classList.toggle('focus',p.getAttribute('data-role')===role);});"
        "prev.disabled=(i===0);"
        "next.textContent=(i===steps.length-1)?'Start over':'Next →';}"
        "prev.onclick=function(){show(i-1);};"
        "next.onclick=function(){show(i===steps.length-1?0:i+1);};"
        "show(i);"
        "})();"
        "</script></body></html>"
    )
