"""stations - the role model of the warden bridge.

The cockpit's third law (after the design law and the UX law): THE CREW
IS A TEAM OF DISTINCT ROLES, NOT A BLUR. If no AI were around, running
this estate would take a crew: a proposer, a quorum bench, an operator,
a cryptographer, an architect, and a newcomer finding their feet. In
production one financial agent can play every role - but the roles stay
separate, hand work to each other through explicit interfaces, and never
melt into one another. Separation of duties is a custody control, not a
metaphor: the one who proposes never approves, the one who verifies
never proposes, the one who watches never overrides the bench.

Design lineage, deliberately borrowed:
- control-room HMI hierarchy (overview -> station -> instrument -> raw
  detail; color reserved for state that needs attention),
- mission-control discipline consoles (one role, one console, explicit
  handoffs on the loop),
- banking's maker-checker (four-eyes) separation of duties,
- checklist culture: every duty is a runnable command, not advice.

This module is pure presentation over passed-in data: no wallet imports,
no I/O. Live evidence panels are built by walletui and handed in as
`embeds`, so the read-only guarantee and the provenance discipline stay
in one place.
"""
from __future__ import annotations

from typing import Any

from .uikit import cmd_block, esc, explain

# ---------------------------------------------------------------------------
# the crew
# ---------------------------------------------------------------------------

STATIONS: list[dict[str, Any]] = [
    {
        "id": "proposer", "name": "Proposer", "monogram": "PR",
        "hue": "#a86a10", "tint": "#fdf0da",
        "question": "I need something signed — how do I ask, and what do I do with the answer?",
        "card": "Originates signing requests; consumes signatures and refusal receipts.",
        "lead": ("You are at the <strong>Proposer</strong> station. You originate signing "
                 "requests and you live with the answers — a signature or a written "
                 "refusal. You never approve anything yourself; that separation is what "
                 "makes your requests trustworthy."),
        "mission": ("Turn an intent (\"pay this\", \"sign that\") into a precise, "
                    "fingerprinted request; submit it through the wallet's front door; "
                    "read every refusal receipt as instructions, not rejection."),
        "duties": [
            ("Form the request precisely",
             "Know the exact bytes you want signed and compute their fingerprint — the "
             "device will sign those bytes and nothing else, and every later dispute is "
             "settled by this hash.",
             "sha256sum payload.bin"),
            ("Submit through the wallet's front door",
             "The proposal interface is agent-native: the <code>request_signature</code> "
             "tool on the wallet's MCP surface. A human drives the same surface over "
             "stdio (the JSON-RPC lines are in WALLET.md).",
             "pacta wallet mcp --wallet WALLET_DIR\n# then call the request_signature tool"),
            ("Track your request",
             "Your request appears in the Queue instrument (embedded below) as "
             "«awaiting device» until the offline signer answers.",
             None),
            ("On refusal: read the receipt, fix, retry",
             "A refusal receipt names the rule (<code>code</code>), what was missing, and "
             "the <code>remediation</code>. It is a to-do list, not a verdict on you.",
             None),
            ("On success: verify what you got",
             "Never forward a signature you have not checked. For a Solana transaction, "
             "the quorum re-verifies every signature locally:",
             "pacta wallet treasury-verify --wallet WALLET_DIR --tx-file tx.bin"),
        ],
        "never": [
            "Approve or verify the evidence behind your own proposal — that is the "
            "Quorum bench's seat, and the whole point is that it is not yours.",
            "Touch the air-gap device or its outbox/inbox files — the Operator owns "
            "that walk.",
            "Clear a latch, or edit <code>policy.json</code> to make your own request "
            "fit — policy changes are the Operator's deliberate, recorded act.",
        ],
        "receives": ["a signature, or a refusal receipt — from the wallet",
                     "custody posture answers — from the Operator"],
        "delivers": ["fingerprinted signing requests — to the signing firewall",
                     "escalations after repeated refusals — to the Operator"],
        "instruments": [("/queue", "Queue"), ("/incidents", "Incidents (refusals)")],
    },
    {
        "id": "quorum", "name": "Quorum bench", "monogram": "QM",
        "hue": "#3b4d8f", "tint": "#eef0f7",
        "question": "Would I stake custody on this evidence? Four seats, one answer each.",
        "card": "Four independent verifier seats; unanimity admits, one dissent latches.",
        "lead": ("You are at the <strong>Quorum bench</strong> — four seats, one per "
                 "independently built verifier (dalek, anza, risc0, betrusted). Each seat "
                 "answers for itself. The bench never averages: unanimity admits a "
                 "component, a single dissent freezes custody. Your value is your "
                 "independence."),
        "mission": ("Hold an independent verdict on every piece of cryptographic "
                    "evidence the wallet is asked to trust. Your seat's judgment must "
                    "come from your seat's binary, built from your seat's verified "
                    "sources — nobody else's."),
        "duties": [
            ("Know your seat",
             "Which verified repository you are built from, at which commit, with which "
             "binary fingerprint — the live bench roster is embedded below.",
             None),
            ("Rebuild your member from pinned proven sources",
             "When sources or toolchains move, rebuild from the pinned fork checkouts "
             "and let the capsule re-pin your fingerprint:",
             "pacta wallet build-quorum --sources-root FORK_CHECKOUTS_DIR"),
            ("Guard your independence",
             "A shared toolchain is a shared bug. Do not copy another seat's build "
             "artifacts, caches, or patches — four seats that agree because they are "
             "secretly one seat protect nothing.",
             None),
            ("On divergence: your dissent worked",
             "If your seat says INVALID while others say OK, custody latches and an "
             "incident is written. That is the system succeeding, not you failing. Read "
             "the incident (embedded on the Incidents instrument) and defend your "
             "verdict to the Operator.",
             None),
        ],
        "never": [
            "Propose a request — the bench judges evidence, it never originates spends.",
            "Vote another seat's verdict, or harmonize before answering — the bench "
            "never averages; unanimity or latch.",
            "Clear a latch your own dissent caused — the Operator investigates; you are "
            "a witness, not the judge of your own alarm.",
        ],
        "receives": ["component evidence (attestations + receipts) — from the wallet's "
                     "inbound boundary",
                     "rebuilt source workspaces — from the Architect's pinned forks"],
        "delivers": ["a unanimous admit, or a latch-tripping dissent — to the wallet",
                     "divergence incidents — to the Operator"],
        "instruments": [("/posture", "Posture (bench roster)"), ("/incidents", "Incidents")],
    },
    {
        "id": "operator", "name": "Operator", "monogram": "OP",
        "hue": "#1e7f4f", "tint": "#e2f2e9",
        "question": "Is everything that should be running, running — and is custody unfrozen?",
        "card": "Watches liveness of every service and repo; owns latch recovery.",
        "lead": ("You are at the <strong>Operator</strong> station. You watch the "
                 "liveness of everything — every service, every repo, the wallet's own "
                 "health — and you own the emergency procedures. When the latch trips, "
                 "everyone else stops and you start."),
        "mission": ("Keep the estate observably alive: probe the public services, check "
                    "the local repos, re-verify the wallet daily, advance the log pin, "
                    "and run latch recovery by the book. You are the only station that "
                    "may clear a latch — deliberately, with a permanent written note."),
        "duties": [
            ("Daily watch",
             "Press «Probe now» on the liveness board below — it re-checks every "
             "service and repo live, on demand. Then re-verify the wallet from the "
             "command line:",
             "pacta wallet status --wallet WALLET_DIR\npacta wallet verify-ledger --wallet WALLET_DIR"),
            ("Advance the log pin",
             "Fetch the latest signed head of the transparency log, verify signature "
             "and consistency against your pinned size, and advance the pin — this is "
             "the split-view/rollback defense:",
             "pacta sth-refresh --url https://ltl.zkdefi.org \\\n  --sth-store sth-store.json --log-public-key log.pub"),
            ("Witness the published log",
             "Audit a full clone: recompute every prefix root, check every historical "
             "signed head. An unwatched log is safe only on paper — you are the watcher:",
             "pacta witness-audit --published-dir path/to/lean-transparency-log"),
            ("On latch: run the book",
             "Follow <code>docs/runbook-latch.md</code> step by step. Only when the "
             "cause is understood and fixed, clear the latch — the note is recorded "
             "permanently in the ledger:",
             'pacta wallet unlatch --wallet WALLET_DIR --note "root cause and fix"'),
        ],
        "never": [
            "Clear a latch without a written root cause — the CLI refuses an empty "
            "note, and the ledger keeps it forever.",
            "Rewrite log history: never force-push the log repo, never edit or delete "
            "under <code>entries/</code>, never re-sign a published head, never "
            "backdate. The log is append-only or it is nothing.",
            "Override the bench: if the quorum diverged, the answer is investigation, "
            "not a fifth vote.",
            "Sign or propose — you hold the brakes, not the pen.",
        ],
        "receives": ["incidents and latch events — from the wallet and the Quorum bench",
                     "escalations — from the Proposer"],
        "delivers": ["unlatch decisions with permanent notes — to the wallet ledger",
                     "outage and repair notes — to the Architect (map updates)"],
        "instruments": [("/posture", "Posture"), ("/incidents", "Incidents"),
                        ("/queue", "Queue")],
    },
    {
        "id": "cryptographer", "name": "Cryptographer", "monogram": "CR",
        "hue": "#6d4a8f", "tint": "#f0e8f7",
        "question": "Does the evidence really prove what it claims — no more, no less?",
        "card": "Re-verifies receipts, replays the log offline, guards claim boundaries.",
        "lead": ("You are at the <strong>Cryptographer</strong> station. You take "
                 "nothing on trust that you can recompute: receipts, inclusion proofs, "
                 "signed heads, the whole log. And you guard the boundary of every "
                 "claim — what is proven, and exactly where the proof stops."),
        "mission": ("Independently re-verify any evidence artifact anyone hands you, "
                    "replay the public log offline, and keep everyone honest about what "
                    "the mathematics does and does not cover."),
        "duties": [
            ("Verify a receipt end to end",
             "Use the Inspect instrument (embedded below) or the CLI with the hardened "
             "flags — pin store, freshness policy, verified-verifier requirement:",
             "pacta receipt-verify --attestation a.json --receipt r.json \\\n"
             "  --log-public-key log.pub --sth-store sth-store.json \\\n"
             "  --max-sth-age-seconds 604800 --require-verified-verifier"),
            ("Fetch fresh evidence yourself",
             "Never verify only what you were handed — fetch from the live log and "
             "verify locally:",
             "pacta log-fetch --url https://ltl.zkdefi.org --component dalek-ed25519-verified"),
            ("Replay the whole log offline",
             "In a clone of the published log repo: a fail-closed, standard-library "
             "verifier re-checks every leaf, every signed head, every receipt — with "
             "its adversarial self-test shipped beside it:",
             "python3 verify.py --all\npython3 verify_selftest.py"),
            ("Guard the claim boundary",
             "The evidence grades (R0–R5) are exact: R4 means machine-checked proofs on "
             "the documented boundary — SHA-512 opaque, reproducible builds out of "
             "scope (R5). A claim stretched past its boundary is a false claim. The "
             "grading tools are <code>pacta claims</code>, <code>pacta score</code>, "
             "<code>pacta report</code>.",
             None),
        ],
        "never": [
            "Accept a green light you did not recompute — including this cockpit's.",
            "Extend a claim beyond its stated boundary — «verified» never means more "
            "than the certificate says.",
            "Treat the log as a truth oracle — it is an accountability ledger: leaves "
            "can lie, and only independent replay catches a fabricated claim.",
        ],
        "receives": ["evidence artifacts to audit — from anyone",
                     "fresh attestations and receipts — from the live log"],
        "delivers": ["audit verdicts — to the Operator and the Proposer",
                     "claim-boundary corrections — to the Architect (docs and map)"],
        "instruments": [("/inspect", "Inspect"), ("/guide", "Guide (limits)")],
    },
    {
        "id": "architect", "name": "Architect", "monogram": "AR",
        "hue": "#2b5b78", "tint": "#e8eef2",
        "question": "Does the map still match the territory — every repo, service, loop?",
        "card": "Keeps the estate map true; watches the loops and the public boundary.",
        "lead": ("You are at the <strong>Architect</strong> station. The estate is many "
                 "repos, services, mirrors, and two self-referential loops — too much "
                 "for anyone's head, which is why the map exists. Your job is that the "
                 "map never lies: about what exists, what runs, and what is public."),
        "mission": ("Keep the estate map congruent with reality after every change, "
                    "keep its two renderings from drifting, watch the loops, and gate "
                    "what may be named in public."),
        "duties": [
            ("Walk the map after every landed change",
             "Open the Estate instrument and check the changed entity's card — "
             "runtime (always-on / on-demand / not-running / static), mutability, "
             "custody lane. The live drift tripwire is embedded below.",
             None),
            ("Keep the two renderings synced",
             "The map exists twice: <code>ESTATE.md</code> (canonical, committed) and "
             "the cockpit's estate view. A name-level tripwire test fails the suite if "
             "they drift — run it after map edits:",
             "python3 scripts/mini_pytest.py"),
            ("Watch the loops",
             "Loop 1: the dogfood signer is attested at leaf 8 of the very log it "
             "signs. Loop 2: entry 13 — the log carries the kernel-checked mechanization "
             "of its own accumulator's soundness. Both must stay tellable in one "
             "breath; if an explanation of a loop stops being crisp, the estate has "
             "drifted somewhere.",
             None),
            ("Gate the public boundary",
             "Public documents list only entities whose existence is already public or "
             "must be public for trust. Private infrastructure stays unnamed, "
             "everywhere, always.",
             None),
        ],
        "never": [
            "Name private infrastructure in a public artifact — not in maps, not in "
            "docs, not in commit messages.",
            "Let a generated file drift from its canonical source — when you fix a "
            "published file, find and fix its generator in the same change.",
            "Redraw the map from memory — the map is recomputed from the repos and "
            "services, never from recollection.",
        ],
        "receives": ["outage and repair notes — from the Operator",
                     "claim-boundary corrections — from the Cryptographer"],
        "delivers": ["the updated, drift-guarded map — to everyone "
                     "(ESTATE.md + the estate view)"],
        "instruments": [("/estate", "Estate map"), ("/guide", "Guide")],
    },
    {
        "id": "newcomer", "name": "Newcomer", "monogram": "NC",
        "hue": "#0f766e", "tint": "#e0f2f0",
        "question": "What is all this? Where do I even start?",
        "card": "Learns the system hands-on with the DEMO wallet; supplies fresh eyes.",
        "lead": ("You are at the <strong>Newcomer</strong> station — everyone's first "
                 "station, including the people now sitting at the other five. Your "
                 "first hour is mapped out below, and your confusion is valuable: it "
                 "finds the gaps the veterans stopped seeing."),
        "mission": ("Learn the system hands-on, with a wallet that cannot hurt "
                    "anything, until you can read the Bridge at a glance — then pick a "
                    "station and shadow it."),
        "duties": [
            ("Your first hour, step 1: run the demo",
             "A throwaway, custody-inert wallet with fake members — every view has "
             "content, nothing can sign anything real:",
             "pacta wallet cockpit --demo"),
            ("Step 2: read the Guide",
             "All of it — ten minutes. What warden is, how to read any page, the color "
             "code, and a glossary of every term you will meet.",
             None),
            ("Step 3: take the five-minute tour",
             "Posture → Incidents → Queue → Inspect → Estate, in that order, reading "
             "each page's verdict first.",
             None),
            ("Step 4: verify something real",
             "Paste the sample evidence from <code>examples/wallet-evidence/</code> "
             "into the Inspect instrument and watch the deployed verifier accept it — "
             "then break one character and watch it refuse.",
             None),
            ("Step 5: pick a station and shadow it",
             "Read that station's mission, duties, and its «never» list — the never "
             "list is the fastest way to understand a role.",
             None),
        ],
        "never": [
            "Pretend to understand — every other station once sat exactly here.",
            "Assume a confusing page is your fault: if a page confuses you, that is a "
            "bug in the page, not in you. Report it.",
        ],
        "receives": ["the Guide, the demo wallet, and patient answers — from every "
                     "station"],
        "delivers": ["fresh eyes: every page that confuses you, reported — to the "
                     "Architect and the Operator"],
        "instruments": [("/guide", "Guide"), ("/inspect", "Inspect"),
                        ("/estate", "Estate map")],
    },
]

STATION_BY_ID = {s["id"]: s for s in STATIONS}

# the andon board: event -> who acts, with what
DISPATCH: list[tuple[str, str, str]] = [
    ("A request was refused", "proposer",
     "read the refusal receipt: code → missing → remediation, then retry"),
    ("CUSTODY FROZEN, or a new incident", "operator",
     "runbook-latch, root cause, permanent unlatch note (plus the Quorum bench if it "
     "was a divergence)"),
    ("A new component wants to be trusted", "quorum",
     "evidence through the inbound boundary; unanimity admits, one dissent latches"),
    ("Someone handed you evidence", "cryptographer",
     "Inspect, or receipt-verify with the hardened flags — recompute, never trust"),
    ("A service or repo looks dead", "operator",
     "liveness board: Probe now"),
    ("The map feels wrong", "architect",
     "estate view + drift tripwire; fix the generator, not just the page"),
    ("“I don’t understand any of this”", "newcomer",
     "the Newcomer station is the entry point, not an insult"),
]


# ---------------------------------------------------------------------------
# renderers (pure)
# ---------------------------------------------------------------------------

def _role_vars(s: dict[str, Any]) -> str:
    return f"--role:{s['hue']};--roletint:{s['tint']}"


def render_bridge(strip_html: str, live: dict[str, str]) -> str:
    """The Level-1 overview: whole-system verdict, then the crew."""
    cards = "".join(
        f'<div class="stationcard" style="{_role_vars(s)}">'
        f'<div><span class="monogram">{s["monogram"]}</span> '
        f'<strong>{esc(s["name"])}</strong></div>'
        f'<div class="q">{esc(s["question"])}</div>'
        f'<div class="plain">{esc(s["card"])}</div>'
        f'{live.get(s["id"], "")}'
        f'<a class="take" href="/station/{s["id"]}">Take this station →</a></div>'
        for s in STATIONS)
    dispatch_rows = "".join(
        f'<tr><td>{event}</td>'
        f'<td><a href="/station/{sid}">{esc(STATION_BY_ID[sid]["name"])}</a></td>'
        f'<td>{action}</td></tr>'
        for event, sid, action in DISPATCH)
    return (
        strip_html
        + "<h2>The crew — who does what</h2>"
        "<p class='plain'>Running this estate without an AI takes six roles. Each "
        "station page states its mission, its duties as runnable commands, what it "
        "hands to whom — and what it never does. Roles cooperate through those "
        "handoffs; they do not blur into each other.</p>"
        f"<div class='crew'>{cards}</div>"
        "<h2>If this happens, who acts</h2>"
        "<div class='tablewrap'><table>"
        "<tr><th>event</th><th>station</th><th>first move</th></tr>"
        f"{dispatch_rows}</table></div>"
        + explain(
            "<ul><li>This bridge is the one-glance overview: the verdict strip on top "
            "is the whole system's state, recomputed on load.</li>"
            "<li>The crew cards are the six roles; «Take this station» opens that "
            "role's console with its duties and handoffs.</li>"
            "<li>The dispatch table is the andon board: when something happens, it "
            "names the station that acts first — nobody improvises ownership during an "
            "incident.</li>"
            "<li>The layout follows control-room practice: overview (this bridge) → "
            "station (a role's console) → instrument (shared evidence panels) → raw "
            "files and CLI. Deeper is always one click, never a guess.</li></ul>")
    )


def render_station(s: dict[str, Any], embeds: list[str]) -> str:
    """One role's console: mission, duties (with commands), live instruments,
    the never-list, and explicit handoffs."""
    duties = "".join(
        f'<div class="duty"><strong>{i}. {title}</strong>'
        f'<div class="why">{why}</div>'
        f'{cmd_block(command) if command else ""}</div>'
        for i, (title, why, command) in enumerate(s["duties"], start=1))
    nevers = "".join(f"<li>{item}</li>" for item in s["never"])
    receives = "".join(f"<li>{item}</li>" for item in s["receives"])
    delivers = "".join(f"<li>{item}</li>" for item in s["delivers"])
    instruments = " · ".join(
        f'<a href="{href}">{esc(label)}</a>' for href, label in s["instruments"])
    embedded = "".join(embeds)
    return (
        f'<div class="rolehead" style="{_role_vars(s)}">'
        f'<span class="monogram">{s["monogram"]}</span>'
        f'<div><h2>{esc(s["name"])} station</h2>'
        f'<div class="q">{esc(s["question"])}</div></div></div>'
        f'<div class="panel"><h3 style="margin-top:0">Mission</h3>'
        f'<p class="plain">{s["mission"]}</p>'
        f'<p class="muted">Instruments this station works with: {instruments}</p></div>'
        f'<div class="panel"><h3 style="margin-top:0">Duties — the no-AI drill</h3>'
        "<p class='plain'>Every duty is a runnable command or a concrete act — this is "
        "the work, not advice about the work.</p>"
        f'{duties}</div>'
        f'{embedded}'
        f'<div class="panel" style="border-left:4px solid var(--bad)">'
        f'<h3 style="margin-top:0">This station never…</h3>'
        "<p class='plain'>Separation of duties is the control that makes the team "
        "trustworthy — these lines are load-bearing, not etiquette.</p>"
        f'<ul class="never">{nevers}</ul></div>'
        f'<div class="panel"><h3 style="margin-top:0">Handoffs</h3>'
        f'<div class="hand">'
        f'<div class="hcol"><b>RECEIVES</b><ul class="diag">{receives}</ul></div>'
        f'<div class="hcol"><b>DELIVERS</b><ul class="diag">{delivers}</ul></div>'
        f'</div>'
        + explain(
            "<ul><li>Handoffs are the team's interfaces: what this station takes in, "
            "what it hands out, and to whom. Work moves between stations only through "
            "these — that is how distinct roles cooperate without merging.</li>"
            "<li>If you are alone (or you are the AI), you may hold several stations — "
            "but you switch between them explicitly, one at a time, and the handoffs "
            "still apply to yourself.</li></ul>")
        + "</div>"
    )
