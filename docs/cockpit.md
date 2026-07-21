# The custody cockpit — a bridge for the human crew

`pacta wallet cockpit --wallet <dir>` serves a local web UI
(default `http://127.0.0.1:8471`) over an existing warden wallet.
warden has always been agent-native (MCP) and CLI-native; the cockpit is
the third surface — for the humans who ultimately answer for the money.

It is organized as a **bridge with six role stations** over shared
evidence instruments, in the control-room tradition (overview → station
→ instrument → raw files/CLI): the cockpit provides everything a human
crew would need to run this estate **if no AI were around**.

## The design law

**The cockpit renders evidence; it never asserts it.** Every panel is
recomputed at request time by the same functions the wallet itself uses
(`Wallet.posture()`, `Wallet.verify_ledger()`, directory listings,
`transparency.verify_receipt`), and every panel carries a provenance
line naming the function and the timestamp. Anything that cannot be
recomputed renders as a loud red FAILED-TO-VERIFY panel. There is no
cached green and no neutral gray — a cockpit that shows unverified green
lights would be the anti-warden.

## The UX law (the design law's twin)

**The cockpit never leaves a human in the dark.** A person who has never
heard of warden must be able to read every screen. Concretely, every
page is built from the same anatomy, top to bottom:

1. **Verdict in words** — e.g. CUSTODY HEALTHY / CUSTODY FROZEN
   (LATCHED) / CUSTODY EVIDENCE BROKEN — before any evidence, with one
   sentence saying what that means and what to do.
2. **A plain-language lead** stating what the page shows and what it
   cannot do.
3. **Panels that explain themselves**: each opens with a plain sentence,
   carries a "How to read this panel" expander interpreting every column
   and every pill, and links each jargon term to the glossary via a
   small `?`.
4. **Explained empty states** — an empty list says what empty means and
   whether it is good news (for incidents, it is).
5. **The provenance line** — the dashed footer naming the exact function
   and timestamp that recomputed the panel.

The `/guide` view is the manual: what warden is, the crew model, how to
read any page, the color code, a five-minute tour, a glossary of every
term (capsule, member, pinning, evidence grades R0–R5, ledger, latch,
incident, refusal receipt, air-gap, attestation/receipt, provenance,
station, DEMO), and an honest "what this cockpit cannot tell you"
section. Navigation tabs state the question each view answers. This
contract is enforced by tests (`test_guide_view_explains_every_term`,
`test_every_view_carries_lead_nav_and_explainers`,
`test_empty_states_are_explained`).

## The crew law (roles, not a blur)

**The crew is a team of distinct roles.** Running the estate takes six
roles; in production one financial agent can play every one of them —
but the roles stay separate, cooperate through explicit handoffs, and
never melt into each other. Separation of duties is a custody control:
the one who proposes never approves, the one who verifies never
proposes, the one who watches never overrides the bench.

The **Bridge** (`/`) is the Level-1 overview: the whole-system verdict
strip (custody verdict in words + quorum/ledger/incident/queue chips),
the six crew cards with live data, and the dispatch (andon) board — "if
this happens, who acts". Each **station** (`/station/<id>`) is one
role's console with a fixed anatomy: *Mission* → *Duties* (every duty a
runnable command — the no-AI drill) → live embedded instruments →
*"This station never…"* (the separation-of-duties list) → *Handoffs*
(receives ← / delivers →).

| station | question | live instruments on the console |
|---|---|---|
| **Proposer** (`/station/proposer`) | I need something signed — how do I ask, and what do I do with the answer? | the Queue |
| **Quorum bench** (`/station/quorum`) | Would I stake custody on this evidence? Four seats, one answer each. | the live bench roster (capsule members) |
| **Operator** (`/station/operator`) | Is everything that should be running, running — and is custody unfrozen? | the **liveness board** (on-demand probes of every public service + every local repo), latch, recorded history |
| **Cryptographer** (`/station/cryptographer`) | Does the evidence really prove what it claims — no more, no less? | the Inspect verifier |
| **Architect** (`/station/architect`) | Does the map still match the territory? | the live **drift tripwire** (ESTATE.md vs estate view) |
| **Newcomer** (`/station/newcomer`) | What is all this? Where do I start? | the first-hour checklist |

The liveness board probes **only when the operator presses «Probe
now»** — the cockpit never phones home on an ordinary page load. Probes
are read-only observations (HTTP GET on the public services, `git
rev-parse`/`status` on local checkouts) and report observed facts with
latency; liveness is pulses, not honesty — honesty is the
Cryptographer's replay.

The crew law is test-enforced: `test_bridge_shows_crew_and_dispatch`,
`test_every_station_defines_role_contract` (mission/duties/commands/
never-list/handoffs on all six), `test_stations_are_distinct_roles`
(each role's signature phrase appears on its own station and on no
other — no melting), `test_operator_probe_is_explicit_and_live`.

## The deck (`/deck`) — all roles live, in parallel, with the wizard

The **deck** is the crew law made physical: a tmux-style grid of six
panes, one per role, all live at the same time — because a real crew
works in parallel, roles do not take turns existing. Each pane is an
independent viewport (an iframe onto that role's station in
chrome-stripped **pane mode**, `?pane=1`): it scrolls, reloads (⟳), and
zooms (⤢, tmux-style single-pane zoom) independently, and a tiny shim
keeps every link and form inside the pane (`pane=1` is re-carried), so
pressing «Probe now» in the operator pane runs the probe *in that pane*.
Pane mode strips the page chrome but keeps the READ-ONLY label and the
full station content — one source of truth, two shells.

On the right rides the **wizard**: a ten-step guided first watch that
takes a newcomer by the hand through every role's real actions on the
live demo wallet — probe as the operator, read the queue and a refusal
as the proposer, find the dissenting seat as the bench, verify (and then
deliberately break) real sample evidence as the cryptographer
(`/inspect?sample=1` pre-fills `examples/wallet-evidence/`), check the
drift tripwire as the architect, then run the handoff lap. Each step
card is **camouflaged in the color of the role being lived** ("YOU ARE
THE OPERATOR"), and the matching pane **glows** — instruction and
instrument are bound by hue. Every step states what success looks like
and what was just learned. Step position is remembered per browser
session.

Deck contract tests: `test_deck_serves_all_panes_and_wizard` (six live
panes + all six roles visited by the wizard + success criteria),
`test_pane_mode_is_chromeless_but_labeled` (no chrome, READ-ONLY label,
stay-in-pane shim), `test_inspect_sample_prefill`; the read-only byte
sweep covers `/deck` and pane routes.

## The read-only guarantee

The cockpit cannot approve, sign, unlatch, or modify custody state. It
calls only read paths; the one POST route (the receipt inspector) parses
submitted artifacts in memory and throwaway temp files, never near the
wallet directory. `tests/test_walletui.py` asserts this at the byte
level: a full request sweep, POST included, leaves every file in the
wallet directory hash-identical. Human approve/deny is deliberately NOT
here — that would be a custody-semantics change, which belongs to a
separate, explicitly reviewed milestone.

## The instruments (shared evidence views)

| view | answers | recomputed by |
|---|---|---|
| **Posture** (`/posture`) | *Is custody healthy right now?* Verdict banner, then: custody latch, ledger with full hash-chain re-verification, the pinned quorum members (backend, component, evidence grade, source commit, binary fingerprint), signing rules verbatim, incident/refusal counts | `Wallet.posture()` / `Wallet.verify_ledger()` |
| **Queue** (`/queue`) | *What awaits the offline signer?* Parked air-gap signing requests (outbox) and whether the device has answered (inbox) — observed, never operated | airgap outbox/inbox listing |
| **Incidents** (`/incidents`) | *What has ever gone wrong?* Incident records and signed refusal receipts, verbatim, newest first — with the page explaining why empty is the good state | `incidents/*.json`, `receipts/*.json` |
| **Inspect** (`/inspect`) | *Can I check a receipt myself?* Paste an attestation + transparency receipt + log public key; the verdict, per-signature results, and diagnostics come verbatim from the deployed verifier | `pacta.transparency.verify_receipt` |
| **Estate map** (`/estate`) | *Where does this wallet sit in the whole endeavour?* Every repo, service, mirror, loop — with RUNTIME on every entity (always-on / on-demand / not-running / static) | rendering of ESTATE.md's model (drift-guarded by test) |
| **Guide** (`/guide`) | *What does any of this mean?* The reference: plain-language explanations, color code, tour, full glossary, honest limits — static, no live data | — |
| **Lab manual** (`/manual`) | *Teach me every role.* The full study-club course ([docs/warden-lab-manual.md](warden-lab-manual.md), canonical Markdown rendered live): eight sessions + capstone, one chair per role — labs with checkpoints, a safe tamper drill, self-tests with answers, graduation path to a real wallet. Built for two monitors: manual on one, deck on the other. | `mdlite` over the committed file |

Every panel also states what it does **not** prove (e.g. the quorum
table says binary hashes are pinned but source-to-binary correspondence
is out of scope until reproducible builds).

## Serving

```bash
pacta wallet cockpit --demo                        # no wallet yet? throwaway
                                                   # DEMO wallet, custody-inert
pacta wallet cockpit --wallet ~/my-wallet          # 127.0.0.1:8471
pacta wallet cockpit --wallet ~/my-wallet --port 9000
```

(Uninstalled, from the repo root:
`PYTHONPATH=src:provider/src python3 -m pacta wallet cockpit --demo`.)

The server binds localhost by default and is not meant to be exposed;
there is no authentication because there is nothing to operate.
