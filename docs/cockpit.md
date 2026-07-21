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
| **Guide** (`/guide`) | *What does any of this mean?* The manual: plain-language explanations, color code, tour, full glossary, honest limits — static, no live data | — |

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
