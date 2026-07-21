# The warden lab manual — one person, six roles

*A study-club course in verified custody. You will not read about the roles —
you will sit in each chair, do each job with your own hands on a live (and
harmless) wallet, and only leave a chair when you can say what that role
does, why it exists, and what it must never do.*

---

## How to use this manual

**Two monitors.** Put this manual on one screen. On the other, start the
cockpit and keep it open for the whole course:

```
cd proof-aware-crypto-tooling-agent
PYTHONPATH=src:provider/src python3 -m pacta wallet cockpit --demo
```

The command prints two things you need:

1. the **demo wallet path** (something like `/tmp/warden-DEMO-xxxxxxxx/wallet`), and
2. the address `http://127.0.0.1:8471` with its `/deck` and `/guide` pointers.

Open **http://127.0.0.1:8471/deck** on the second monitor. For the terminal
exercises, open a *second* terminal in the same repo directory and set up two
things once (the server keeps running in the first terminal):

```
alias pacta='PYTHONPATH=src:provider/src python3 -m pacta'
export W=/tmp/warden-DEMO-xxxxxxxx/wallet    # <- your printed demo path
```

**Time.** The course is eight sessions plus a capstone: roughly four to six
hours total. Every session is self-contained — stopping after any session and
resuming tomorrow is fine. The demo wallet is throwaway: if you come back
later, just start `--demo` again and re-export `W`.

**Notation.** Four marks carry the whole manual:

- **▶ Do** — an action at the machine (deck pane, page, or terminal).
- **✔ Checkpoint** — what you must be seeing before you continue. If you do
  not see it, stop and re-do the step; checkpoints are the course's rails.
- **✎ Write** — answer in your own words, on paper or in a scratch file.
  Writing is not optional; it is how the role gets into your hands.
- **⌂ Optional** — needs internet, or goes beyond the demo. Skip freely.

**The two rules of the lab.**

1. Everything in the cockpit is **read-only** — you cannot break custody from
   a browser, so click with total freedom.
2. When we *deliberately* break things (and we will — that is Session 4's
   best moment), we break **copies**, never originals. The demo wallet is
   custody-inert anyway; the discipline is the point.

> ✔ **Checkpoint.** Your second monitor shows the deck: six colored panes and
> the wizard rail. Your second terminal answers `pacta --help` without an
> error. If both are true, you are ready.

---

## Session 0 — the world you are entering

**Goal of this session:** hold the whole system in your head at low
resolution, so every later session has a place to hang its detail.

### 0.1 The one idea

warden is a prototype custody wallet built on a single idea: **no single
program is trusted.** Before this wallet trusts a piece of cryptography, four
verifier programs — each built from a *different*, formally verified codebase
— must independently agree. If they ever disagree, the wallet freezes itself
and writes down what happened. Every decision leaves a tamper-evident trace.

Why so paranoid? Because in custody, the failure mode is not a crash — it is
a *quiet lie*: a verifier that says "valid" when it should say "invalid," a
history that has been edited, a green light nobody actually checked. Every
mechanism you will meet in this course exists to make a quiet lie either
impossible or loud.

### 0.2 The estate in five minutes

warden does not float alone. It is the custody corner of a larger estate:

- **Four verified forks** (`dalek`, `anza`, `risc0`, `betrusted`
  `-ed25519-verified`): four independent Ed25519 implementations, each with
  machine-checked proofs (in the Lean 4 proof assistant) that the code
  matches the mathematics, each fork from a different upstream lineage.
- **The Lean Transparency Log** (LTL, live at `ltl.zkdefi.org`): a public,
  append-only log. Each entry is a signed statement — *"this repository, at
  this exact commit, was verified with this exact toolchain, with this
  result"* — recorded so it can never be quietly edited or denied.
- **pacta** (this repository): the tooling that verifies, grades, and
  consumes that evidence — and warden, the wallet that stakes custody on it.
- **The public faces**: the log's API, the paper, the blog, the mirror.

You will meet all of these from inside the cockpit. You do not need to
memorize the estate — that is the Architect's chair, Session 6, and there is
a live map.

### 0.3 The three laws of the cockpit

Everything you look at for the rest of the course obeys three laws. Learn
them now; test them all course long:

1. **The design law — it renders evidence, it never asserts it.** Every panel
   is recomputed from the wallet's files at the moment the page loads, by the
   same functions the wallet itself uses. Every panel ends with a dashed
   *provenance line* naming the function and timestamp that produced it.
   What cannot be recomputed shows a red FAILED TO VERIFY — never a stale
   green, never a neutral gray.
2. **The UX law — it never leaves a human in the dark.** Verdicts come in
   words before colors; every panel has a "How to read this panel" expander;
   every term links to the glossary.
3. **The crew law — roles are distinct and cooperate through handoffs.** Six
   roles run this estate. The one who proposes never approves; the one who
   verifies never proposes; the one who watches never overrides the bench.
   You are about to become all six — *one at a time*.

### LAB 0

1. ▶ On the deck, read each pane's header: name and italic question. Say each
   role's question out loud (yes, out loud — it works).
2. ▶ Click **← Bridge** in the deck's top bar. Read the verdict banner and
   the strip of chips under it.
3. ▶ Find the **"If this happens, who acts"** dispatch table. ✎ Copy the
   two-column skeleton (event → station) onto paper. This is your course map:
   each row is a session.
4. ▶ Return to the deck (the STATIONS row of tabs, or your browser's back).

> ✔ **Checkpoint.** The bridge said **CUSTODY HEALTHY** in words, the chips
> said `4 pinned` and `chain verified`, and your paper holds a seven-row
> dispatch table.

### Self-test 0 *(answers in Appendix B)*

1. What is the one idea warden is built on, in one sentence?
2. Why does the cockpit refuse to show a "neutral gray" state?
3. Name the six roles without looking.

---

## Session 1 — the Newcomer: learning to read evidence

**You are becoming:** the person who reads evidence correctly and whose
confusion is a diagnostic instrument, not an embarrassment.

### 1.1 Why this role exists

Every other role assumes a skill nobody is born with: reading a security
surface *without trusting it*. The Newcomer chair is where that skill is
built. It is also the estate's quality sensor: veterans stop seeing gaps;
fresh eyes find them. That is why the Newcomer's report — "this page confused
me" — is treated as a bug report about the page, never about the reader.

### 1.2 The mind of the Newcomer

Adopt these three postures for this session (and keep them forever):

- **Verdict first.** On any page, read the words at the top before any
  numbers. If you read nothing else, read the verdict.
- **Provenance always.** Before believing a panel, glance at its dashed
  footer: *what function recomputed this, and when?* No footer, no belief.
- **Ask the page.** Every panel has a "How to read this panel" expander and
  little `?` marks. Using them is the skill, not a failure of it.

### 1.3 Concepts: the reading system

- **Colors mean one thing each.** Green = re-checked just now and passed.
  Amber = waiting, or needs attention. Red = failed, or *could not be
  checked*. That last part matters: the cockpit treats "I don't know" as red,
  because in custody, unverified and broken deserve the same caution.
- **The provenance line is the anti-cache.** It names the exact function
  (e.g. `Wallet.verify_ledger()`) and the UTC second of recomputation.
- **FAILED TO VERIFY is honesty, not breakage.** It means: this panel refused
  to guess.

### LAB 1

1. ▶ Open the **Guide** (INSTRUMENTS row). Read it fully once — ten minutes,
   no skimming. It is the reference the rest of the course leans on.
2. ▶ Open **Posture**. Read only the verdict banner and each panel's *first
   sentence*. ✎ In one line each: what do the latch, ledger, quorum, signing
   rules, and recorded-history panels answer?
3. ▶ The recompute proof: note the timestamp in the Ledger panel's provenance
   line. Reload the page. Compare.
4. ▶ Open one `?` mark (any panel) and follow it to the glossary and back.
5. ▶ On the deck, run wizard steps 1–3 if you have not already (the wizard is
   this session's condensed twin).

> ✔ **Checkpoint.** The provenance timestamp *changed* when you reloaded —
> you watched the ledger's full hash chain being re-verified for you,
> live, both times. That is the design law observed with your own eyes.

### What the Newcomer never does

- Never pretends to understand. Every other chair once sat here.
- Never assumes a confusing page is their fault — they report it.

*Thought experiment:* if newcomers politely stayed quiet, which of the three
laws would rot first, and who would notice — and when?

### Handoff

The Newcomer **delivers** confusion reports to the Architect and Operator,
and **receives** the guide, the demo, and patient answers. ✎ Write one real
confusion report from your Lab 1 (there is always one). Keep it — you will
deliver it in Session 6.

### Self-test 1

1. A panel shows green. What two things did the cockpit do before showing it?
2. What is the difference between red-failed and red-could-not-check, and why
   does the cockpit refuse to distinguish them visually?
3. Where do you look first on any page?

> **Recap card — NEWCOMER.** Question: *what is all this?* Reads verdict
> first, provenance always. Confusion = instrument. Never silent, never
> ashamed. Delivers: fresh eyes.

---

## Session 2 — the Proposer: asking precisely

**You are becoming:** the origin of every signature — the one who asks, and
who lives with written answers.

### 2.1 Why this role exists

Somebody has to want something signed; in production that is the financial
agent. The danger of the asking role is scope creep: the asker who also
approves, or who "just quickly" adjusts policy to fit their own request, has
dismantled the whole trust story alone. So the estate gives asking its own
chair with hard walls — and in exchange, the Proposer gets something rare:
**every "no" arrives in writing, with instructions.**

### 2.2 The mind of the Proposer

- **Precision or nothing.** A proposal is the exact bytes to be signed, named
  by their SHA-256 fingerprint. "Roughly this transaction" does not exist.
- **A refusal is a to-do list.** Not an insult, not a negotiation opening —
  a machine-readable statement of what rule fired and what would satisfy it.
- **I ask; I never approve.** Even when — especially when — I am sure.

### 2.3 Concepts

- **The payload fingerprint.** SHA-256 of the exact bytes to sign. The
  offline signer signs those bytes and nothing else; both sides of the
  air gap can compare fingerprints before anything happens. Every later
  dispute is settled by this hash.
- **The front door.** Proposals enter through the wallet's agent-native MCP
  surface — the `request_signature` tool on `pacta wallet mcp`. There is
  deliberately no cozier side entrance.
- **The refusal receipt.** `code` (which rule fired), `missing` (the exact
  unmet precondition), `remediation` (what would make the same request
  succeed). Machine-readable so an agent — or you — can correct and retry
  without guessing.
- **Queue states.** *awaiting device* = parked in the outbox, the offline
  signer has not answered; *answered* = a response file arrived in the inbox.

### LAB 2

1. ▶ In the **amber Proposer pane** (or the full station page), find the
   queue. One request sits *awaiting device*. ✎ Note the first 12 characters
   of its payload fingerprint.
2. ▶ Watch a fingerprint being born. In your second terminal:

```
printf 'pay 5 to bob' > /tmp/payload.demo
sha256sum /tmp/payload.demo
```

   Change one character (`5` → `6`) and hash again. ✎ How much of the
   fingerprint changed? What does that mean for "roughly this transaction"?
3. ▶ From the Proposer station's instrument links, open **Incidents** and
   read the demo refusal receipt. ✎ Fill this sentence from its fields: *"My
   request was refused under rule ________ because ________ was missing; it
   would succeed if I ________."*
4. ▶ Read the Proposer station's Duties top to bottom — every command shown
   is the real CLI. (⌂ The JSON-RPC lines for driving `request_signature` by
   hand are in `WALLET.md` — worth a look, not required.)

> ✔ **Checkpoint.** Your two hashes differ completely (an avalanche — one
> character flipped roughly half the bits), and your refusal sentence reads:
> rule `POLICY_DENIED`, missing *allowlisted destination*, succeed after
> *adding the destination to the policy allowlist*.

### What the Proposer never does — and why

- **Never approves or verifies their own proposal.** Self-approval is the
  single cheapest attack on any custody system: no cryptography needs to be
  broken, only one person's honesty. The wall is load-bearing.
- **Never touches the air-gap device or its folders.** The walk belongs to
  the Operator; splitting request-maker from request-carrier means collusion,
  not error, is required for abuse.
- **Never edits `policy.json` to fit their own request.** Policy changes are
  the Operator's deliberate act — and the ledger records them permanently.

### Handoff

Delivers: fingerprinted requests → the signing firewall; escalations after
repeated refusals → the Operator. Receives: a signature, or a refusal
receipt ← the wallet. ✎ Draft a two-line escalation note for the demo
refusal, addressed to the Operator. Keep it for the capstone.

### Self-test 2

1. Why is the payload fingerprint the thing both sides of the air gap
   compare, rather than a human-readable description?
2. Name the three fields of a refusal receipt and each one's job.
3. Your request keeps being refused and you are *certain* it is fine. List
   your legal moves.

> **Recap card — PROPOSER.** Question: *how do I ask?* Exact bytes,
> fingerprinted. Refusals are instructions. Asks through the front door;
> never approves, never carries, never bends policy.

---

## Session 3 — the Quorum bench: four seats, one answer each

**You are becoming:** one seat of four — a verifier whose entire value is
that its judgment is nobody else's.

### 3.1 Why this role exists

One verifier — however carefully built — is one bug, one backdoor, one
compromised build machine away from a quiet lie. warden's answer is not "be
more careful"; it is **independence multiplied**: four verifier programs,
each built from a *different* formally verified Ed25519 codebase from a
different upstream lineage. For a wrong verdict to pass, the same lie would
have to exist independently in all four — not one mistake, but a coordinated
miracle.

### 3.2 The mind of a seat

- **My verdict is mine alone.** Built from my sources, computed by my
  binary. I do not preview, harmonize, or average with the other seats.
- **Dissent is my job working.** If I say INVALID while three say OK, I have
  either caught the failure of the century or found a bug in myself — both
  are exactly what four seats exist to surface. Custody freezes; humans look.
- **My independence is my hygiene.** A shared toolchain, cache, or patch
  with another seat is a shared bug: four seats that secretly agree because
  they are one seat protect nothing.

### 3.3 Concepts

- **Unanimity or latch.** All members must independently accept, or custody
  freezes. Not majority — a 3-of-4 design would trade the estate's whole
  premise (catch the quiet lie) for availability. Here, one honest dissenter
  outvotes three comfortable agreements — by design.
- **Pinning.** The custody capsule stores each member binary's SHA-256. On
  use, the file on disk is re-hashed and compared: a swapped or modified
  binary fails and is rejected. Pinning proves the file is *unchanged* —
  and, honestly, nothing more.
- **Evidence grades R0–R5.** This estate's scale for formal evidence:
  R0 = no usable evidence … R4 = machine-checked proofs covering the full
  documented boundary … R5 would add reproducible builds and side-channel
  assurance. **Nothing holds R5 yet**, so pinning cannot prove a binary was
  honestly *built* from its attested sources. The capsule requires R4 of
  every member, and the gap to R5 is stated everywhere it matters — an
  honest system states its own boundary.
- **The capsule.** The wallet's founding document: members, pins, policy.
  Its own SHA-256 is anchored in the ledger's first entry — so even the list
  of who is trusted cannot be quietly swapped.

### LAB 3

1. ▶ **Indigo Quorum pane** (or full Posture): the bench roster. ✎ For each
   of the four seats: backend name, the repo it is built from, and the first
   8 characters of its binary fingerprint. Write all four — the act of
   copying fingerprints by hand is the point.
2. ▶ Open the roster's "How to read this panel" expander and read the
   *evidence grade* bullet. ✎ In one line: what exactly would R5 add, and
   what attack does its absence leave open?
3. ▶ In the terminal:

```
pacta wallet status --wallet "$W"
```

   ✎ Find the members and the capsule hash in the output. Does the capsule
   hash's first 24 hex match what the cockpit's quorum panel shows?
4. ▶ Open **Incidents** and read the demo divergence: `risc0` answered
   INVALID where three answered OK. ✎ As the risc0 seat, write two sentences
   defending your dissent to the Operator *without apologizing*.

> ✔ **Checkpoint.** Four seats on paper with four distinct fingerprints; the
> CLI's capsule hash matches the cockpit's; your dissent defense states what
> you observed and refuses to guess at what the others did.

### What the bench never does — and why

- **Never proposes.** The bench judges evidence; the moment it originates
  spends, judge and party have merged.
- **Never harmonizes before answering.** Pre-agreement converts four
  independent measurements into one measurement with four signatures.
- **Never clears a latch its own dissent caused.** You are a witness to your
  own alarm, not its judge.

*Thought experiment:* an attacker can fully compromise the build of exactly
one seat. Walk through what happens on the next verification — and what the
attacker would have needed instead for the lie to go through.

### Handoff

Delivers: unanimous admits, or a latch-tripping dissent → the wallet;
divergence incidents → the Operator. Receives: component evidence ← the
wallet's inbound boundary; rebuilt pinned sources ← the Architect's forks.

### Self-test 3

1. Why unanimity instead of 3-of-4 majority — what is being traded for what?
2. What does a pinned fingerprint prove, and what does it *not* prove? Name
   the grade that would close the gap.
3. Your seat dissents and custody freezes trading for a day. Was this a
   success or a failure? For whom?

> **Recap card — QUORUM SEAT.** Question: *would I stake custody on this?*
> One seat, one codebase, one verdict. Unanimity or latch. Independence is
> hygiene; dissent is the job working; never proposes, never averages.

---

## Session 4 — the Operator: watching, and the day something breaks

**You are becoming:** the person who watches the pulses, holds the brakes,
and writes the permanent notes — the calm in the estate.

### 4.1 Why this role exists

Every guarantee you have met so far is *checkable* — but checkable is
worthless if nobody checks. An unwatched log, an unprobed service, an
unverified ledger are safe only on paper. The Operator is the estate's
standing answer to "who actually looks?" — and, when the latch trips, the
one chair with the authority (and the obligation) to run the recovery by the
book.

### 4.2 The mind of the Operator

- **Liveness is not honesty.** My probes tell me something *answered* — not
  that it told the truth. Truth is the Cryptographer's replay; I check
  pulses, daily, on demand, never on autopilot.
- **Procedures over improvisation.** When the latch trips, I open the
  runbook. Excitement is for people without checklists.
- **Permanent notes.** My unlatch decision goes into the ledger with a
  written root cause, forever. If I cannot write the cause, I am not done
  investigating.

### 4.3 Concepts

- **The liveness board.** On-demand probes: HTTP GET on each public service
  (status, observed facts, latency), `git` checks on each local working copy
  (present, HEAD, clean/dirty). It runs only when you press **Probe now** —
  the cockpit never phones home on an ordinary page load.
- **The latch lifecycle.** Trips on quorum divergence or suspected tampering
  → all outbound signing refused (with receipts) → investigation per
  `docs/runbook-latch.md` → root cause fixed → `pacta wallet unlatch` with a
  mandatory note, recorded permanently.
- **Append-only ethics.** The transparency log's operator side has four
  absolute nevers: never force-push the log repo, never edit or delete under
  `entries/`, never re-sign a published head, never backdate. An append-only
  log that gets "corrected" once is not append-only — it is marketing.
- **Advancing the pin.** `pacta sth-refresh` fetches the log's newest signed
  head, verifies its signature *and its consistency with the previously
  pinned tree size*, then advances the local pin — the defense against a log
  that shows different histories to different people (split view) or rolls
  back.

### LAB 4

1. ▶ **Green Operator pane**: press **Probe now**. ✎ Record: the log head's
   `tree_size` and root prefix; the slowest probe's latency; any repo marked
   *dirty* (uncommitted changes) — dirty is amber, not red: alive, but with
   local work in progress.
2. ▶ Daily wallet checks, from the terminal:

```
pacta wallet status --wallet "$W"
pacta wallet verify-ledger --wallet "$W"
```

   ✎ What did verify-ledger actually recompute? (The Ledger panel's
   explainer has the exact answer.)
3. ▶ **The tamper drill.** You will now watch the system catch history
   editing — on a **copy**:

```
cp -r "$W" /tmp/tamper-lab-wallet
sed -i 's/genesis/gene-sis/' /tmp/tamper-lab-wallet/ledger.jsonl
pacta wallet verify-ledger --wallet /tmp/tamper-lab-wallet
```

   One character of history changed. ✔ The verifier reports the chain broken
   at the first entry — loudly, non-zero exit.
4. ▶ Now see it as the crew would: point a *second* cockpit at the corpse:

```
pacta wallet cockpit --wallet /tmp/tamper-lab-wallet --port 8481
```

   Open `http://127.0.0.1:8481/posture`. Read the banner. Then stop that
   server (Ctrl-C) and destroy the evidence of your crime:

```
rm -rf /tmp/tamper-lab-wallet /tmp/payload.demo
```

5. ▶ Read the Operator station's Duties 2 and 3 (`sth-refresh`,
   `witness-audit`) — these are the same watching, aimed at the public log.
   (⌂ With internet and a clone of `lean-transparency-log`, run
   `pacta witness-audit --published-dir <clone>` and watch every historical
   head re-verified.)

> ✔ **Checkpoint.** The tampered copy produced (a) a failing
> `verify-ledger` naming the broken entry and (b) a cockpit banner reading
> **CUSTODY EVIDENCE BROKEN** with the ledger panel red. You edited one
> character of one file, and two independent surfaces caught it instantly.
> *That* is what a hash chain buys.

### What the Operator never does — and why

- **Never unlatches without a written root cause.** The CLI refuses an empty
  note; the ledger keeps it forever. An unexplained unlatch is a future
  incident with a head start.
- **Never rewrites history** — the four log nevers above. The log's entire
  value is that this never happened, not that it rarely happens.
- **Never overrides the bench.** A divergence gets investigation, not a
  fifth vote.
- **Never signs or proposes.** The brakes and the pen live in different
  chairs.

### Handoff

Delivers: unlatch decisions with permanent notes → the ledger; outage and
repair notes → the Architect. Receives: incidents ← wallet and bench;
escalations ← the Proposer (you are holding one from Session 2 — file it
mentally under "capstone").

### Self-test 4

1. Alive and honest — whose job is each, and with which tools?
2. Recite the four log nevers. Which one would be the *most* tempting on a
   bad day, and why is it still absolute?
3. In the tamper drill, why did changing bytes in entry 1 break the chain at
   entry 1 rather than at the newest entry?

> **Recap card — OPERATOR.** Question: *is everything running, and is
> custody unfrozen?* Probes on demand; verifies the chain daily; runs the
> runbook when the latch trips; writes permanent notes; never rewrites,
> never overrides, never signs.

---

## Session 5 — the Cryptographer: recompute everything

**You are becoming:** the person who accepts nothing they did not recompute
— and who knows *exactly* where each guarantee stops.

### 5.1 Why this role exists

Everything in this estate ultimately reduces to a claim someone could check.
The Cryptographer is the someone. Without this chair, "verifiable" quietly
degrades into "verified by nobody" — and the estate becomes exactly the
kind of trust-me system it was built to replace.

### 5.2 The mind of the Cryptographer

- **Recompute, don't trust.** A green light I did not recompute is a rumor —
  including the cockpit's own green lights.
- **Boundaries are sacred.** "Verified" means precisely what the certificate
  says — never one theorem more. Stretching a claim past its boundary is not
  enthusiasm, it is a false claim.
- **The log is not an oracle.** It is an accountability ledger: it makes
  claims permanent and attributable, not true. A lie recorded in the log is
  still a lie — permanently on the record, and catchable by replay.

### 5.3 Concepts

- **Attestation.** A signed statement: repository X, at exact commit C, was
  verified with exact toolchain T, with result R (every certificate, every
  axiom listed). It names its own evidence precisely enough to replay.
- **Transparency receipt.** Proof that the attestation is recorded in the
  public log: an *inclusion proof* (a short chain of hashes showing the
  leaf is under the log's signed root) plus the *signed tree head*. Verify
  both and you know: this exact statement is permanently in the public
  record — the operator can never unsay, edit, or deny it.
- **What the log guarantees — and what it does not.** The Merkle machinery
  guarantees inclusion, append-only history, and transferable evidence of
  equivocation (two conflicting signed heads at the same size, in one log
  context, convict the key holder). It does **not** referee truth: a leaf's
  *content* can be false, and only independent replay — off-protocol work
  with the proof assistant — catches that. The design's honest slogan:
  cheap to claim, impossible to unsay, catchable forever.
- **Claim boundaries you must be able to recite.** The Ed25519 proofs treat
  SHA-512 as an opaque function (its correctness is assumed, not proven);
  reproducible builds are out of scope (the R4/R5 gap); the mechanized
  results cover the accumulator model as stated in the paper, with a
  published ledger of what is *not* proven. Where the mathematics stops,
  the certificate says so.

### LAB 5

1. ▶ **Purple Cryptographer pane**: click **Load the sample evidence**, then
   **Verify (read-only)**. Do not just admire the green: ✎ copy out the
   diagnostics list and annotate each line with what check it was
   (signature? inclusion? hash equality? freshness?). Use the panel's
   explainers.
2. ▶ Break it, three ways. After each, restore (reload the sample) before
   the next:
   - delete one character from the **receipt** box → verify;
   - delete one character from the **attestation** box → verify;
   - delete one character from the **public key** box → verify.
   ✎ For each: what failed, and *at which layer*? Notice the error surfaces
   are different — a verifier that fails identically for every cause is a
   verifier you cannot debug.
3. ▶ Boundary recitation, closed-book: ✎ write the three claim boundaries
   from 5.3 from memory. Check yourself against the guide's "What this
   cockpit cannot tell you."
4. ⌂ **The full replay** (internet + a clone):

```
pacta log-fetch --url https://ltl.zkdefi.org --component dalek-ed25519-verified
git clone https://zkdefi.org/saymrwulf/lean-transparency-log
cd lean-transparency-log && python3 verify.py --all && python3 verify_selftest.py
```

   `verify.py --all` re-checks every leaf, every signed head, every receipt,
   offline, fail-closed — and `verify_selftest.py` then attacks the verifier
   itself with corrupted inputs to prove it *would* fail if lied to.
   ✎ Why does shipping the self-test beside the verifier matter?

> ✔ **Checkpoint.** One ACCEPTED verdict whose every diagnostic line you can
> name; three different refusals you caused on purpose and can tell apart;
> three boundaries recited without looking.

### What the Cryptographer never does — and why

- **Never accepts an unrecomputed green** — the chair exists to be the
  recomputation.
- **Never extends a claim past its boundary.** The estate's credibility is
  the sum of its stated limits; one stretched claim spends all of it.
- **Never treats the log as a truth oracle.** Permanence is not truth;
  replay is truth's only entrance.

### Handoff

Delivers: audit verdicts → Operator and Proposer; boundary corrections →
the Architect (docs and map). Receives: artifacts to audit ← anyone; fresh
evidence ← the live log.

### Self-test 5

1. An attestation verifies perfectly: signatures good, inclusion proven,
   head signed. List everything this does — and does not — tell you.
2. What is equivocation evidence, and why is it the one misbehavior directly
   attributable to the log operator?
3. Why did the three sabotages in Lab 5 fail *differently*, and why is that
   a feature?

> **Recap card — CRYPTOGRAPHER.** Question: *does the evidence prove what it
> claims?* Recomputes everything, everywhere, including the cockpit. Knows
> each boundary by heart. Log = permanent, not true; replay decides. Never
> stretches, never trusts, never tires.

---

## Session 6 — the Architect: the map and the territory

**You are becoming:** the person who keeps the whole estate tellable — every
repo, service, mirror, and loop — and who guards what may be said in public.

### 6.1 Why this role exists

The estate is many repositories, services, mirrors, and two self-referential
loops. No head holds that reliably — and an estate nobody can hold is an
estate where drift, duplication, and quiet inconsistency breed. The
Architect's answer is a *map that is recomputed, never remembered* — and a
tripwire that screams when the map forks from itself.

### 6.2 The mind of the Architect

- **The map is recomputed, never remembered.** If I "know" the estate from
  memory, I know last month's estate.
- **Two renderings of one model need a tripwire.** Anything that exists
  twice will drift; the only question is whether the drift is caught.
- **Public is a one-way door.** A name published once is published forever.
  Public documents list only entities whose existence is already public or
  must be public for trust.

### 6.3 Concepts

- **The estate map.** Five lanes of custody (upstream sources → verified
  subjects → machinery and operator-held → published faces → consumers),
  with every entity carrying its *runtime* (always-on / on-demand /
  not-running / static) and mutability class.
- **The two loops** — the estate's hardest furniture, each tellable in one
  breath:
  - **Loop 1, the dogfood signer:** the log's own signing machinery uses an
    Ed25519 implementation that is itself verified and attested *inside the
    log it signs* (leaf 8). The tool guards the evidence; the evidence
    covers the tool.
  - **Loop 2, the self-attesting mechanization:** entry 13 of the log is the
    kernel-checked mechanization of the very soundness arguments the log's
    accumulator relies on. The proofs about the machinery live inside the
    ledger the machinery protects — scoped honestly, with a published list
    of what is *not* proven.
- **The drift tripwire.** The map exists twice (committed `ESTATE.md`; the
  cockpit's estate view). A name-level comparison runs live on the Architect
  station and in the test suite; if the renderings disagree, the suite fails.
- **The generated-file lesson** (a true war story): a published verifier
  once got hardened at its destination while the *template that generates
  it* kept the old, weaker code — a time bomb where the next publish would
  have silently un-fixed it. It was caught in an audit and now has its own
  tripwire test. The Architect's rule ever since: **when you fix a
  generated file, find and fix its generator in the same change.**

### LAB 6

1. ▶ **Slate Architect pane**: read the **drift tripwire** result. Then open
   the **Estate map** (instrument link). Click the transparency-log card and
   read its dossier. ✎ Which lane is it in, what is its runtime, what is its
   mutability?
2. ▶ Find warden/pacta on the map. ✎ Which entities *consume* the log's
   evidence, per the map's edges?
3. ▶ Trace Loop 2 on the map until you can tell it in one breath. ✎ Write
   both loops, one sentence each, closed-book.
4. ▶ Close the map. ✎ Draw the five lanes from memory — boxes and arrows,
   ninety seconds, ugly is fine. Reopen and compare. What did you misplace?
5. ▶ Deliver the Newcomer's confusion report from Session 1 (you kept it):
   decide *as the Architect* — is it a page bug, a glossary gap, or a map
   gap? ✎ Write the one-line disposition.

> ✔ **Checkpoint.** The tripwire says the renderings agree; both loops exist
> as single sentences in your handwriting; the confusion report has a
> disposition.

### What the Architect never does — and why

- **Never names private infrastructure in public artifacts.** Existence
  disclosure is irreversible and someone else's risk to accept, not yours.
- **Never fixes a generated file without its generator** — the war story
  above is why this is a never and not a tip.
- **Never redraws the map from memory.** Memory is where drift lives.

### Handoff

Delivers: the updated, drift-guarded map → everyone. Receives: outage and
repair notes ← the Operator; boundary corrections ← the Cryptographer;
confusion reports ← the Newcomer.

### Self-test 6

1. Tell both loops, one sentence each.
2. Why is "runtime" (always-on / on-demand / static) a property the *map*
   must carry, rather than something people just know?
3. A teammate fixed a bug directly in a published, generated file and
   pushed. What do you do, in order?

> **Recap card — ARCHITECT.** Question: *does the map match the territory?*
> Five lanes, two loops, runtime on everything. Tripwires over trust;
> generators with their outputs; public is forever. Never draws from memory.

---

## Session 7 — Capstone: the incident day

*One person, six chairs, one incident, no AI. You will walk a single event
through every role, producing each role's real artifact. Do this with the
deck open — move your eyes to each pane as you take its chair. If you run a
study club (see Session 8), this is the session to run as a group, one chair
per person.*

**The scenario.** A routine component re-verification comes through the
wallet's inbound boundary. Seat `risc0` answers INVALID; `dalek`, `anza`,
`betrusted` answer OK. The latch trips. (This is exactly the incident your
demo wallet carries — the deck is your set dressing.)

Work the stations **in this order**, writing each artifact (✎) before
moving to the next chair. Do not blend chairs — that is the whole exam:

1. **The wallet speaks first** (no chair): an incident file exists; the
   latch is on; every signing request now gets a refusal receipt citing
   `CUSTODY_LATCHED`. ▶ Find all three facts in the cockpit (incidents
   list; latch panel wording; refusal-code explainer).
2. **Proposer.** Your pending payment just got refused. ✎ Artifact 1: the
   escalation note to the Operator — request id, payload fingerprint,
   refusal code, and the sentence "awaiting custody recovery; will resubmit
   unchanged." (No pressure on anyone to hurry — note that restraint; it is
   the role.)
3. **Operator.** Open the runbook mentally: freeze confirmed, incident read.
   ✎ Artifact 2: the investigation plan — three numbered checks you will
   run, in order, and who you will hear from before any unlatch (the bench
   and the cryptographer). *Hint: your Session 4 daily checks are two of the
   three.*
4. **Quorum seat (risc0).** ✎ Artifact 3: the dissent defense — what your
   seat observed, refusal to speculate about other seats, and the one thing
   that would change your verdict (a re-run on your rebuilt, re-pinned
   binary).
5. **Cryptographer.** ✎ Artifact 4: the audit verdict — what you recomputed
   (the payload against each seat's verifier, the members' pins, the
   evidence receipts), what you found (in this scenario's story: the risc0
   seat's binary was faulty *at sealing time* — its pin verified, meaning
   unchanged since sealing, which is exactly why pin-checking could not
   catch it; a rebuild from the pinned proven sources produced a differing,
   correct binary), and the boundary sentence: "this attributes the
   divergence; it does not prove the other three correct — their pins
   verified, and unchanged-since-sealing is all a pin ever proves."
6. **Operator again.** Root cause in hand (stale seat binary; rebuilt and
   re-pinned by the bench). ✎ Artifact 5: the permanent unlatch note —
   cause, fix, evidence checked, date. One paragraph you would sign with
   your name, knowing the ledger keeps it forever.
7. **Architect.** ✎ Artifact 6: the map disposition — does anything on the
   estate map change? (A seat was rebuilt and re-pinned: the capsule's pin
   set changed, which is a re-sealing event the wallet's dossier must
   reflect — and the incident is now permanent recorded history. One line
   each.)
8. **Newcomer** (yes, last chair): reread all six artifacts as someone who
   joined today. ✎ Artifact 7: the one place the paper trail would confuse a
   fresh reader, and the one-line fix.

> ✔ **Checkpoint — the debrief.** Lay the seven artifacts in a row. Notice
> three things. *Every handoff is written* — nothing moved by hallway
> conversation. *No chair did another chair's job* — the proposer never
> argued innocence, the bench never touched the latch, the operator never
> re-verified crypto. And *the system was never trusted to be fine* — it
> was recomputed fine, at every step. That is the crew law, lived once,
> end to end.

---

## Session 8 — Graduation: toward the real thing

### 8.1 What changes with a real wallet

The demo you have been flying is custody-inert: fake members, throwaway
keys. The real path — read it now, walk it when you mean it:

1. **Build the quorum from the pinned proven sources:**
   `pacta wallet build-quorum --sources-root <fork-checkouts>` — four real
   verifier binaries, four real fingerprints.
2. **Fetch real evidence** for every member from the live log:
   `pacta log-fetch --url https://ltl.zkdefi.org --component <each>`.
3. **Seal the wallet — the R4 gate in executable form:**
   `pacta wallet init --wallet <dir> --evidence <dir> --log-public-key
   log.pub --trusted-provider <name>` — it *refuses* to seal below
   end-to-end evidence coverage. A wallet that cannot prove its bench is a
   wallet that does not open.
4. **Write policy before you need it:** `pacta wallet policy --wallet <dir>
   --init-template`, then edit limits and allowlists while nothing is at
   stake.
5. **Decide the air-gap story** (which machine holds the key, who walks the
   files) — and only then let value near it.

### 8.2 Running this as a study club

The capstone was built for a table of people: one chair each, artifacts
passed as real handoffs, the deck on a shared screen. Rotate chairs and
re-run it — the incident reads completely differently from inside another
role, and *that* discovery is the club's graduation. (One person plus an AI
agent works too: the agent takes the chairs you are not sitting in — but it
must obey the same law you learned: one chair at a time, handoffs in
writing.)

### 8.3 Where this manual ends

- The **paper** — the transparency model, the accountability games, and the
  honest limits, with full rigor: linked from the estate map's log dossier
  and at `ltl.zkdefi.org/paper`.
- The **blog** (`blog.zkdefi.org`) — the narrative pieces, including what
  the log does and does not promise.
- **`WALLET.md`** and **`docs/`** in this repository — the wallet's
  reference documentation, threat model, runbooks, product lineup.
- The **curriculum repository** (`verifying-crypto-with-lean`) — if Session
  5 left you wanting the mathematics itself, that is its course.

You came in as one person. You leave as a crew that happens to share a
body — and you know which chair you are sitting in at every moment.

---

## Appendix A — command reference by chair

*All read-only against the demo wallet except where marked ⚠ (mutates
wallet state — real operations, operator's deliberate acts).*

| Chair | Command | What it does |
|---|---|---|
| any | `pacta wallet cockpit --demo` | seal + serve a throwaway demo wallet |
| any | `pacta wallet cockpit --wallet DIR` | serve the cockpit over a wallet |
| any | `pacta wallet status --wallet DIR` | custody posture (capsule, latch, ledger) |
| Proposer | `sha256sum payload.bin` | the payload fingerprint, born |
| Proposer | `pacta wallet mcp --wallet DIR` | the front door (then `request_signature`) |
| Proposer | `pacta wallet treasury-verify --wallet DIR --tx-file f` | quorum-verify a transaction's signatures |
| Quorum | `pacta wallet build-quorum --sources-root DIR` | rebuild members from pinned proven sources |
| Operator | `pacta wallet verify-ledger --wallet DIR` | recompute the full hash chain |
| Operator | `pacta sth-refresh --url URL --sth-store F --log-public-key K` | advance the log pin (split-view defense) |
| Operator | `pacta witness-audit --published-dir DIR` | re-verify a log clone's entire history |
| Operator ⚠ | `pacta wallet unlatch --wallet DIR --note "cause"` | clear the latch; note recorded forever |
| Cryptographer | `pacta receipt-verify --attestation A --receipt R --log-public-key K` | verify one receipt (add `--sth-store`, `--max-sth-age-seconds`, `--require-verified-verifier` to harden) |
| Cryptographer | `pacta log-fetch --url URL --component C` | fetch + locally verify fresh evidence |
| Cryptographer | `python3 verify.py --all` (in a log clone) | replay the whole log offline |
| Architect | `python3 scripts/mini_pytest.py` | run the suite, incl. the drift tripwire |

## Appendix B — self-test answers

**0.1** No single program is trusted: four independently built, formally
verified verifiers must unanimously agree before the wallet trusts a
component; disagreement freezes custody and is recorded.
**0.2** Gray would mean "status unknown, presumed fine." In custody,
unverified must look as alarming as broken — so unknown renders red
(FAILED TO VERIFY), never neutral.
**0.3** Newcomer, Proposer, Quorum bench, Operator, Cryptographer,
Architect.

**1.1** It recomputed the underlying fact from the wallet's files at
request time, and it stamped a provenance line naming the function and
timestamp that did it.
**1.2** Red-failed = a check ran and failed; red-could-not-check = the check
could not run. Visually identical on purpose: both must stop you, and a
distinction would invite "it's probably just the checker."
**1.3** The verdict, in words, at the top.

**2.1** The fingerprint commits to the exact bytes; a description can match
many byte strings (and can be argued about later). Both sides hash
independently and compare — no trust in transcription needed.
**2.2** `code` = which rule fired; `missing` = the precise unmet
precondition; `remediation` = what would make the same request succeed.
**2.3** Read the receipt and remediate; resubmit unchanged if the receipt
says the block is temporary (e.g. latch); escalate in writing to the
Operator. Not on the list, ever: self-approve, touch the device, edit
policy.

**3.1** Unanimity trades availability (any seat can halt custody) for the
guarantee that a single honest seat defeats a quiet lie. Majority would
keep trading through exactly the event the system exists to catch.
**3.2** Pinning proves the binary on disk is byte-identical to the one
sealed in the capsule. It does not prove the binary was honestly built from
the attested sources — that is the reproducible-builds gap, closed only at
grade R5 (which nothing holds yet, and the estate says so).
**3.3** A success of the mechanism (the lie or fault did not pass), whatever
it cost in downtime. For the seat: the job working. For the estate: the
premium it agreed to pay.

**4.1** Alive = Operator, with probes (HTTP GET, git checks). Honest =
Cryptographer, with recomputation (receipt-verify, offline replay).
**4.2** Never force-push, never edit/delete under `entries/`, never re-sign
a published head, never backdate. The tempting one is re-signing "to fix a
mistake" — and it is absolute because one corrected head destroys the only
thing the log sells: that this never happens.
**4.3** Because every entry contains the hash of the previous one, the
chain is checked from genesis forward; the first entry whose stored link
fails to recompute is where verification stops and reports. The tamper was
*in* entry 1, so the chain broke *at* entry 1.

**5.1** It tells you: this exact statement is permanently recorded in the
log under a validly signed head, and the artifacts are internally
consistent. It does not tell you: that the statement's content is true
(replay decides that), that the verification it describes was competent, or
anything beyond the certificate's stated boundary.
**5.2** Two conflicting signed tree heads at the same tree size, in one log
context. Only the operator's key can produce signed heads, so two
conflicting ones are transferable proof of double-speak, attributable to
the key holder — no interpretation needed.
**5.3** Each sabotage hit a different layer (log signature chain,
attestation content hash, key parsing), and the verifier reports the layer
that failed. Distinct failures mean a debuggable verifier — and are
themselves evidence the checks are real and separate, not one theatrical
boolean.

**6.1** Loop 1: the log's signing machinery runs on an Ed25519
implementation that is itself verified and attested inside the log it
signs (leaf 8). Loop 2: entry 13 is the kernel-checked mechanization of
the accumulator arguments the log itself relies on — the proofs about the
machinery live in the ledger the machinery protects.
**6.2** Because "what is running" is invisible from any single machine and
rots fastest in memory; carrying runtime on the map makes staleness a
checkable property instead of folklore.
**6.3** (1) Check whether the generator still produces the old file — if
so, the fix is a time bomb. (2) Fix the generator, regenerate, verify
byte-identity with the intended output. (3) Add the tripwire test that
fails on generator/output drift. (4) Only then consider the incident
closed — and write the note.

## Appendix C — glossary and further reading

Every term this manual uses — capsule, seat, pin, grade, ledger, latch,
incident, refusal receipt, air gap, attestation, receipt, provenance,
station — is defined in plain language in the cockpit's **Guide**
(`/guide`), which is the manual's companion reference. The estate map
(`/estate`) is the territory's picture; `ESTATE.md` is its committed twin;
the paper and blog (Session 8.3) are the deep end. Go sit in a chair.
