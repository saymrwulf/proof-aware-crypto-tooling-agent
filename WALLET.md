# warden — the verified-custody wallet

warden is the acting end of pacta. Where the rest of the project *decides*
which cryptographic code is trustworthy, warden *runs on that decision*:
it builds an Ed25519 custody boundary out of the four independently
proven curve25519-dalek forks, and puts them to work guarding money-
adjacent signatures — inbound and outbound.

It is agent-native first. The primary interface is an MCP server; a human
CLI is provided for operation and inspection. The design research behind
that choice is in [docs/agent-native.md](docs/agent-native.md).

---

## The one idea

**Inbound acceptance requires a unanimous quorum of provably-equivalent
verifiers. Outbound signatures must pass the same quorum before release.**

Each quorum member is an Ed25519 verifier compiled from a source workspace
whose correctness certificates are machine-checked in Lean 4 and replay-
attested in the public [Lean Transparency Log](https://ltl.zkdefi.org).
The four members — `dalek`, `anza`, `risc0`, `betrusted` — are genuinely
different codebases, but each is *proven* to decide the same predicate:

```
accept(A, m, R, s)  ⇔  decompress(R) = [k](−A) + [s]B
```

Classic N-version programming hopes independent implementations won't
share a bug. warden doesn't hope: on the proven domain the members
*cannot* disagree about semantics, so a runtime disagreement is not a
difference of opinion — it is evidence of build corruption, a memory
fault, or tampering. That turns "the verifiers disagreed" from a shrug
into an alarm with a machine-checked guarantee behind it.

---

## Trust posture (read this before trusting it)

| surface | assurance |
|---|---|
| inbound verification | **custody-grade** — quorum of certificate-covered verify paths |
| outbound firewall (verify-after-sign) | **custody-grade** — same quorum |
| outbound signing itself | **trusted base** — the attested artifact, not a third implementation; not covered by any theorem |
| SHA-512 | opaque oracle inside the theorems |
| wire parsers | outcomes are hypotheses |
| reproducible builds, side channels | not claimed (that is R5) |
| ML-DSA / PQC | fail-closed: no proven implementation exists |

The asymmetry is the point: warden is strongest exactly where it matters
most for custody — deciding whether an inbound authorization is real — and
honest about the weaker outbound edge, which it fences with the firewall.

---

## Anatomy of a wallet

A wallet is a directory of evidence, not a database of secrets:

```
capsule.json     the sealed custody capsule: quorum members, their attested
                 source commits, the transparency-log receipts that
                 authorized them (the R4 gate), and the policy in force
ledger.jsonl     append-only, SHA-256 hash-chained event log
keys/            wallet identities (local signer keys are 0600; the airgap
                 identity has no private key on this host)
incidents/       quorum divergences and firewall quarantines, full trails
receipts/        refusal receipts — signed, machine-actionable
quarantine/      signatures the firewall refused to release
airgap/          outbox/inbox for the Precursor-style gap signer
latch.json       present and latched=true when custody is frozen
```

Every state change — inbound verify, outbound sign, refusal, incident,
latch, unlatch — is a hash-chained ledger entry. `pacta wallet
verify-ledger` recomputes the chain; a single altered byte anywhere in
the history is caught.

---

## The R4 gate, in executable form

`pacta wallet init` refuses to create a wallet unless, **for every member**:

1. the built binary's provenance names an attested source commit;
2. the evidence dir holds that component's attestation + inclusion receipt;
3. the attestation re-validates locally — verdicts are **re-derived from
   observed axiom cones**, never taken from the provider's label;
4. the local score reaches the required tier (default **R4**);
5. the receipt's inclusion proof verifies against its signed tree head,
   under the log public key you pass;
6. the source commit the binary was compiled from matches the attested one.

Miss any of these and wallet creation fails with the reasons listed. A
custody wallet that cannot show its evidence has no business existing.

`--trusted-provider` is **required**: you must name whose *observations*
you are consuming. You are never asked to trust their verdicts.

### You hold the ruler

The allowed-axioms lists the gate checks against are a **requirements
card** that ships in *your* tooling ([the ed25519
profile](src/pacta/profiles/ed25519.py)) — small enough to read over
coffee, re-derivable from the attested repos' own docs and check
scripts, and replaceable with a card you write yourself from first
principles. Verdicts are re-derived against *your* copy, name by name;
the provider's labels are ignored. If your card is stricter than
today's supply (e.g. "SHA-512 itself proven"), the gap is itemized and
your options are honest: accept a named line item, walk away, or prove
the missing piece and enter it into the log — *if your ruler is
stricter than our supply, your ruler is our roadmap.* The full
walk-through is
[lecture 11](notebooks/11_the_customers_eye_view.ipynb).

---

## Quickstart

```bash
# 0. one-time: build the dogfood signer + the four quorum members
pacta dogfood-build --source <…>/curve25519-dalek-source
pacta wallet build-quorum --sources-root <…>/sources     # dalek anza risc0 betrusted

# 1. fetch fresh evidence for each fork from the live log
for c in dalek anza risc0 betrusted; do
  pacta log-fetch --url https://ltl.zkdefi.org \
    --component ${c}-ed25519-verified --out-dir ./evidence
done

# 2. create the wallet (R4 gate)
pacta wallet init --wallet ./my-warden --evidence ./evidence \
  --log-public-key ./log.pub --trusted-provider local-pacta-provider

# 3. inspect
pacta wallet status --wallet ./my-warden
pacta wallet card   --wallet ./my-warden          # the self-proving custody card

# 4. serve the agent-native surface
pacta wallet mcp --wallet ./my-warden             # stdio JSON-RPC MCP server
```

---

## The custody cockpit (human surface, read-only)

`pacta wallet cockpit --wallet <dir>` (or `--demo` for a throwaway,
custody-inert wallet to explore from zero) serves a local web UI
organized as a **bridge with six role stations** — Proposer, Quorum
bench, Operator (with an on-demand liveness board probing every public
service and local repo), Cryptographer, Architect, Newcomer — over
shared evidence instruments: posture (verdict banner, latch, ledger
chain re-verified, pinned quorum), the airgap signature queue (observed,
never operated), the incident and refusal browser, a receipt inspector
driven by the deployed verifier, the estate map, and a plain-language
guide with a full glossary. Three test-enforced laws: the design law (it
renders recomputed evidence with provenance lines, never cached status;
it cannot approve, sign, unlatch, or modify custody state — byte-level
read-only guarantee in `tests/test_walletui.py`), the UX law (every page
explains itself — verdict in words, per-panel "how to read this"
expanders, jargon linked to the `/guide` glossary), and the crew law
(each station states its mission, duties as runnable commands — the
no-AI drill — its "never" list, and explicit handoffs; roles stay
distinct). Details: [docs/cockpit.md](docs/cockpit.md).

## Agent-native surface (MCP)

`pacta wallet mcp` speaks MCP over stdio JSON-RPC. Eight outcome-first
tools with read-only/destructive annotations; strict input schemas;
results carry evidence; errors are structured objects that include the
signed refusal receipt, never prose. Tool classes are rate-limited
(custody 30/min, verify 120/min, liveness 240/min).

| tool | does |
|---|---|
| `wallet_status` | custody posture: members/tiers, latch, ledger head + chain integrity, counts |
| `verify_inbound` | run the quorum on (payload, signature, public_key); unanimity or a classified incident |
| `request_signature` | intent-bound outbound signing through the firewall; refusal object on any gate |
| `custody_card` | the self-proving card (embedded inclusion proofs; recompute, don't believe) |
| `posture_challenge` | nonce → firewalled, signed posture attestation with the quorum trail |
| `list_incidents` | divergences and quarantines, newest-first |
| `explain_refusal` | fetch a refusal receipt by index (or latest) |
| `airgap_pending` | parked gap-signing requests and whether the device answered |

Refusal codes (every refusal names one): `EVIDENCE_REQUIRED`,
`POLICY_DENIED`, `CUSTODY_LATCHED`, `EVIDENCE_STALE`, `MALFORMED_INTENT`,
`SIGNER_UNAVAILABLE`, `FIREWALL_QUARANTINE`, `PENDING_AIRGAP`,
`RATE_LIMITED`.

### The custody card is self-proving

Unlike an A2A agent card that you take on the operator's signature, the
warden card embeds, per member, the transparency-log **inclusion proof**
and **signed tree head**. A counterparty recomputes the Merkle roots and
checks the STH signature against the log key it already pins — trust by
recomputation, not by assertion. See `verify_posture_attestation` and the
log's own `verify.py` for the ~40-line client side.

---

## The spending policy (POLICY_DENIED)

Optional `policy.json` in the wallet directory - the rules you would give
a teenager with a debit card, checked before the signer ever runs:

```json
{
  "outbound": {
    "max_amount_per_request": 100.0,
    "max_amount_per_day": 500.0,
    "counterparty_allowlist": ["alice"],
    "counterparty_denylist": ["mallory"]
  },
  "identities": { "warden": { "max_amount_per_request": 10.0 } },
  "ledger": { "rotate_at": 100000 }
}
```

Amount rules bind on `intent.amount`; list rules bind on
`intent.counterparty` - policy makes those fields **mandatory**, so a
request that omits them is refused, never waved past. Daily ceilings sum
the released amounts in the ledger's last 24 hours per identity.
Per-identity overrides win over `outbound` defaults. No `policy.json`
means unrestricted (and `wallet_status` says so). `pacta wallet policy
--wallet <dir> --init-template` writes a starter file.

## Surface controls and the ledger's diet

The MCP layer rate-limits by tool class (custody 30/min, verify 120/min,
liveness 240/min) so a hostile counterparty cannot grind the signer or
bloat the audit trail; rate refusals are surface events, not custody
events, and are not ledgered. The ledger itself appends in O(1) (only
the tail is read, under a dedicated lock file, fsynced) and rotates into
hash-chained archive segments at `ledger.rotate_at` entries -
`verify-ledger` walks the whole chain across segments back to genesis.

## warden-treasury (Solana)

`pacta wallet treasury-verify` takes a wire-format Solana transaction
(from a file, or fetched by signature via `--rpc-url`), parses it locally
(stdlib; legacy and v0), and quorum-verifies **every required signature**
over the exact message bytes - including through the `anza` member, the
certificate-covered verify path of the code Solana validators run. The
RPC is demoted from oracle to bandwidth: it can withhold transactions
(the verdict names this completeness gap explicitly), but it cannot
manufacture one the quorum will accept. Every check lands in the ledger
with a treasury context.

## The signing firewall (verify-after-sign)

Outbound is: **intent → sign → firewall → release**.

1. **intent** — a structured envelope whose `purpose` is recorded (the
   ledger stores *why*, not only *what*) and whose `payload_sha256` binds
   the request to exact bytes.
2. **sign** — either the local dogfood signer or the airgap/Precursor
   signer (seed never on this host; request parked in `airgap/outbox`,
   response read from `airgap/inbox`).
3. **firewall** — the fresh signature faces the full quorum. This is the
   textbook fault-injection countermeasure: a glitched or tampered signer
   is caught before anything leaves the building.
4. **release** — only unanimity releases. A rejected self-signature is
   **quarantined, never returned**, and custody **latches**.

A latched wallet refuses all outbound with `CUSTODY_LATCHED`, and — by
design — its refusals arrive **unsigned**: a wallet that no longer trusts
its own boundary does not certify its apologies. `pacta wallet unlatch
--note "<why>"` is a deliberate operator act; the note is recorded
permanently in the ledger next to the latch it releases.

---

## Divergence taxonomy

The forks' accept() predicates are *allowed* to differ only on documented
degenerate inputs (anza rejects `A = 0` and a legacy excluded-small-order-
`R` list). warden fails closed regardless; the taxonomy only grades the
alarm:

| classification | when | verdict | incident |
|---|---|---|---|
| `unanimous-accept` | all accept | accept | — |
| `unanimous-reject` | all reject | reject | — |
| `semantic-edge` | disagree AND a documented edge flag applies | reject | note |
| `unexplained` | disagree with no explanation (or a member errored) | reject | **tamper → latch** |

---

## Product lineup

warden ships as one core with four production-ready deployment profiles —
see [docs/products.md](docs/products.md). Operational docs: the attacker
matrix in [docs/threat-model.md](docs/threat-model.md) and the
[latch-recovery runbook](docs/runbook-latch.md). In one line each:

- **warden-solo** — a single agent's custody sidecar (local signer).
- **warden-airgap** — signing behind a Precursor/Betrusted hardware gap.
- **warden-treasury** — trust-minimized chain watching (re-verify with the
  chain's own proven verifier; the RPC is demoted to bandwidth).
- **warden-choir** — N wardens cross-witnessing each other's ledgers.
