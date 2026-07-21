# warden threat model

Who can attack the wallet, what each attacker can and cannot achieve, and
which control stops them. "Proven" below means certificate-covered by the
Lean corpus attested in the transparency log; everything else is named
trusted base. The honest summary first: **warden's strongest guarantees
are about deciding what to believe (inbound) and catching its own signer
lying (firewall); an attacker who fully owns the host owns the wallet.**

## Attacker matrix

| # | attacker controls | can achieve | cannot achieve | stopped / bounded by |
|---|---|---|---|---|
| 1 | the network path | delay, reorder, withhold traffic | forge an accepted authorization | quorum verification (proven); freshness policy bounds staleness |
| 2 | the RPC provider (treasury) | withhold transactions (completeness) | fabricate a transaction the wallet believes | quorum re-verification of every signature (proven); verdict notes the completeness gap explicitly |
| 3 | a counterparty agent | spam requests; submit garbage | drain funds; grind the ledger unboundedly | MCP rate limiter (surface control); intent binding; spending policy (POLICY_DENIED); refusals cheap, custody calls scarce |
| 4 | ONE quorum member binary on disk (swap/corrupt) | cause divergence | pass a forged signature (needs all four) | capsule hash-pin catches swap at assembly; unexplained divergence latches custody |
| 5 | the signing key (exfiltrated) | sign arbitrary payloads AS this wallet elsewhere | make THIS wallet release out-of-policy signatures | policy + intent gates still bind the wallet's own releases; key custody itself is trusted base — use the airgap profile when this attacker is in scope |
| 6 | the airgap channel (tampered device response) | return a wrong signature | get it released | the firewall: verify-after-sign through the quorum; wrong signature is quarantined and latches |
| 7 | the wallet host (root) | everything: edit ledger, replace binaries AND capsule, read keys | escape detection by an OFF-HOST copy of the ledger head | out of scope for on-host controls — this is the warden-choir rationale (cross-witnessed heads) and the airgap rationale (key not on host) |
| 8 | the log operator (LTL) | attest falsely that proofs re-check | change verdicts (consumers re-derive from cones); rewrite history unnoticed (append-only, witnessed) | observation-not-verdict; STH pinning; witness mirror |
| 9 | the wallet operator (insider) | unlatch carelessly; loosen policy.json | do either invisibly | latch/unlatch and policy live in artifacts; unlatch requires a note recorded permanently in the hash-chained ledger |

## What is proven vs. trusted, one line each

- **Proven** (Lean certificates, log-attested): the verify path of each of
  the four quorum members — field arithmetic through the full signature
  acceptance equation.
- **Trusted base**: the signing path (attested artifact, fenced by the
  firewall); SHA-512 (oracle); wire parsers in the forks (hypotheses) and
  the ~120-line Solana wire parser in treasury mode; the OS, filesystem,
  and Python runtime; compilers; key custody.
- **Deliberately absent**: reproducible builds, side-channel hardening
  (R5 frontier); ML-DSA (fail-closed — no proven implementation exists).

## The cockpit surface (attack surface note)

The custody cockpit (`pacta wallet cockpit`) adds a localhost-bound,
read-only HTTP surface. Its threat posture, stated plainly:

- **No mutating routes exist.** It cannot approve, sign, unlatch, or edit
  custody state; the test suite asserts byte-level wallet-directory
  identity across a full request sweep including POST. Custody-mutating
  acts are only ever printed as CLI commands for the human.
- **No authentication because there is nothing to operate** — but it binds
  `127.0.0.1` by default and must not be exposed: it *reads* wallet state,
  so exposure is an information-disclosure risk (posture, incidents,
  member fingerprints), not a custody-control risk.
- **It phones home never by default.** Outbound traffic happens only when
  the operator explicitly presses «Probe now» (liveness GETs) — page loads
  perform no network I/O.
- An attacker who can serve the operator a *fake* cockpit (host compromise,
  attacker #7) can lie to the human — which is the standing host-compromise
  boundary above, not a new one; the CLI (`pacta wallet status`,
  `verify-ledger`) remains the independent second surface.

## Design invariants the controls enforce

1. **Unanimity or nothing**: no majority voting; any divergence fails
   closed. A lone honest member is sufficient to block.
2. **A signature that failed the firewall never leaves the process** —
   quarantined bytes, latched custody.
3. **Nothing custody-relevant is un-ledgered**; nothing in the ledger can
   be edited without breaking the chain (single-flight lock, fsync,
   rotation with chained segments).
4. **Refusals are receipts**: machine-actionable, signed when the wallet
   still trusts its own boundary, deliberately unsigned when latched.
5. **Policy failures are named** (`POLICY_DENIED`), never silent, and
   policy rules make their inputs mandatory rather than waving through
   requests that omit them.
