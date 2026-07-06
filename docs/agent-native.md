# Agent-native design notes — warden, the verified-custody wallet

Field research (July 2026) distilled into the design decisions behind
`warden`, pacta's custody product. Sources at the bottom; each decision
names what it borrows and what it deliberately does differently.

## The field, in one paragraph

"Agent experience" (AX) graduated in 2026 from a Netlify-blog coinage to
job postings and VC theses: the discipline of making products that
*agents* can discover, evaluate, and operate without a human in the
loop. The load-bearing standards: **MCP** (tools/resources over
JSON-RPC; the de-facto agent tool bus), **A2A** with its
`/.well-known/agent-card.json` discovery (v1.0 added *signed* agent
cards, plus the AP2 payments extension whose Intent/Cart/Payment
mandates are W3C Verifiable Credentials), **x402** (the HTTP 402
payment-required handshake; >150M agentic stablecoin transactions since
2025), **ERC-8004** (on-chain identity/reputation/validation registries
for agents), and **llms.txt** (machine-readable site manifests; ~10%
adoption, Shopify default). The AX community's design canon: outcome
-first tools, machine-parseable errors, deterministic interfaces,
progressive scoping, capability metadata at well-known paths.

## Where every 2026 agent wallet puts its trust — and where we put ours

Turnkey evaluates signing policy inside AWS Nitro enclaves. Privy gates
every signature through a policy engine on its servers. Coinbase
AgentKit ships session keys with TEE-enforced spending caps. The common
shape: **policy is enforced by trusted hardware plus a vendor**. The
verification of the *cryptography itself* is nowhere in the trust
story — it is assumed.

`warden` inverts the foundation. Its acceptance boundary is a **quorum
of independently compiled Ed25519 verifiers, each built from source
whose correctness certificates are machine-checked in Lean 4 and
replay-attested in a public RFC 9162 transparency log**. Classic
N-version programming fails because independent implementations share
design bugs; here each member is *proven* to decide
`accept ⇔ decompress(R) = [k](−A) + [s]B`, so members cannot disagree
about semantics on the proven domain — runtime disagreement is
evidence of build corruption, memory fault, or tampering, and is
treated as an incident, not an anomaly to shrug at. No enclave is
required, and nothing stops you adding one; proofs and TEEs compose.

The honest asymmetry, stated everywhere the product speaks: theorems
cover the **verification** path. Signing is declared trusted base
(mitigated by the firewall below), SHA-512 is an oracle, wire parsing
is hypothesis, side channels and reproducible builds are the R5
frontier. ML-DSA remains fail-closed: no proven implementation exists,
so the PQC slot reports `unavailable` rather than pretending.

## The four semantic edges (why divergence needs a taxonomy)

The four proven forks do not promise identical verdicts on *all* inputs
— each fork's theorem characterizes *its own* accept():

- **anza** checks `A ≠ 0` and rejects a legacy list of excluded small
  -order `R` values; its certificate-covered entry point is
  `verify_sha512` (≡ `verify_dalek`), *not* the default `verify()`,
  which implements different (Zebra-lineage) semantics.
- **dalek / risc0 / betrusted** follow upstream `VerifyingKey::verify`
  canonical semantics.

So quorum divergence is classified, never ignored:

| class | example trigger | wallet behavior |
|---|---|---|
| `unanimous-accept` | honest signature | accept, ledger entry |
| `unanimous-reject` | bad signature | reject, ledger entry |
| `semantic-edge` | small-order R on the legacy list, zero A | **reject** + incident (severity: note) |
| `unexplained` | anything else | **reject** + incident (severity: tamper) + custody latch |

Fail-closed is unconditional: acceptance requires unanimity. The
taxonomy only grades the alarm.

## Agent-native surfaces (what we borrowed, what we sharpened)

1. **MCP server** (`warden-mcp`, stdio JSON-RPC, stdlib-only). Follows
   the AX canon: outcome-first tools (`verify_inbound`,
   `request_signature`, `posture`, `custody_card`, `incidents`,
   `explain_refusal`), strict schemas, and errors that are
   machine-actionable objects (`code`, `missing`, `remediation`) rather
   than prose.
2. **The custody card** — A2A's `/.well-known/agent-card.json` pattern,
   sharpened: A2A v1.0 cards are *signed*; warden's card is
   **self-proving**. It embeds the LTL inclusion proofs for the exact
   attested sources its quorum binaries were compiled from, the pinned
   STH, binary hashes, and the live latch state. A counterparty does
   not have to believe the card's adjectives; it can recompute the
   Merkle roots.
3. **Proof-of-posture (PoP) challenge** — a counterparty sends a nonce;
   warden returns a signed posture attestation (capsule hash, quorum
   membership, ledger head, incident count, STH pin age) whose
   signature has itself passed the outbound firewall, with the
   firewall's quorum trail attached. A heartbeat you can audit.
4. **Refusal receipts** — the inverse of x402. x402 answers "402
   Payment Required" with a structured way to pay; warden answers
   refusals with `EVIDENCE_REQUIRED` (or `POLICY_DENIED`,
   `CUSTODY_LATCHED`, …): a signed, hash-chained receipt naming exactly
   which artifact is missing (e.g. "LTL inclusion proof at tier ≥ R4
   for your verifier") and how to remedy. The requesting agent can
   *prove to its principal* that it was refused, by whom, and why — an
   auditable conscience.
5. **Intent envelopes** — an AP2 homage, honestly reduced: outbound
   signing requests carry a structured intent (purpose, constraints,
   payload digest) that is bound into the ledger entry next to the
   signature. Not W3C VCs; a documented, simpler binding that an
   auditor can walk.
6. **Evidence freshness as a liveness rule** — via pacta's STH pin
   store: if the wallet's view of the transparency log goes stale
   beyond policy, outbound custody refuses until refreshed. A wallet
   that declines to outlive its evidence.

## Roadmap ideas that survived contact with honesty (not built yet)

- **x402 lane**: answer 402 challenges and pay per-call — after the
  outbound path earns more than trusted-base status.
- **zk verification receipts**: run the proven verifier inside the
  RISC Zero guest (the risc0 fork *is* the proven code) and hand
  counterparties STARK receipts of verified verification.
- **ERC-8004 registration**: put the custody card's hash in the
  validation registry; the LTL becomes an off-chain validator.
- **The choir**: N wardens cross-witnessing each other's ledger heads
  — gossip-audited custody, the same witness pattern the LTL already
  uses for its STHs.

## Sources

- https://agentexperience.ax/ and https://agentexperience.ax/articles/
- https://a2a-protocol.org/latest/topics/agent-discovery/
- https://ap2-protocol.org/ (mandates as W3C VCs; v0.2.0 April 2026)
- https://x402.org/ and Chainalysis/Coinbase adoption reports (100M+
  transactions on Base, 69k active agents by Q2 2026)
- https://modelcontextprotocol.info/docs/best-practices/ and
  https://www.philschmid.de/mcp-best-practices
- https://github.com/erc-8004/erc-8004-contracts
- llms.txt state-of-adoption surveys (SE Ranking 300k-domain study;
  Shopify default rollout, April–May 2026)
- Agent-wallet landscape: Turnkey (Nitro-enclave policy engine), Privy
  (server-wallet policies), Coinbase AgentKit (session keys, TEE caps),
  Crossmint comparison, ERC-4337/7710/7715 session-scoping posts.
