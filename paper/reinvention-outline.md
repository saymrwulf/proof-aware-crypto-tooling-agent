# Paper reinvention — working outline (post second ePrint rejection)

Status: approved direction (operator order 2026-07-16: "entry 13 and
paper reinvention"); this outline is the committed starting point for
the full rewrite. Diagnosis it responds to: both external analyses
(GPT-5.6 rejection post-mortem; round-6 reviewer aside) converge on
POSITIONING, not correctness — five papers compressed into one, the
novelty (trust decomposition) occupying less space than its supporting
machinery, and the honest "components unchanged" refrain reading as
"nothing new" in a thirty-second editorial skim.

## 0. The one sentence (everything else exists to support it)

> We define and instantiate a cryptographic distribution model for
> machine-checked correctness evidence, enabling lightweight consumers
> to obtain accountable assurance without executing the original
> verifier — and demonstrate it end to end with a deployed log that
> carries kernel-checked proofs of its own accountability machinery as
> an entry in itself.

The second clause is the only-this-paper claim; it becomes literally
true at entry 13 and the paper should be finalized AFTER that append so
the abstract can cite the live leaf.

## 1. Title candidates (working)

- "Accountable Distribution of Machine-Checked Correctness Evidence"
- "Transparency for Theorem Provers: Distributing Formal Verification
  to Consumers Who Cannot Replay It"
- (subtitle either way): "…with a deployed log that notarizes the
  proofs of its own machinery"

"The Lean Transparency Log" becomes the *system's* name, not the
paper's identity.

## 2. Inverted structure

1. **Problem.** Theorem provers solve the PRODUCTION of correctness
   evidence; nothing standard solves scalable DISTRIBUTION and
   CONSUMPTION by clients that cannot run the prover (no toolchain, no
   hours of replay, no trust in the operator's word). State it as the
   gap between "verified" and "verifiable by you."
2. **Model.** The trust decomposition, presented abstractly:
   (a) producer performs expensive deterministic verification once;
   (b) the result becomes a precise attestation object (subject commit,
   toolchain, certificates with exact assumption cones, scope);
   (c) a transparency structure supplies persistence, consistency, and
   equivocation-evidence; (d) consumers apply policy locally without
   executing the verifier; (e) the residual trust is enumerated, not
   waved at. Define the accountability property: misbehavior
   manufactures transferable evidence.
3. **Design space** (the section the old paper lacked). Position
   against: reproducible replay services; succinct proofs of proof
   checking (SNARKed kernels); checkpoint/cosigning committees;
   witness cosigning; downloadable proof artifacts; proof-carrying
   code; cached prover environments/containers. Axis of comparison:
   consumer cost, operator trust, accountability (evidence on
   misbehavior), incrementality, and what happens when the operator
   disappears. The log wins on accountability-per-consumer-cost; be
   honest where SNARKed checking would win (validity vs
   accountability) and why it is not yet practical for a full kernel.
4. **Instantiation: the LTL.** Lean 4 + Aeneas corpora as producers;
   Ed25519 heads signed by the dogfooded verified signer
   (self_inclusion); RFC 9162 accumulator; pin-store consumers.
   Compressed from old §4–5; the four ed25519 subject corpora become a
   TABLE + pointer to project documentation, not sections.
5. **Security of the instantiation.** The mechanized model (61
   certificates, single opaque-SHA-256 axiom, environment-derived audit
   surface); Theorems 1–3 + Prop 1 in one page each of STATEMENT (the
   proofs live in the repo; the paper sells the statements). Present
   gap 14/15 as a RESULT, not a confession: the model/deployment seam
   located, measured (3,867 one-sided divergences), fenced by pinned
   tests, and bridged by an explicitly stated operational invariant —
   this is what honest mechanization boundaries look like.
6. **Exhibit A: the log attests itself.** Entry 13 as the paper's
   demonstration: the accountability machinery's own proofs, carried by
   the machinery, verifiable end to end by one command from a stock
   toolchain. Include the leaf hash + head root; a reader can check
   inclusion in seconds.
7. **Deployment & consumers.** Live service; warden (quorum custody
   wallet) as the internal consumer; Swiss Post e-voting PoC as the
   prospective external consumer (dalek-family transport). Replay
   economics (measured ~1,800 s/fork) as the cost the model amortizes.
8. **Related work.** CT lineage (RFC 6962/9162, CONIKS, sigstore);
   optimistic-rollup analogy (accountability-over-validity; the
   fraud-proof reading of Theorem 3 — from
   ltl-accumulator-verified/docs/optimistic-accountability.md);
   proof-carrying code; reproducible builds/SLSA; in-toto.
9. **Limitations** = the 15-gap ledger, grouped (assumption base /
   scope lines / unmechanized bridge), each one sentence, pointer to
   the repo ledger.

## 3. What moves OUT of the paper

- Ed25519 corpus construction details → project docs / possible
  separate implementation report ("Paper C" in the GPT taxonomy).
- Curriculum, wallet internals, agent-native surfaces → out entirely.
- Appendix A/B verbatim-leaf material → shrink to one leaf excerpt
  (entry 13 itself, naturally).
- The §8 operational-history narrative → compress to the
  retrievability-decay paragraph + one table.

## 4. Sequencing & venues

1. Entry 13 lands (prerequisite for the abstract's second clause).
2. Rewrite per this outline (fresh tex, new title; old ltl.tex remains
   hosted as the system report at /paper — versioned, not erased).
3. arXiv (cs.CR) immediately for timestamp + citability.
4. Venue: CPP/ITP (mechanization framing) or SCORED/SecDev
   (supply-chain framing) or RWC talk (deployment framing) — decide
   after the rewrite settles which face leads.
5. All queued wording fixes (Lemma-2 specializations, fidelity =
   pinned families, §10(i)/(v), Remark 1, pinned-pair side condition)
   are ABSORBED by the rewrite rather than patched into the old text.

## 5. Success criterion

A hurried editor can answer "what is the contribution?" from the title
+ first paragraph alone, and the thought-experiment inversion holds:
remove any single supporting component (Lean, Ed25519, RFC 9162) and
the CLAIM survives; remove the trust-decomposition model and nothing is
left. That is the opposite polarity of the rejected manuscript.
