# PACTA Curriculum Notebooks

This directory contains a zero-to-hero teaching sequence for proof-aware cryptographic tooling.

Start with `00_course_map.ipynb`, then proceed in order. The notebooks are intentionally output-free in git. Run them from the repository root or from this directory; each notebook locates the repo root and imports `pacta` from `src/`.

The course teaches:

- theorem-boundary thinking,
- claim cards and residual risk,
- Lean replay and axiom audit concepts,
- proof hygiene,
- third-party proof-check provider trust,
- RFC 9162-style Merkle transparency logs,
- the mirrored provider/agent domain split (6a: one provider builds and dogfood-signs the log; 6b: many agents verify inclusion in ~25 lines, no Lean),
- receipt-gated agent consequences (including the R4 wallet gate, now reachable),
- split-view defense: STH pinning, consistency enforcement, freshness, monitoring,
- dogfood verified cryptography and the honest hybrid post-quantum posture,
- the verified-custody wallet (warden): a quorum boundary of four proven forks, the signing firewall, and the agent-native MCP surface,
- research roadmaps from R4 evidence toward R5 assurance.

This curriculum is not financial advice, not a trading bot, and not a wallet-building guide. It is a training path for engineers and researchers who need to evaluate formal-verification-enhanced cryptographic tooling without overclaiming.
