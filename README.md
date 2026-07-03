# proof-aware-crypto-tooling-agent

`pacta` is a local CLI prototype for interpreting formal-verification evidence in cryptographic tooling. It is not a trading bot, does not move funds, and does not make financial decisions.

The immediate corpus is the `saymrwulf/*-verified` family of repositories. The shipped Lean files are treated as the verification artifact. This project intentionally does not run Charon, Aeneas, extraction, or Rust-to-Lean regeneration.

## Purpose

An autonomous economic agent needs to answer a narrow question before trusting infrastructure:

> Does this theorem cover the exact code path that will protect my funds?

`pacta` helps answer that by replaying pure Lean checks where possible, auditing axioms and proof hygiene, generating machine-readable claim cards, and assigning residual-risk classifications with explicit exclusions.

## macOS / Apple Silicon

The prototype is written for Python 3.11+ and macOS on Apple Silicon. It does not assume GNU coreutils, Linux `free`, Linux `taskset`, GNU `timeout`, Docker, Nix, or x86_64.

Lean tooling is detected with `shutil.which("lean")` and `shutil.which("lake")`. If neither is available, `pacta` reports clear diagnostics and still supports offline claim-card generation and static hygiene scans.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

PyYAML is optional. Without it, `pacta` can still read the included simple YAML examples and JSON-compatible `.yaml` files.

## Commands

```bash
python -m pacta --help
pacta scan --config examples/repos.yaml
pacta claims --config examples/repos.yaml --repo-name dalek-ed25519-verified --offline-fixture --out claims.yaml
pacta audit --repo ./repos/dalek-ed25519-verified
pacta lean-check --repo ./repos/dalek-ed25519-verified
pacta report --claims claims.yaml --out report.md
pacta score --claims claims.yaml
```

## Truth Boundary

The Ed25519 repositories should not be marketed as fully verified wallets or fully verified Ed25519 end-to-end. The strongest current claim is lower-layer and theorem-bound:

For selected curve25519-dalek / Solana-Ed25519-family Rust code paths already transpiled into Lean, the repositories contain Lean-checked certificates for field arithmetic over `F_p`, `p = 2^255 - 19`, and complete twisted Edwards point-operation laws, under explicit invariants and backend constraints.

`pacta` treats these as out of scope unless separately proven:

- Full EdDSA signature verification.
- Complete Scalar52 arithmetic.
- SHA-512.
- Encoding, decoding, and canonicality.
- Rust compiler correctness.
- Charon/Aeneas translation faithfulness.
- Side-channel resistance.
- SIMD, AVX, hardware, zkVM, accelerator, or syscall paths.
- Wallet policy, transaction construction, RPC, chain, oracle, market, and LLM decision safety.

## Risk Levels

- `R0`: Unknown or untrusted. No usable evidence.
- `R1`: Tests, audits, or informal claims only.
- `R2`: Formal model exists, but it is incomplete, weakly tied to production code, or major proof gaps remain.
- `R3`: A specific lower-layer implementation artifact is Lean-checked for a specific backend and theorem boundary.
- `R4`: End-to-end primitive proof covers public API, parsing/encoding, scalar arithmetic, hashing interface, signature equation, rejection rules, and implementation boundary.
- `R5`: `R4` plus reproducible production builds, compiler/build assurance, side-channel analysis, hardware/KMS/MPC integration, and operational controls.

Expected first-pass classification: Ed25519 field plus Edwards point arithmetic can reach `R3` if configured certificates compile and the axiom audit is clean. Full Ed25519 signature verification remains `R2` or lower unless complete scalar, encoding, hashing, and signature certificates exist.
