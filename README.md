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
pacta agent --config examples/repos.yaml --repo-name dalek-ed25519-verified --offline-fixture --action build-library
pacta agent --config examples/repos.yaml --repo-name dalek-ed25519-verified --clone --run-axioms --action build-library --artifact-dir artifacts-live
pacta agent --claims claims.yaml --action build-wallet-demo
```

## Consequence Engine

`pacta agent` turns evaluation into an operational consequence.

- `build-library` requires `R3` by default. It builds a small Rust proof-gated component capsule under `artifacts/`. The capsule embeds the claim card and exposes whether downstream automation may use the component for lower-layer cryptographic code only.
- `build-wallet-demo` requires `R4`. An `R3` Ed25519 arithmetic claim will refuse this action and write a machine-readable denial artifact instead of building a wallet.

This is intentional. Arithmetic proof evidence can authorize a constrained lower-layer library decision, but it must not contaminate wallet, transaction, custody, or trading-agent risk scoring.

In live mode, `--clone --run-axioms` downloads the configured repository, replays the local Lean checks, runs the axiom audit, writes `claims.yaml` and `report.md`, and only builds the capsule if the resulting score satisfies the policy threshold. Failed replay is a hard consequence: no artifact is built.

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
