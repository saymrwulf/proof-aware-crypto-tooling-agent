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

## Tests

```bash
python -m pytest            # with pytest installed
python3 scripts/mini_pytest.py   # dependency-free fallback runner (same suite)
```

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
pacta doctor --config examples/repos.yaml --repo-name dalek-ed25519-verified
pacta claims --config examples/repos.yaml --repo-name dalek-ed25519-verified --offline-fixture --out claims.yaml
pacta audit --repo ./repos/dalek-ed25519-verified
pacta lean-check --repo ./repos/dalek-ed25519-verified
pacta report --claims claims.yaml --out report.md
pacta score --claims claims.yaml
pacta receipt-verify --attestation provider/out/dalek-ed25519.attestation.yaml --receipt provider/out/dalek-ed25519.receipt.yaml --log-public-key provider/state/local-provider/provider.ed25519.pub
pacta agent --config examples/repos.yaml --repo-name dalek-ed25519-verified --offline-fixture --action build-library
pacta agent --config examples/repos.yaml --repo-name dalek-ed25519-verified --clone --run-axioms --action build-library --artifact-dir artifacts-live
pacta agent --claims claims.yaml --action build-wallet-demo
pacta agent --config examples/repos.yaml --repo-name dalek-ed25519-verified --attestation examples/dalek-ed25519.attestation.yaml --trust-attestation-provider example-proof-checker.invalid --action build-library
```

## Curriculum Notebooks

The `notebooks/` directory contains a zero-to-hero teaching sequence for undergraduate students moving toward research-grade assurance engineering:

- `00_course_map.ipynb`: course structure, prerequisites, assessment model, references.
- `01_threat_model_and_truth_boundary.ipynb`: threat model, theorem boundaries, exclusions.
- `02_claim_cards_and_risk_model.ipynb`: claim card schema and R0-R5 scoring.
- `03_lean_replay_and_axiom_audit.ipynb`: replay versus transpilation, Lean invocation, axiom audits.
- `04_proof_hygiene_and_boundaries.ipynb`: `sorry`, local axioms, trivial targets, manifest coverage.
- `05_third_party_attestation_provider.ipynb`: provider trust transformation and signed attestations.
- `06_merkle_transparency_logs.ipynb`: RFC 9162-style Merkle proofs, STHs, Ed25519/ML-DSA policy.
- `06a_provider_build_the_log.ipynb` / `06b_agent_verify_inclusion.ipynb`: the MIRRORED PAIR - one provider (builds, Lean-verifies, signs with the merkleized library, self-checks its own inclusion), many agents (verify inclusion from scratch in ~25 lines, no Lean); the domain separation is the design and the lecture structure mirrors it.
- `07_agent_consequences.ipynb`: receipt-gated artifact builds and wallet-denial policy.
- `08_capstone_research_program.ipynb`: audit the shipped R4 evidence; design the R5 discharge plan.
- `09_dogfood_verified_crypto.ipynb`: the proven-path verifier in the agent's own loop; hybrid-PQC posture.

The course states and keeps a "ratchet rule": every load-bearing idea runs twice - napkin scale, then real scale - and every pair is executable in the notebook.

The notebooks are committed without execution output. They can be opened in Jupyter, VS Code, or any notebook reader. They import `pacta` directly from this repository and avoid external notebook-only dependencies.

## Consequence Engine

`pacta agent` turns evaluation into an operational consequence.

- `build-library` requires `R3` by default. It builds a small Rust proof-gated component capsule under `artifacts/`. The capsule embeds the claim card and exposes whether downstream automation may use the component for lower-layer cryptographic code only.
- `build-wallet-demo` requires `R4`. An `R3` Ed25519 arithmetic claim will refuse this action and write a machine-readable denial artifact instead of building a wallet.

This is intentional. Arithmetic proof evidence can authorize a constrained lower-layer library decision, but it must not contaminate wallet, transaction, custody, or trading-agent risk scoring.

In live mode, `--clone --run-axioms` downloads the configured repository, replays the local Lean checks, runs the axiom audit, writes `claims.yaml` and `report.md`, and only builds the capsule if the resulting score satisfies the policy threshold. Failed replay is a hard consequence: no artifact is built.

## Verifier Bootstrap

Some verified repositories rely on a pinned Aeneas Lean project, usually exposed by an environment script such as `~/aeneas-toolchain/env.sh`. `pacta` can use that environment without running extraction:

```bash
pacta doctor --config examples/repos.yaml --repo-name dalek-ed25519-verified
pacta agent --config examples/repos.yaml --repo-name dalek-ed25519-verified --clone --run-axioms --action build-library
```

The configured defaults are:

- `env_script: ~/aeneas-toolchain/env.sh`
- `lean_project_dir: $AENEAS_HOME/backends/lean`

If those are missing, the result is `R0` for local replay because this machine lacks verifier capability. That is different from saying the theorem is false. It means the agent cannot trust the repository from local machine-checked evidence yet.

## Third-Party Attestation

For agents that should not build the full Lean/Aeneas environment locally, `pacta` also supports an attestation lane. A specialized proof-checking service can replay the proofs in its own controlled environment and publish a certificate describing:

- repository URL and commit,
- theorem/certificate names,
- observed axioms,
- Lean/toolchain environment,
- service identity and signature metadata.

The agent can consume that certificate only when the provider is explicitly trusted:

```bash
pacta agent --config examples/repos.yaml \
  --repo-name dalek-ed25519-verified \
  --attestation examples/dalek-ed25519.attestation.yaml \
  --trust-attestation-provider example-proof-checker.invalid \
  --allow-unsigned-attestation \
  --action build-library
```

This changes the trusted base. The agent is no longer trusting local Lean replay; it is trusting the proof-checking service, its environment, signing key custody, and log retention. Without an explicitly trusted provider, attestation evidence scores `R0`.

The included `examples/dalek-ed25519.attestation.yaml` is an unsigned schema/demo fixture and requires `--allow-unsigned-attestation`. Real provider certificates should be signed and consumed with `--attestation-public-key`.

## Transparency-Logged Attestations

Standalone signatures prove who signed an attestation, but they do not make the provider accountable for equivocation or silent replacement. The nested provider can also append attestations to a local RFC 9162-style Merkle transparency log and issue inclusion receipts.

The log uses:

- `RFC9162_SHA256` Merkle leaf/node hashing with `0x00` leaf and `0x01` node domain separation.
- Signed Tree Heads over canonical JSON tree-head payloads.
- OpenSSL Ed25519 signatures today.
- An explicit `ML-DSA-65` / FIPS 204 signature slot that is `unavailable` unless the host has a real backend. If an agent policy requires both signatures, verification fails closed.

Example:

```bash
PYTHONPATH=src:provider/src python -m pacta_provider log-init \
  --log-dir provider/state/transparency-log \
  --provider local-pacta-provider \
  --public-key provider/state/local-provider/provider.ed25519.pub

PYTHONPATH=src:provider/src python -m pacta_provider log-append \
  --log-dir provider/state/transparency-log \
  --attestation provider/out/dalek-ed25519.attestation.yaml \
  --private-key provider/state/local-provider/provider.ed25519.key \
  --public-key provider/state/local-provider/provider.ed25519.pub \
  --out provider/out/dalek-ed25519.receipt.yaml

pacta receipt-verify \
  --attestation provider/out/dalek-ed25519.attestation.yaml \
  --receipt provider/out/dalek-ed25519.receipt.yaml \
  --log-public-key provider/state/local-provider/provider.ed25519.pub
```

Agents can require the receipt before building anything:

```bash
pacta agent \
  --config examples/repos.yaml \
  --repo-name dalek-ed25519-verified \
  --repo repos/dalek-ed25519-verified \
  --attestation provider/out/dalek-ed25519.attestation.yaml \
  --trust-attestation-provider local-pacta-provider \
  --attestation-public-key provider/state/local-provider/provider.ed25519.pub \
  --transparency-receipt provider/out/dalek-ed25519.receipt.yaml \
  --transparency-log-public-key provider/state/local-provider/provider.ed25519.pub \
  --require-transparency-receipt \
  --action build-library
```

To demand post-quantum log signatures as well:

```bash
pacta receipt-verify \
  --attestation provider/out/dalek-ed25519.attestation.yaml \
  --receipt provider/out/dalek-ed25519.receipt.yaml \
  --log-public-key provider/state/local-provider/provider.ed25519.pub \
  --require-signatures both
```

On a host without ML-DSA support, that command should fail. That is intentional. The system records the missing capability as a deployment blocker instead of treating the Ed25519 signature as quantum-robust.

## Nested Proof-Check Provider

This repository includes a nested provider prototype under `provider/`. It searches read-only under your home/GitClone tree for reusable Lean/Aeneas infrastructure, runs the proof replay, signs the result with OpenSSL Ed25519, and emits an attestation.

```bash
PYTHONPATH=src:provider/src python -m pacta_provider discover --root ~/GitClone
PYTHONPATH=src:provider/src python -m pacta_provider init-key --key-dir provider/state/local-provider
PYTHONPATH=src:provider/src python -m pacta_provider check \
  --config examples/repos.yaml \
  --repo-name dalek-ed25519-verified \
  --repo repos/dalek-ed25519-verified \
  --provider local-pacta-provider \
  --private-key provider/state/local-provider/provider.ed25519.key \
  --public-key provider/state/local-provider/provider.ed25519.pub \
  --env-script /path/to/aeneas-toolchain/env.sh \
  --lean-project-dir '$AENEAS_HOME/backends/lean' \
  --out provider/out/dalek-ed25519.attestation.yaml

pacta agent \
  --config examples/repos.yaml \
  --repo-name dalek-ed25519-verified \
  --attestation provider/out/dalek-ed25519.attestation.yaml \
  --trust-attestation-provider local-pacta-provider \
  --attestation-public-key provider/state/local-provider/provider.ed25519.pub \
  --transparency-receipt provider/out/dalek-ed25519.receipt.yaml \
  --transparency-log-public-key provider/state/local-provider/provider.ed25519.pub \
  --require-transparency-receipt \
  --action build-library
```

This is the intended trust transformation: local agents can avoid constructing the full verifier environment, but they must explicitly trust the provider identity and verification key.

## Real Evidence (shipped)

`evidence/` contains signed, transparency-logged attestations from a REAL
guarded replay of all four verified repositories: 16/16 certificates proven
per fork with boundary-exact axiom cones, pinned to exact repo commits,
machine-protected by `lean-guard` throughout (~30 min of Lean kernel
re-checking per fork, done ONCE - verifying the signature + inclusion
receipt afterwards takes milliseconds, which is the entire point of the
provider model). The log's first four leaves honestly record a failed audit
run (two pacta bugs, fixed and documented); the ledger keeps its history.
See `evidence/README.md` to re-verify everything yourself.

## The Online Log and the Published Mirror

The log has three synchronized faces, transport being orthogonal to trust:

1. **Files** (`evidence/`): self-contained receipts, verifiable offline.
2. **Git mirror** ([saymrwulf/lean-transparency-log](https://github.com/saymrwulf/lean-transparency-log), mirrored on Forgejo):
   every leaf, every signed tree head (the WITNESS CHANNEL - all cloners
   see the same heads), per-component receipts, the provider public key,
   and a standalone stdlib-only `verify.py`. Anyone: `python3 verify.py --all`.
3. **HTTP service** (deployed at `zkdefi.org/lean-transparency-log`, see
   `DEPLOY.md`): read-only CT-style endpoints + customer docs. The web
   process never touches private keys - heads are signed offline; a
   compromised server can withhold or replay (pinning + freshness detect
   both) but never forge.

```bash
PYTHONPATH=src:provider/src python -m pacta_provider serve --log-dir ... --base-path lean-transparency-log
PYTHONPATH=src:provider/src python -m pacta_provider log-publish --log-dir ... --git-dir <mirror clone> --public-key <pub>
pacta log-fetch   --url https://zkdefi.org/lean-transparency-log --component dalek-ed25519-verified --out-dir fetched
pacta sth-refresh --url https://zkdefi.org/lean-transparency-log --sth-store pins.json --log-public-key <pub>
pacta witness-audit --published-dir <clone of lean-transparency-log> --log-public-key <pub>
```

## Split-View Defense (STH Pinning)

Standalone receipt verification cannot detect a provider maintaining two log views. `pacta` keeps a local STH pin store:

```bash
pacta receipt-verify ... --sth-store state/sth-store.json [--consistency-proof proof.yaml] [--max-sth-age-seconds 86400]
pacta agent ... --sth-store state/sth-store.json ...
PYTHONPATH=src:provider/src python -m pacta_provider log-consistency --log-dir ... --from-size N   # proofs for older pins
PYTHONPATH=src:provider/src python -m pacta_provider log-audit --log-dir ...                        # monitor self-check
```

Unknown log: pin on first use (recorded as trust-on-first-use). Same tree size: the root must match the pin - a mismatch is named EQUIVOCATION and rejected forever. Larger tree: a consistency proof from the pinned size is required (receipts embed a from-previous anchor whose root is itself checked against the pin). Smaller tree: rollback, rejected. `--max-sth-age-seconds` additionally rejects stale or future-dated tree heads.

## Dogfood Verified Cryptography

`pacta` can verify its own evidence signatures through the PROVEN code path - a small Rust binary built from the pinned proven source workspace (the exact commit the dalek certificates pin, serial backend pinned as the verified extraction pins it):

```bash
pacta dogfood-build --source ~/GitClone/FormalVerification/sources/curve25519-dalek-source
pacta dogfood-status
pacta receipt-verify ... --require-verified-verifier   # fail closed unless the proven path ran
```

The backend that actually verified each signature (`verified-dalek-serial` or the `openssl` fallback) is recorded in receipts' signature statuses and attestation evidence; the fallback is never silent. A provenance sidecar records the source commit, backend cfg, and the honest coverage note (the certificates cover the extraction image of this verify path; SHA-512 and the wire glue remain the documented trusted base). ML-DSA is deliberately NOT dogfooded: no proven implementation exists, so the slot stays fail-closed - the hybrid-PQC posture is one proven-classical signature plus one required-but-honest post-quantum slot.

## Truth Boundary

The Ed25519 repositories should not be marketed as fully verified wallets. Since 2026-07-06 the strongest claim is substantial and theorem-bound:

Every ed25519 repository in the corpus carries Lean-checked certificates for field arithmetic over `F_p` (`p = 2^255 - 19`), the complete twisted Edwards laws, full scalar arithmetic mod l, encoding/decoding canonicality with constructive decompression, and a FOUR-TIER signature apex culminating in the full lift: the extracted verifier accepts iff the signature's R decompresses to a valid on-curve point equal to `[k](-A) + [s]B`. Each apex tier's axiom cone is pinned to EXACTLY the fork's documented SHA-512/wire-format boundary by that repository's own check script (`pacta` mirrors those boundary sets per fork and re-checks observed cones against them - the authority is always the repo's button).

`pacta` treats these as out of scope (they are the theorems' documented trusted base or genuinely unproven):

- SHA-512 itself (an opaque oracle in the apex theorems - no properties assumed).
- Wire parser/filter byte-level specs (their outcomes are hypotheses in the apex tiers).
- Signing-side correctness (key generation, nonces, the signer).
- Rust compiler correctness.
- Charon/Aeneas translation faithfulness.
- Side-channel resistance.
- SIMD, AVX, hardware, zkVM, accelerator, or syscall paths (extraction pins the serial path).
- Wallet policy, transaction construction, RPC, chain, oracle, market, and LLM decision safety.

## Risk Levels

- `R0`: Unknown or untrusted. No usable evidence.
- `R1`: Tests, audits, or informal claims only.
- `R2`: Formal model exists, but it is incomplete, weakly tied to production code, or major proof gaps remain.
- `R3`: A specific lower-layer implementation artifact is Lean-checked for a specific backend and theorem boundary.
- `R4`: End-to-end primitive proof covers public API, parsing/encoding, scalar arithmetic, hashing interface, signature equation, rejection rules, and implementation boundary.
- `R5`: `R4` plus reproducible production builds, compiler/build assurance, side-channel analysis, hardware/KMS/MPC integration, and operational controls.

Expected classifications: the arithmetic pair alone reaches `R3`. The full configured set - arithmetic, scalars, encoding/decoding, and the four apex tiers with boundary-exact cones - reaches `R4`, always with explicit residual blockers (the SHA-512 oracle, hypothesis-parametric parses, translation faithfulness, missing side-channel/build assurance). `R5` remains future work. The `build-wallet-demo` gate therefore genuinely opens on real evidence now - and still emits only a policy scaffold, never a production wallet.
