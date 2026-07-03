# PACTA Proof Check Provider

This nested project is a prototype third-party proof-checking service. It reuses host Lean/Aeneas infrastructure, runs portable PACTA replay/audit checks, and emits signed attestation certificates.

It does not modify anything outside this repository. It may read configured toolchains such as `/Users/oho/GitClone/ClaudeCodeProjects/your-lean-project/aeneas-toolchain/env.sh`.

It can also maintain a local transparency log. The log is an RFC 9162-style Merkle accumulator over signed attestations. It emits Signed Tree Heads with Ed25519 today and records an ML-DSA/FIPS 204 signature slot as `unavailable` unless a real backend is present. Agents that require both signatures must reject such receipts.

## Commands

```bash
PYTHONPATH=src:provider/src python -m pacta_provider discover
PYTHONPATH=src:provider/src python -m pacta_provider init-key --key-dir provider/state/demo-provider
PYTHONPATH=src:provider/src python -m pacta_provider check \
  --config examples/repos.yaml \
  --repo-name dalek-ed25519-verified \
  --repo repos/dalek-ed25519-verified \
  --provider local-pacta-provider \
  --private-key provider/state/demo-provider/provider.ed25519.key \
  --public-key provider/state/demo-provider/provider.ed25519.pub \
  --out provider/out/dalek.attestation.yaml
```

Transparency log:

```bash
PYTHONPATH=src:provider/src python -m pacta_provider log-init \
  --log-dir provider/state/transparency-log \
  --provider local-pacta-provider \
  --public-key provider/state/demo-provider/provider.ed25519.pub

PYTHONPATH=src:provider/src python -m pacta_provider log-append \
  --log-dir provider/state/transparency-log \
  --attestation provider/out/dalek.attestation.yaml \
  --private-key provider/state/demo-provider/provider.ed25519.key \
  --public-key provider/state/demo-provider/provider.ed25519.pub \
  --out provider/out/dalek.receipt.yaml

PYTHONPATH=src:provider/src python -m pacta_provider log-sth \
  --log-dir provider/state/transparency-log \
  --private-key provider/state/demo-provider/provider.ed25519.key \
  --public-key provider/state/demo-provider/provider.ed25519.pub
```

The resulting certificate can be consumed by `pacta` with `--attestation`, `--trust-attestation-provider`, and `--attestation-public-key`.

The receipt can be consumed with `--transparency-receipt`, `--transparency-log-public-key`, and `--require-transparency-receipt`.

The private key must remain provider-side. Downstream agents only need the public key, the inclusion receipt, and a policy decision that the provider name/log key is trusted.
