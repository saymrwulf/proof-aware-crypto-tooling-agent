# PACTA Proof Check Provider

This nested project is a prototype third-party proof-checking service. It reuses host Lean/Aeneas infrastructure, runs portable PACTA replay/audit checks, and emits signed attestation certificates.

It does not modify anything outside this repository. It may read configured toolchains such as `/Users/oho/GitClone/ClaudeCodeProjects/your-lean-project/aeneas-toolchain/env.sh`.

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

The resulting certificate can be consumed by `pacta` with `--attestation`, `--trust-attestation-provider`, and `--attestation-public-key`.

The private key must remain provider-side. Downstream agents only need the public key and a policy decision that the provider name is trusted.
