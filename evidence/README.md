# Real Provider Evidence

Signed, transparency-logged attestations from a REAL guarded replay of the
four `saymrwulf/*-ed25519-verified` repositories (2026-07-06/07, ~30 min of
Lean re-checking per fork under `lean-guard` memory caps).

| File | What it is |
|---|---|
| `<fork>-ed25519.attestation.yaml` | Signed proof-check attestation: repo commit, environment, machine-protection block, and all 16 certificates with their OBSERVED axiom cones (the four apex tiers carry the fork's exact documented boundary) |
| `<fork>-ed25519.receipt.yaml` | RFC 9162-style inclusion receipt binding the attestation into the transparency log (tree size 8), with a consistency anchor |
| `provider.ed25519.pub` | The provider's public key (the PRIVATE key never leaves `provider/state/`, which is gitignored) |
| `log-metadata.json`, `latest-sth.yaml` | Log identity and the latest Signed Tree Head |
| `log-audit.txt` | Monitor self-check output (recomputed root matches the signed root) |

The log holds EIGHT leaves: entries 0-3 are the first run's attestations,
which honestly record an AUDIT FAILURE (two bugs in pacta's audit step,
since fixed - see the commit history); entries 4-7 are the definitive
16/16-proven attestations. An append-only trust ledger keeps its bad day.

Re-verify everything yourself (signature via the proven-path verifier if
built, STH pinning, freshness):

```bash
pacta receipt-verify \
  --attestation evidence/dalek-ed25519.attestation.yaml \
  --receipt evidence/dalek-ed25519.receipt.yaml \
  --log-public-key evidence/provider.ed25519.pub \
  --sth-store /tmp/my-pins.json --max-sth-age-seconds 604800
```
