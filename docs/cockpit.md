# The custody cockpit — a read-only surface for the human operator

`pacta wallet cockpit --wallet <dir>` serves a local web UI
(default `http://127.0.0.1:8471`) over an existing warden wallet.
warden has always been agent-native (MCP) and CLI-native; the cockpit is
the third surface — for the human who ultimately answers for the money.

## The design law

**The cockpit renders evidence; it never asserts it.** Every panel is
recomputed at request time by the same functions the wallet itself uses
(`Wallet.posture()`, `Wallet.verify_ledger()`, directory listings,
`transparency.verify_receipt`), and every panel carries a provenance
line naming the function and the timestamp. Anything that cannot be
recomputed renders as a loud red FAILED-TO-VERIFY panel. There is no
cached green and no neutral gray — a cockpit that shows unverified green
lights would be the anti-warden.

## The read-only guarantee

The cockpit cannot approve, sign, unlatch, or modify custody state. It
calls only read paths; the one POST route (the receipt inspector) parses
submitted artifacts in memory and throwaway temp files, never near the
wallet directory. `tests/test_walletui.py` asserts this at the byte
level: a full request sweep, POST included, leaves every file in the
wallet directory hash-identical. Human approve/deny is deliberately NOT
here — that would be a custody-semantics change, which belongs to a
separate, explicitly reviewed milestone.

## The four views

| view | shows | recomputed by |
|---|---|---|
| **Posture** (`/`) | custody latch state, ledger head with full hash-chain re-verification, the pinned quorum members (backend, component, tier, source commit, binary hash), spending policy verbatim, incident/refusal counts | `Wallet.posture()` / `Wallet.verify_ledger()` |
| **Signature queue** (`/queue`) | parked airgap signing requests (outbox) and whether the device has answered (inbox) — observed, never operated | airgap outbox/inbox listing |
| **Incidents & refusals** (`/incidents`) | incident records and signed refusal receipts, verbatim, newest first | `incidents/*.json`, `receipts/*.json` |
| **Estate map** (`/estate`) | the whole endeavour — every repo, service, mirror, loop — with RUNTIME on every entity (always-on / on-demand / not-running / static) | rendering of ESTATE.md's model (drift-guarded by test) |
| **Receipt inspector** (`/inspect`) | paste an attestation + transparency receipt + log public key; the verdict, per-signature results, and diagnostics come verbatim from the deployed verifier | `pacta.transparency.verify_receipt` |

Every panel also states what it does **not** prove (e.g. the quorum
table says binary hashes are pinned but source-to-binary correspondence
is out of scope until reproducible builds).

## Serving

```bash
pacta wallet cockpit --wallet ~/my-wallet          # 127.0.0.1:8471
pacta wallet cockpit --wallet ~/my-wallet --port 9000
```

The server binds localhost by default and is not meant to be exposed;
there is no authentication because there is nothing to operate.
