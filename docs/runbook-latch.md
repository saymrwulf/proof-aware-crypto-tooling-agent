# Runbook: the custody latch fired

You are here because outbound custody is frozen and every signing request
returns `CUSTODY_LATCHED`. This is the wallet doing its job: an
unexplained quorum divergence or a firewall quarantine occurred, and the
wallet refuses to certify anything — including its own refusals, which
now arrive unsigned on purpose.

**Do not unlatch first. Diagnose first.** The latch is cheap; a released
forged signature is not.

## 1. Read what happened (2 minutes)

```bash
pacta wallet status --wallet <dir>          # latch reason + incident ref
cat <dir>/latch.json
cat <dir>/incidents/<ref>.json              # the full divergence trail
ls <dir>/quarantine/                        # any withheld signatures
pacta wallet verify-ledger --wallet <dir>   # is the history itself intact?
```

The incident file names, per quorum member, its verdict and its binary
hash at the moment of divergence. That table is your suspect list.

## 2. Classify (the incident file already did; check its work)

- `classification: semantic-edge` (severity `note`) — the input hit a
  documented degenerate class (small-order R, non-canonical s). This does
  NOT latch by itself; if you are latched, something else also happened.
- `classification: unexplained` (severity `tamper`) — members disagreed
  with no documented reason, or one errored. Assume fault or tampering
  until shown otherwise.

## 3. Investigate the three usual suspects, in order

1. **A corrupted/updated member binary.** Compare each member's current
   hash against the capsule:
   `sha256sum dogfood/state/quorum/pacta-verify-*` vs
   `capsule.json` → `members[].binary_sha256`. A mismatch on exactly the
   dissenting member is the common benign case (a rebuild happened);
   a mismatch you cannot explain is not benign.
2. **Hardware/memory fault.** Re-run the exact input from the incident
   file through the quorum (`payload_sha256`, `signature_hex`,
   `public_key_hex` are all recorded). A divergence that does not
   reproduce points at a transient fault; log that finding in the
   unlatch note.
3. **Actual tampering.** Divergence reproduces, hashes match the capsule,
   input is not a documented edge → treat the host as suspect: rebuild
   members from pinned sources on a machine you trust, re-run, compare.

## 4. Remediate

- Benign rebuild drift → rebuild all members (`pacta wallet
  build-quorum`), then **re-init or re-seal** the capsule so the pins
  match reality again.
- Transient fault → document it; consider the machine's RAM.
- Suspected tamper → do not unlatch on this host. Preserve the wallet
  directory (it is the evidence), stand up a fresh wallet from fresh
  builds + fresh evidence elsewhere.

## 5. Unlatch — a deliberate, recorded act

```bash
pacta wallet unlatch --wallet <dir> --note "<what happened, what you checked, why it is safe now>"
```

The note is permanent: it lands in the hash-chained ledger next to the
latch it releases, and shows up in every future audit. Write it for the
auditor you hope never needs it. An empty or lazy note defeats the
design; the CLI requires the flag, your discipline supplies the content.

## 6. Afterwards

Re-run a signing smoke test and confirm `unanimous-accept`; check
`pacta wallet status` shows `latched: false`, chain intact, and the
incident count where you expect it. If this wallet participates in a
choir, expect peers to ask about the head gap — that is the system
working.
