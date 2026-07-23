# Security note: RFC 9162 Step-7 terminal check restored in `verify_consistency`

**Date:** 2026-07-23
**Component:** `pacta.transparency.verify_consistency` (consumer-side consistency-proof verifier)
**Severity:** low (RFC-conformance defect; no exploit found through the honest pin-store flow)
**Vulnerable commit:** tagged `vulnerable/sn0-consistency-fd2f6ba`
**Status:** fixed; found by this project's own differential fidelity harness.

## What was wrong

RFC 9162 §2.1.4.2 Step 7 requires a consistency proof to satisfy three
conditions: both reconstructed roots must match the supplied roots, **and** the
new-size navigation counter `sn` must reach `0`. That last condition couples the
consumed proof length to the claimed tree sizes. The deployed
`verify_consistency` implemented the RFC bit-navigation loop (including the
mid-loop `sn == 0` guard) but its final return checked only the two
reconstructed roots — it omitted the terminal `sn == 0` conjunct.

Consequence: when the claimed old size is a power of two, the verifier seeds the
walk with the old root and uses the sizes only as bit-navigation state, so
several distinct (false) old-size claims navigate one proof identically. A valid
proof for one transition therefore verifies under a lied size. Flagship: a valid
`2 → 3` consistency proof is accepted under the false claim `1 → 3` when paired
with the true size-2 root.

## Scope and reachability (measured, not assumed)

- The defect is confined to `verify_consistency`. Its **only** production caller
  is the consumer-side pin store (`sthstore.check_sth_against_store`), which is
  reached only behind a verified head signature in all three of its callers
  (`attestation.py`, `cli.py`, `logclient.py`).
- Consistency-proof **generation** (`consistency_proof`) is RFC-correct and was
  never affected; every honest proof the system emits verifies everywhere.
- The **live** LTL provider/mirror service does not run `verify_consistency` in
  its serving path (it generates proofs, it does not verify them). The published
  standalone `verify.py` has no consistency verifier at all (inclusion +
  receipts only). So this is a consumer-library defect, not a live-service one.
- An empirical search for a pin-advance poison against an **honestly** pinned
  consumer found **0** realizable cases: the two-root check still binds the new
  root, and the pin binds `(size, root)` from the consumer's own store, so the
  lied-size acceptance does not translate into a pin poison for an honest pin.
  No exploit is claimed; the fix restores conformance regardless.

## The fix

One conjunct in the final return of `verify_consistency`:

```python
return old_hash == old_root_hash and new_hash == new_root_hash and sn == 0
```

## Verification

- **Fail-first regression** `test_consistency_lied_size_three_way_agreement`
  (in `tests/test_paper_verifiers.py`): a **three-way** harness comparing the
  deployed verifier, the recursive `ConsRec` model, and an independent faithful
  RFC 9162 §2.1.4.2 transliteration, over both the honest family and the
  lied-size family. It fails against the pre-fix verifier (the flagship lie is
  accepted) and passes once `sn == 0` is restored.
- The historical differential tests (164,479 inclusion; 164,224 consistency)
  stay green — the fix rejects nothing honest.
- Full suite: 145 passed, 0 failed.
- The independent RFC oracle is honest-complete on the tested range but is not
  yet cross-checked against a second independent implementation (ATL / Sigsum);
  that cross-check is a follow-up harness item.

## Honesty / provenance

This defect is the corpus's Known Gap 14: the project's own fidelity harness
**found** the divergence (3,867 deployed-accepts-only cases in a pinned
73,573-case family) and recorded it in public log entry 13. What the two-way
harness could not do was assign blame — with only the deployed verifier and the
Lean model disagreeing, and both labelled "RFC 9162", the divergence was filed
as a scoped gap rather than a conformance bug. A post-appeal review round added
the missing third oracle (a faithful RFC verifier), which showed the deployed
side was the deviant one, and traced it to the omitted Step 7.

Public log entry 13 and the attested accumulator commit are unchanged: the
historical experiment remains truthfully recorded and reproducible at the
tagged pre-fix commit. The IACR submission PDF is unchanged. The corpus
Known-Gaps ledger records this closure.
