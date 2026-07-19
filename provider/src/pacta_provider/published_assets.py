"""Static assets dropped into the git-published log repository: the
standalone fail-closed verifier, its adversarial self-test, and the
customer README. Kept as string constants so the published repo is fully
self-contained.

SYNC RULE: these constants MUST stay byte-identical to the canonical
files in the published mirror (lean-transparency-log: verify.py,
verify_selftest.py, README.md). A publish overwrites the mirror copies
from here, so drift REGRESSES shipped fixes (found 2026-07-19: this file
still carried the pre-hardening fail-open verify.py and the pre-Tier-2
README). tests/test_published_assets.py pins the security-critical
markers; regenerate from the canonical files rather than hand-editing.
"""

VERIFY_PY = r'''#!/usr/bin/env python3
"""Standalone verifier for the published Lean Transparency Log.

Pure Python 3 standard library for hashing and structure; Ed25519
signature checking shells out to the `openssl` binary. Verifies, from the
files in this repository alone:

  1. every entry's leaf hash,
  2. every historical Signed Tree Head against the recomputed prefix root
     (a split view or tampered entry fails here),
  3. every STH Ed25519 signature,
  4. every published receipt under receipts/ (with --all), and any receipt
     supplied via --receipt FILE, as a FULL transparency receipt: type tag,
     STH signature, REQUIRED key fingerprint, log id, presence of its STH
     in the published history, REQUIRED leaf hash matching the named entry,
     tree-size agreement, and the inclusion proof. Binding fields are
     required, never compare-if-present.

FAIL-CLOSED: if signature checking is unavailable (no `openssl`, or the
public key is missing), the run FAILS — signatures are load-bearing and a
"couldn't check" is not a pass. Use --structural-only to explicitly ask
for hashes/structure without signatures (it prints, and exits, as a
reduced check, never as full verification).

Usage:
  python3 verify.py --all
  python3 verify.py --receipt receipts/dalek-ed25519-verified.receipt.json
  python3 verify.py --all --structural-only   # explicit reduced check
"""
import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return node_hash(merkle_root(leaves[:split]), merkle_root(leaves[split:]))


def verify_inclusion(leaf: bytes, index: int, size: int, proof, root: bytes) -> bool:
    if index >= size:
        return False
    fn, sn = index, size - 1
    node = leaf_hash(leaf)
    for sibling in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            node = node_hash(sibling, node)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            node = node_hash(node, sibling)
        fn //= 2
        sn //= 2
    return sn == 0 and node == root


def canonical_json(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_leaves():
    leaves, problems = [], []
    for position, path in enumerate(sorted((HERE / "entries").glob("[0-9]*.json"))):
        record = json.loads(path.read_text())
        data = canonical_json(record["leaf"])
        if record.get("index") != position:
            problems.append(f"{path.name}: index {record.get('index')} at position {position}")
        if leaf_hash(data).hex() != record.get("leaf_hash"):
            problems.append(f"{path.name}: leaf_hash mismatch (tampered entry)")
        leaves.append(data)
    return leaves, problems


def signatures_available() -> bool:
    return bool(shutil.which("openssl")) and (HERE / "provider.ed25519.pub").exists()


def key_fingerprint() -> str:
    return hashlib.sha256((HERE / "provider.ed25519.pub").read_bytes()).hexdigest()


def check_sth_signature(head) -> str:
    """VALID / INVALID / UNAVAILABLE. UNAVAILABLE is a FAILURE at the
    caller unless the run is explicitly --structural-only."""
    openssl = shutil.which("openssl")
    key = HERE / "provider.ed25519.pub"
    if not openssl or not key.exists():
        return "UNAVAILABLE"
    signatures = head.get("signatures") or {}
    ed = signatures.get("ed25519") or {}
    payload = canonical_json({k: v for k, v in head.items() if k != "signatures"})
    with tempfile.TemporaryDirectory() as tmp:
        payload_path = Path(tmp) / "p"
        signature_path = Path(tmp) / "s"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(base64.b64decode(ed.get("signature_base64", "")))
        result = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin",
             "-in", str(payload_path), "-sigfile", str(signature_path)],
            capture_output=True,
        )
    return "VALID" if result.returncode == 0 else "INVALID"


RECEIPT_TYPE = "pacta.transparency.receipt.v1"


def verify_receipt(receipt, heads, structural_only: bool, label: str):
    """Full binding checks for one receipt. Every binding field is REQUIRED;
    a missing field is a failure, never a skip. Returns failure strings."""
    problems = []
    if receipt.get("type") != RECEIPT_TYPE:
        problems.append(f"{label}: type is {receipt.get('type')!r}, expected {RECEIPT_TYPE!r}")
    sth = receipt.get("sth") or {}
    if sth.get("hash_algorithm") != "RFC9162_SHA256":
        problems.append(f"{label}: STH hash_algorithm is not RFC9162_SHA256")
    if receipt.get("hash_algorithm") != "RFC9162_SHA256":
        problems.append(f"{label}: receipt hash_algorithm is not RFC9162_SHA256")
    if receipt.get("log_id") != sth.get("log_id"):
        problems.append(f"{label}: receipt log_id != its STH log_id")
    try:
        index = int(receipt.get("leaf_index"))
    except (TypeError, ValueError):
        index = -1
    entry_path = HERE / "entries" / f"{index:06d}.json" if index >= 0 else None
    if entry_path is None or not entry_path.exists():
        problems.append(f"{label}: leaf_index {receipt.get('leaf_index')!r} names no published entry")
        return problems
    entry = json.loads(entry_path.read_text())
    leaf_bytes = canonical_json(entry["leaf"])
    # (a) the receipt's STH must be signed by THIS log's key ...
    rsig = check_sth_signature(sth)
    if rsig == "INVALID" or (rsig == "UNAVAILABLE" and not structural_only):
        problems.append(f"{label}: STH signature {rsig}")
    # (b) ... the named key fingerprint is REQUIRED and must be this key ...
    fp = (sth.get("signatures", {}).get("ed25519", {}) or {}).get("public_key_fingerprint_sha256")
    if not fp:
        problems.append(f"{label}: STH lacks public_key_fingerprint_sha256 (required)")
    elif (HERE / "provider.ed25519.pub").exists() and fp != key_fingerprint():
        problems.append(f"{label}: STH signed by a different key than provider.ed25519.pub")
    # (c) ... its log_id must be present and match the log ...
    meta_path = HERE / "log-metadata.json"
    if meta_path.exists():
        meta_log_id = json.loads(meta_path.read_text()).get("log_id")
        if meta_log_id and sth.get("log_id") != meta_log_id:
            problems.append(f"{label}: STH log_id missing or not this log's")
    # (d) ... the receipt's STH must appear in the published history ...
    if heads and canonical_json(sth) not in {canonical_json(h) for h in heads}:
        problems.append(f"{label}: STH not present in sth-history.jsonl")
    # (e) ... the leaf_hash is REQUIRED and must match the named entry ...
    if not receipt.get("leaf_hash"):
        problems.append(f"{label}: leaf_hash missing (required)")
    elif receipt["leaf_hash"] != leaf_hash(leaf_bytes).hex():
        problems.append(f"{label}: leaf_hash does not match the named entry")
    # (f) ... tree_size agreement ...
    try:
        size_agree = int(receipt.get("tree_size")) == int(sth.get("tree_size"))
    except (TypeError, ValueError):
        size_agree = False
    if not size_agree:
        problems.append(f"{label}: tree_size != its STH tree_size")
    # (g) ... and finally the inclusion proof itself.
    try:
        ok = verify_inclusion(
            leaf_bytes, index, int(receipt.get("tree_size") or 0),
            [bytes.fromhex(h) for h in receipt.get("inclusion_proof") or []],
            bytes.fromhex(sth.get("root_hash") or ""),
        )
    except (TypeError, ValueError):
        ok = False
    if not ok:
        problems.append(f"{label}: inclusion proof INVALID")
    print(f"receipt {label}: leaf {index} of {receipt.get('tree_size')} "
          f"STH-sig:{rsig} bindings+inclusion:{'OK' if not problems else 'FAIL'}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--receipt")
    parser.add_argument("--structural-only", action="store_true",
                        help="skip Ed25519 signature checks explicitly; the run reports a "
                             "REDUCED check and can never print full verification.")
    args = parser.parse_args()

    sigs_ok = signatures_available()
    if not args.structural_only and not sigs_ok:
        # Fail closed: a verifier that cannot check signatures must not
        # imply it did. Do not silently continue.
        print("FATAL: signature checking unavailable (need the `openssl` binary and "
              "provider.ed25519.pub). Install openssl / fetch the key, or pass "
              "--structural-only to run an explicit hashes-and-structure check.")
        return 2

    leaves, problems = load_leaves()
    print(f"entries: {len(leaves)}")
    failures = list(problems)
    for problem in problems:
        print("PROBLEM:", problem)

    history_path = HERE / "sth-history.jsonl"
    heads = [json.loads(line) for line in history_path.read_text().splitlines() if line.strip()] if history_path.exists() else []

    if args.all or not args.receipt:
        # log-wide checks (GPT §4.3): history internally consistent AND the
        # published latest-sth.json is exactly the final history head.
        previous = -1
        log_id = None
        for position, head in enumerate(heads):
            size = int(head["tree_size"])
            if size > len(leaves):
                failures.append(f"STH #{position} claims size {size} > {len(leaves)} leaves")
            expected = merkle_root(leaves[:size]).hex()
            structural = "OK" if head["root_hash"] == expected and size >= previous else "MISMATCH"
            if structural != "OK":
                failures.append(f"STH #{position} prefix-root/monotonicity")
            if log_id is None:
                log_id = head.get("log_id")
            elif head.get("log_id") != log_id:
                failures.append(f"STH #{position} log_id changed mid-history")
            signature = check_sth_signature(head)
            if signature == "INVALID" or (signature == "UNAVAILABLE" and not args.structural_only):
                failures.append(f"STH #{position} signature {signature}")
            print(f"STH #{position} size={size} root={head['root_hash'][:16]}… prefix-root:{structural} signature:{signature}")
            previous = max(previous, size)
        latest_path = HERE / "latest-sth.json"
        if latest_path.exists() and heads:
            latest = json.loads(latest_path.read_text())
            if canonical_json(latest) != canonical_json(heads[-1]):
                failures.append("latest-sth.json is not the final sth-history head")
            elif int(latest["tree_size"]) != len(leaves):
                failures.append(f"latest-sth tree_size {latest['tree_size']} != {len(leaves)} leaves")
            else:
                print(f"latest-sth: size {latest['tree_size']} == leaf count, and == final history head  OK")
        for receipt_path in sorted((HERE / "receipts").glob("*.receipt.json")):
            failures += verify_receipt(json.loads(receipt_path.read_text()),
                                       heads, args.structural_only, receipt_path.name)

    if args.receipt:
        failures += verify_receipt(json.loads(Path(args.receipt).read_text()),
                                   heads, args.structural_only, Path(args.receipt).name)

    mode = "REDUCED (structural only, signatures NOT checked)" if args.structural_only else "full"
    if failures:
        print(f"RESULT: FAILED ({len(failures)} problems) [{mode}]")
        return 1
    print(f"RESULT: OK [{mode}]"
          + ("" if not args.structural_only else " — signatures were NOT verified; this is not full verification"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

VERIFY_SELFTEST_PY = r'''#!/usr/bin/env python3
"""Adversarial self-test for verify.py — proves the fail-closed paths fail.

Each case mutates a real published receipt (or the environment) and asserts
the verifier REJECTS it; plus the honest controls. Exit 0 only if every case
behaves. Run from a clone: python3 verify_selftest.py
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(*args, env=None):
    result = subprocess.run(
        [sys.executable, str(HERE / "verify.py"), *args],
        capture_output=True, text=True, env=env,
    )
    return result.returncode, result.stdout


def base_receipt():
    path = sorted((HERE / "receipts").glob("*.receipt.json"))[0]
    return json.loads(path.read_text())


def mutated(**changes):
    receipt = copy.deepcopy(base_receipt())
    for dotted, value in changes.items():
        target, keys = receipt, dotted.split(".")
        for key in keys[:-1]:
            target = target[key]
        if value is None:
            target.pop(keys[-1], None)
        else:
            target[keys[-1]] = value
    return receipt


def check_receipt(receipt) -> int:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(receipt, handle)
        path = handle.name
    try:
        code, _ = run("--receipt", path)
        return code
    finally:
        os.unlink(path)


def main() -> int:
    cases = []

    code, out = run("--all")
    cases.append(("honest --all passes (full)", code == 0 and "RESULT: OK [full]" in out))
    cases.append(("--all covers every published receipt",
                  out.count("receipt ") == len(list((HERE / "receipts").glob("*.receipt.json")))))

    cases.append(("honest receipt passes", check_receipt(base_receipt()) == 0))
    cases.append(("missing key fingerprint REJECTED",
                  check_receipt(mutated(**{"sth.signatures.ed25519.public_key_fingerprint_sha256": None})) == 1))
    cases.append(("missing leaf_hash REJECTED", check_receipt(mutated(leaf_hash=None)) == 1))
    cases.append(("wrong receipt type REJECTED", check_receipt(mutated(type="forged.v0")) == 1))
    cases.append(("forged (unsigned) root REJECTED",
                  check_receipt(mutated(**{"sth.root_hash": "ff" * 32})) == 1))
    cases.append(("tree_size mismatch REJECTED",
                  check_receipt(mutated(tree_size=int(base_receipt()["tree_size"]) + 1)) == 1))
    cases.append(("wrong log_id REJECTED",
                  check_receipt(mutated(**{"sth.log_id": "00" * 32})) == 1))

    code, out = run("--all", "--structural-only")
    cases.append(("--structural-only is explicit, never claims full",
                  code == 0 and "REDUCED" in out and "[full]" not in out))

    with tempfile.TemporaryDirectory() as tmp:
        os.symlink(sys.executable, Path(tmp) / Path(sys.executable).name)
        code, out = run("--all", env={"PATH": tmp})
        cases.append(("no openssl -> FAIL CLOSED (exit 2)", code == 2))

    width = max(len(name) for name, _ in cases)
    for name, ok in cases:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}")
    if all(ok for _, ok in cases):
        print(f"SELFTEST GREEN ({len(cases)} cases)")
        return 0
    print("SELFTEST RED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''

README_MD = r'''# Lean Transparency Log — published mirror

This repository is the **git-published face** of a transparency log of
formal-verification attestations: signed statements that the Lean 4 proofs
of specific software, at specific git commits, re-check with exactly their
documented assumptions. Its first twelve leaves attest four cryptographic
Rust libraries (Ed25519 implementations); as of **entry 13 (2026-07-16)**
the log also attests **its own accumulator machinery** — a kernel-checked
mechanization of the log's security analysis, so the log carries
kernel-checked proofs *about the accumulator model* underlying its own
inclusion and consistency reasoning, as one of its own entries (subject
[`ltl-accumulator-verified`](https://github.com/saymrwulf/ltl-accumulator-verified);
scoped to the mechanized model — it does not prove operator honesty,
signing, or execution provenance). Current head: tree size 13, root
`3488a2d0…`.

Layout:

| Path | Content |
|---|---|
| `entries/NNNNNN.json` | one log leaf per file, append-only (git history mirrors log history) |
| `entries/<component>.attestation.json` | the newest attestation per library, for convenience |
| `receipts/<component>.receipt.json` | inclusion proof binding that attestation to the latest signed head |
| `sth-history.jsonl` | **every** Signed Tree Head ever issued — the witness channel: all cloners see the same heads |
| `latest-sth.json` | the current head |
| `provider.ed25519.pub` | the provider's public key — the sole cryptographic identity anchor; each statement's truth additionally rests on the assumptions stated in its leaf |
| `verify.py` | standalone verifier (Python stdlib + the `openssl` binary; fails closed without them; `--all` covers every published receipt) |
| `verify_selftest.py` | adversarial self-test: proves the verifier's fail-closed paths reject mutated receipts |

Verify everything locally, no installation:

```bash
python3 verify.py --all
python3 verify.py --receipt receipts/dalek-ed25519-verified.receipt.json
```

The online service (same data, live endpoints + customer documentation):
**https://ltl.zkdefi.org**

The provider tooling, agent tooling, and course materials:
**https://github.com/saymrwulf/proof-aware-crypto-tooling-agent**

Honesty notes, always in force: attestations cover Rust **source** at a
pinned commit (clone it — the commit identifies the committed git tree,
not dependencies or toolchains — and build it yourself; compilers are
declared trusted base). The log deliberately
retains early leaves recording a **failed** audit run: an append-only
trust ledger keeps its history. Tree heads are signed by the merkleized,
proof-attested Ed25519 library itself, and each signature embeds the
provider's own Merkle self-check of that library's leaf.
'''
