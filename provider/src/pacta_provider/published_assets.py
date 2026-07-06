"""Static assets dropped into the git-published log repository: a
standalone stdlib-only verifier and the customer README. Kept as string
constants so the published repo is fully self-contained."""

VERIFY_PY = '''#!/usr/bin/env python3
"""Standalone verifier for the published Lean Transparency Log.

Python 3 standard library ONLY - no pacta, no pip. Verifies, from the
files in this repository alone:

  1. every entry's leaf hash,
  2. every historical Signed Tree Head against the recomputed prefix root
     (this is the witness check: a split view or tampered entry fails here),
  3. every STH Ed25519 signature (via the openssl binary, if available),
  4. any receipt's inclusion proof (--receipt FILE).

Usage:
  python3 verify.py --all
  python3 verify.py --receipt receipts/dalek-ed25519-verified.receipt.json
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
    return hashlib.sha256(b"\\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\\x01" + left + right).digest()


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


def check_sth_signature(head) -> str:
    openssl = shutil.which("openssl")
    key = HERE / "provider.ed25519.pub"
    if not openssl or not key.exists():
        return "skipped (openssl or provider.ed25519.pub missing)"
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--receipt")
    args = parser.parse_args()
    leaves, problems = load_leaves()
    print(f"entries: {len(leaves)}")
    failures = list(problems)
    for problem in problems:
        print("PROBLEM:", problem)

    if args.all or not args.receipt:
        history_path = HERE / "sth-history.jsonl"
        heads = [json.loads(line) for line in history_path.read_text().splitlines() if line.strip()] if history_path.exists() else []
        previous = -1
        for position, head in enumerate(heads):
            size = int(head["tree_size"])
            expected = merkle_root(leaves[:size]).hex()
            structural = "OK" if head["root_hash"] == expected and size >= previous else "MISMATCH"
            if structural != "OK":
                failures.append(f"STH #{position}")
            signature = check_sth_signature(head)
            if signature == "INVALID":
                failures.append(f"STH #{position} signature")
            print(f"STH #{position} size={size} root={head['root_hash'][:16]}… prefix-root:{structural} signature:{signature}")
            previous = max(previous, size)

    if args.receipt:
        receipt = json.loads(Path(args.receipt).read_text())
        index = int(receipt["leaf_index"])
        entry = json.loads((HERE / "entries" / f"{index:06d}.json").read_text())
        ok = verify_inclusion(
            canonical_json(entry["leaf"]),
            index,
            int(receipt["tree_size"]),
            [bytes.fromhex(h) for h in receipt["inclusion_proof"]],
            bytes.fromhex(receipt["sth"]["root_hash"]),
        )
        print(f"receipt leaf {index} of {receipt['tree_size']}: inclusion {'VALID' if ok else 'INVALID'}")
        if not ok:
            failures.append("receipt inclusion")

    print("RESULT:", "OK - the log is internally consistent" if not failures else f"FAILED ({len(failures)} problems)")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
'''

README_MD = """# Lean Transparency Log — published mirror

This repository is the **git-published face** of a transparency log of
formal-verification attestations: signed statements that the Lean 4 proofs
of specific cryptographic Rust libraries, at specific git commits,
re-check with exactly their documented assumptions.

Layout:

| Path | Content |
|---|---|
| `entries/NNNNNN.json` | one log leaf per file, append-only (git history mirrors log history) |
| `entries/<component>.attestation.json` | the newest attestation per library, for convenience |
| `receipts/<component>.receipt.json` | inclusion proof binding that attestation to the latest signed head |
| `sth-history.jsonl` | **every** Signed Tree Head ever issued — the witness channel: all cloners see the same heads |
| `latest-sth.json` | the current head |
| `provider.ed25519.pub` | the provider's public key (the sole trust anchor) |
| `verify.py` | standalone verifier, Python standard library only |

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
pinned commit (clone it — the git hash is the content hash — and build it
yourself; compilers are declared trusted base). The log deliberately
retains early leaves recording a **failed** audit run: an append-only
trust ledger keeps its history. Tree heads are signed by the merkleized,
proof-attested Ed25519 library itself, and each signature embeds the
provider's own Merkle self-check of that library's leaf.
"""
