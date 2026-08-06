#!/usr/bin/env bash
# Build pacta-verify-slhdsa from the PINNED proven source.
#
# The pinned checkout is never modified. This script exports the pinned commit
# into a scratch tree, applies expose-mono.patch there, builds against that, and
# records exactly what went in. If the pinned checkout is dirty, or is not at
# the commit the attestation names, it refuses: a quorum member built from a
# tree nobody can identify is a quorum member that proves nothing.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${FIPS205_SOURCE:-$HOME/GitClone/FormalVerification/sources/fips205-source}"
PIN="${FIPS205_PIN:-a3ce8e8}"
BUILD="${BUILD_DIR:-$HERE/.build-slhdsa}"
OUT="$HERE/verify-slhdsa/target/release/pacta-verify-slhdsa"

echo "=== pacta-verify-slhdsa: build from the proven source ==="

[ -d "$SRC/.git" ] || { echo "FATAL: '$SRC' is not a git checkout of fips205-source."; exit 2; }
HEAD_SHA="$(git -C "$SRC" rev-parse HEAD)"
case "$HEAD_SHA" in
  "$PIN"*) ;;
  *) echo "FATAL: pinned source is at ${HEAD_SHA:0:8}, expected $PIN."
     echo "  The certificates cover $PIN. Building a 'proven' verifier from any"
     echo "  other tree would be a claim nobody can check."; exit 1;;
esac
if [ -n "$(git -C "$SRC" status --porcelain)" ]; then
  echo "FATAL: the pinned source has uncommitted changes:"
  git -C "$SRC" status --porcelain | sed 's/^/    /'
  echo "  Refusing: the binary must correspond to a nameable tree."; exit 1
fi
echo "  pinned source  $SRC @ ${HEAD_SHA:0:8} (clean)"

# Export the pinned commit, never a working copy.
rm -rf "$BUILD"; mkdir -p "$BUILD"
git -C "$SRC" archive --format=tar "$HEAD_SHA" | tar -x -C "$BUILD"
echo "  exported       $(find "$BUILD" -type f | wc -l) files from $PIN"

# --- the two changes, applied verbatim and then VERIFIED to be present -------
LIB="$BUILD/src/lib.rs"; VM="$BUILD/src/verify_mono.rs"
grep -q '^mod verify_mono;' "$LIB" || { echo "FATAL: 'mod verify_mono;' not found in lib.rs — the source moved."; exit 1; }
# The crate is `#![deny(missing_docs)]`, so a module cannot become public
# without a doc comment. The comment is part of the visibility change, not an
# extra edit: `pub mod` alone does not compile here.
sed -i 's|^mod verify_mono;|/// Aeneas-compat monomorphic verify path: the extraction root the eleven\n/// certificates cover (apex `fips205.slh_verify_128s_accepts_iff`). Public only\n/// so a quorum binary can call the proven function; see expose-mono.patch.\npub mod verify_mono;|' "$LIB"

cat >> "$VM" <<'RUST'

/// Byte-level entry to the PROVEN root, for out-of-crate callers.
///
/// Assembles arguments only; the body is the crate's own test helper
/// `internal_inputs` followed by the call. `mprime` is FIPS 205's M' and is
/// built by the CALLER — its construction is outside every certificate
/// (TRUSTED-BASE item 10), which is why it is a parameter and not computed
/// here.
pub fn verify_mono_bytes(mprime: &[u8], sig_bytes: &[u8; 7856], pk_bytes: &[u8; 32]) -> bool {
    let mut pk_seed = [0u8; 16];
    let mut pk_root = [0u8; 16];
    pk_seed.copy_from_slice(&pk_bytes[0..16]);
    pk_root.copy_from_slice(&pk_bytes[16..32]);
    let pk = SlhPublicKey { pk_seed, pk_root };
    let sig = SlhDsaSig::<12, 7, 9, 14, 35, 16>::deserialize(sig_bytes);
    slh_verify_128s(mprime, &sig, &pk)
}
RUST

# The extraction root must be untouched. Compare it against the pinned tree.
if ! diff <(git -C "$SRC" show "$HEAD_SHA:src/verify_mono.rs") \
          <(head -n "$(git -C "$SRC" show "$HEAD_SHA:src/verify_mono.rs" | wc -l)" "$VM") > /dev/null; then
  echo "FATAL: the patch altered existing lines of verify_mono.rs, not just appended."
  exit 1
fi
echo "  patched        lib.rs visibility + verify_mono_bytes appended (existing lines unchanged)"

# --- render Cargo.toml from the template ------------------------------------
sed "s|{{SOURCE}}|$BUILD|g" "$HERE/verify-slhdsa/Cargo.toml.template" > "$HERE/verify-slhdsa/Cargo.toml"

echo "  building..."
( cd "$HERE/verify-slhdsa" && cargo build --release 2>&1 | tail -5 | sed 's/^/    /' )

[ -x "$OUT" ] || { echo "FATAL: build produced no binary at $OUT"; exit 1; }

cat > "$HERE/verify-slhdsa/target/release/pacta-verify-slhdsa.provenance.json" <<JSON
{
  "binary_sha256": "$(sha256sum "$OUT" | cut -d' ' -f1)",
  "source_repo": "fips205-source",
  "source_commit": "$HEAD_SHA",
  "patch": "expose-mono.patch",
  "patch_sha256": "$(sha256sum "$HERE/verify-slhdsa/expose-mono.patch" | cut -d' ' -f1)",
  "main_sha256": "$(sha256sum "$HERE/verify-slhdsa/src/main.rs" | cut -d' ' -f1)",
  "proven_root": "slh_verify_128s",
  "parameter_set": "SLH-DSA-SHA2-128s",
  "certificates": 11,
  "apex": "fips205.slh_verify_128s_accepts_iff",
  "not_covered": "M-prime assembly (domain separator, context length), hex/file IO, and the compiler. Signing and keygen are out of scope entirely.",
  "rustc": "$(rustc --version)"
}
JSON

echo "  binary         $OUT"
echo "                 sha256 $(sha256sum "$OUT" | cut -c1-16)…"
echo "  provenance     written beside the binary"
