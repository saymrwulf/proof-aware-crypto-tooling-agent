"""SLH-DSA-SHA2-128s signing and verification for transparency-log heads.

This module is the post-quantum signing path that did NOT exist before
2026-08-06 (register: pq-slot-names-unproven-algorithm). Scope discipline,
stated up front because the estate has measured what silence costs:

  * The parameter set is LOCKED to SLH-DSA-SHA2-128s — the only set the
    eleven fips205 certificates cover. Every entry point asserts the key's
    algorithm and refuses anything else rather than producing a signature
    outside every proof the estate holds.
  * Signing is DETERMINISTIC (operator decision 2026-08-06): FIPS 205's
    optional deterministic variant, selected via OpenSSL's
    `-pkeyopt deterministic:1`. Chosen so the byte-level reproducibility
    check that caught a real defect on the Ed25519 side survives for this
    algorithm too. The trade is documented: fault-attack hardening from
    hedged signing is forgone, for a key that signs a public log.
  * NOTHING here is Lean-proven. The certificates cover the VERIFY path of
    the extracted model; signing and key generation are outside every proof
    (fips205 TRUSTED-BASE item 2). Verification below can be cross-checked
    against the proven-source binary (pacta-verify-slhdsa); signing cannot
    be cross-checked against anything proven, and no field this module
    emits claims otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SLH_SCHEME = "openssl-slh-dsa-sha2-128s"
SLH_STANDARD = "FIPS 205"
SLH_PARAMETER_SET = "SLH-DSA-SHA2-128s"
SLH_SIGNATURE_BYTES = 7856
SLH_PUBLIC_KEY_BYTES = 32

# Package-anchored, NOT cwd-relative. The Ed25519 twin of this constant was a
# relative path and which implementation signed the log became an accident of
# the launch directory (register: signer-backend-depends-on-cwd). parents[2]
# of src/pacta/slhdsa.py is the repository root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
PROVEN_VERIFIER = (_REPO_ROOT / "dogfood" / "quorum" / "verify-slhdsa"
                   / "target" / "release" / "pacta-verify-slhdsa")
SLHDSA_VERIFIER_ENV = "PACTA_SLHDSA_VERIFIER"


class SlhDsaError(RuntimeError):
    pass


def _openssl() -> str:
    import shutil
    exe = shutil.which("openssl")
    if not exe:
        raise SlhDsaError("openssl binary not found; SLH-DSA operations unavailable")
    return exe


def _assert_128s_key(key_path: str | Path, public: bool) -> None:
    """Refuse any key that is not SLH-DSA-SHA2-128s.

    The check is on the PROPERTY (the algorithm OpenSSL reports for the key),
    not on a filename. A signature under any other parameter set would sit
    outside all eleven certificates while looking exactly like dogfood.
    """
    args = [_openssl(), "pkey", "-in", str(key_path), "-noout", "-text"]
    if public:
        args.insert(2, "-pubin")
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise SlhDsaError(f"cannot read key {key_path}: {(result.stderr or '').strip()[:120]}")
    if SLH_PARAMETER_SET not in result.stdout:
        first = (result.stdout.strip().splitlines() or ["<empty>"])[0]
        raise SlhDsaError(
            f"key {key_path} is not {SLH_PARAMETER_SET} (openssl reports: {first!r}). "
            f"The certificates cover {SLH_PARAMETER_SET} only; refusing.")


def generate_slhdsa_keypair(private_key_path: str | Path, public_key_path: str | Path) -> None:
    """Generate an SLH-DSA-SHA2-128s key pair. Private key mode 0600.

    Key generation is NOT covered by any certificate; this is OpenSSL's
    generator, trusted base, and recorded as such wherever the key is used.
    """
    openssl = _openssl()
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([openssl, "genpkey", "-algorithm", SLH_PARAMETER_SET,
                    "-out", str(private_path)], check=True, timeout=60)
    os.chmod(private_path, 0o600)
    subprocess.run([openssl, "pkey", "-in", str(private_path), "-pubout",
                    "-out", str(public_path)], check=True, timeout=30)
    _assert_128s_key(private_path, public=False)
    _assert_128s_key(public_path, public=True)


def sign_payload_slhdsa(payload: bytes, private_key_path: str | Path) -> str:
    """Deterministically sign; returns base64. Same payload + key => same bytes."""
    _assert_128s_key(private_key_path, public=False)
    openssl = _openssl()
    with tempfile.TemporaryDirectory(prefix="pacta-slhdsa-sign-") as tmp:
        payload_path = Path(tmp) / "payload.bin"
        signature_path = Path(tmp) / "payload.sig"
        payload_path.write_bytes(payload)
        completed = subprocess.run(
            [openssl, "pkeyutl", "-sign", "-inkey", str(private_key_path), "-rawin",
             "-pkeyopt", "deterministic:1",
             "-in", str(payload_path), "-out", str(signature_path)],
            check=False, capture_output=True, text=True, timeout=120)
        if completed.returncode != 0:
            raise SlhDsaError((completed.stderr or "slh-dsa signing failed").strip())
        signature = signature_path.read_bytes()
    if len(signature) != SLH_SIGNATURE_BYTES:
        raise SlhDsaError(
            f"signature is {len(signature)} bytes, expected {SLH_SIGNATURE_BYTES} "
            f"for {SLH_PARAMETER_SET} — wrong parameter set slipped through?")
    return base64.b64encode(signature).decode("ascii")


def verify_payload_slhdsa(payload: bytes, signature_base64: str,
                          public_key_path: str | Path) -> tuple[bool, str | None]:
    """Verify with OpenSSL. For the proven-source cross-check, see
    verify_payload_slhdsa_proven — callers wanting both run both."""
    _assert_128s_key(public_key_path, public=True)
    try:
        signature = base64.b64decode(signature_base64)
    except Exception as exc:
        return False, f"signature_base64 undecodable: {exc}"
    if len(signature) != SLH_SIGNATURE_BYTES:
        return False, f"signature is {len(signature)} bytes, expected {SLH_SIGNATURE_BYTES}"
    openssl = _openssl()
    with tempfile.TemporaryDirectory(prefix="pacta-slhdsa-verify-") as tmp:
        payload_path = Path(tmp) / "payload.bin"
        signature_path = Path(tmp) / "payload.sig"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        completed = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key_path),
             "-rawin", "-in", str(payload_path), "-sigfile", str(signature_path)],
            capture_output=True, timeout=120)
    if completed.returncode == 0:
        return True, None
    return False, "OpenSSL rejected the SLH-DSA signature"


def locate_proven_verifier() -> Path | None:
    env = os.environ.get(SLHDSA_VERIFIER_ENV)
    if env:
        path = Path(env)
        return path if path.exists() else None
    return PROVEN_VERIFIER if PROVEN_VERIFIER.exists() else None


def raw_public_key(public_key_path: str | Path) -> bytes:
    der = subprocess.run([_openssl(), "pkey", "-pubin", "-in", str(public_key_path),
                          "-outform", "DER"], capture_output=True, timeout=30).stdout
    if len(der) < SLH_PUBLIC_KEY_BYTES:
        raise SlhDsaError(f"cannot extract raw public key from {public_key_path}")
    return der[-SLH_PUBLIC_KEY_BYTES:]


def verify_payload_slhdsa_proven(payload: bytes, signature_base64: str,
                                 public_key_path: str | Path) -> tuple[bool, str | None]:
    """Verify with pacta-verify-slhdsa, built from the PINNED proven source.

    This is the one place in the estate where a log signature is checked by
    the implementation whose verify path the certificates actually cover.
    Honest residue: the binary also assembles M' and does IO, which no
    certificate reaches; and it is a compiled binary, while the proofs are
    about the extracted model (the estate's standing R5 gap).
    """
    binary = locate_proven_verifier()
    if binary is None:
        return False, ("proven verifier not built (dogfood/quorum/build-verify-slhdsa.sh); "
                       "refusing to report a proven-path verdict without it")
    try:
        signature = base64.b64decode(signature_base64)
    except Exception as exc:
        return False, f"signature_base64 undecodable: {exc}"
    if len(signature) != SLH_SIGNATURE_BYTES:
        return False, f"signature is {len(signature)} bytes, expected {SLH_SIGNATURE_BYTES}"
    with tempfile.TemporaryDirectory(prefix="pacta-slhdsa-proven-") as tmp:
        payload_path = Path(tmp) / "payload.bin"
        payload_path.write_bytes(payload)
        completed = subprocess.run(
            [str(binary), raw_public_key(public_key_path).hex(), signature.hex(),
             str(payload_path)], capture_output=True, text=True, timeout=120)
    if completed.returncode == 0:
        return True, None
    if completed.returncode == 1:
        return False, "proven verifier rejected the signature"
    return False, f"proven verifier input error: {(completed.stderr or '').strip()[:120]}"


def public_key_fingerprint(public_key_path: str | Path) -> str:
    return hashlib.sha256(Path(public_key_path).read_bytes()).hexdigest()


def slh_dsa_signature_block(payload: bytes, private_key_path: str | Path,
                            public_key_path: str | Path) -> dict[str, Any]:
    """The `signatures.slh_dsa` block for a signed tree head.

    A SEPARATE block by operator decision 2026-08-06: the ml_dsa slot keeps
    saying, truthfully, that ML-DSA was never configured; no algorithm is
    swapped inside a field that names a different one.
    """
    signature_base64 = sign_payload_slhdsa(payload, private_key_path)
    return {
        "scheme": SLH_SCHEME,
        "standard": SLH_STANDARD,
        "parameter_set": SLH_PARAMETER_SET,
        "mode": "deterministic",
        "status": "signed",
        "signing_backend": "openssl",  # honest: no proven signer exists, for any algorithm
        "payload_digest_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_base64": signature_base64,
        "public_key_fingerprint_sha256": public_key_fingerprint(public_key_path),
    }


def slh_dsa_not_configured_block() -> dict[str, Any]:
    return {
        "scheme": SLH_SCHEME,
        "standard": SLH_STANDARD,
        "parameter_set": SLH_PARAMETER_SET,
        "status": "not_configured",
        "reason": "No SLH-DSA signing key was configured for this log.",
    }
