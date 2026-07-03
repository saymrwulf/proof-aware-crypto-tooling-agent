from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class SignatureError(RuntimeError):
    pass


def canonical_attestation_payload(attestation: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in attestation.items() if key != "signature"}
    return canonical_json(unsigned)


def canonical_json(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def payload_digest(attestation: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_attestation_payload(attestation)).hexdigest()


def public_key_fingerprint(public_key_path: str | Path) -> str:
    data = Path(public_key_path).read_bytes()
    return hashlib.sha256(data).hexdigest()


def generate_ed25519_keypair(private_key_path: str | Path, public_key_path: str | Path) -> None:
    openssl = _openssl()
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([openssl, "genpkey", "-algorithm", "ed25519", "-out", str(private_path)], check=True, timeout=30)
    subprocess.run([openssl, "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)], check=True, timeout=30)


def sign_attestation(attestation: dict[str, Any], private_key_path: str | Path, public_key_path: str | Path | None = None) -> dict[str, Any]:
    payload = canonical_attestation_payload(attestation)
    signature_base64 = sign_payload_ed25519(payload, private_key_path)
    signed = dict(attestation)
    signed["signature"] = {
        "scheme": "openssl-ed25519",
        "status": "signed",
        "payload_digest_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_base64": signature_base64,
    }
    if public_key_path:
        signed["signature"]["public_key_fingerprint_sha256"] = public_key_fingerprint(public_key_path)
    return signed


def verify_attestation_signature(attestation: dict[str, Any], public_key_path: str | Path) -> tuple[bool, str | None]:
    signature = attestation.get("signature") or {}
    if signature.get("scheme") != "openssl-ed25519":
        return False, f"Unsupported attestation signature scheme: {signature.get('scheme')}"
    encoded = signature.get("signature_base64")
    if not encoded:
        return False, "Attestation signature is missing signature_base64."
    expected_digest = signature.get("payload_digest_sha256")
    actual_digest = payload_digest(attestation)
    if expected_digest and expected_digest != actual_digest:
        return False, "Attestation payload digest does not match signature metadata."
    expected_fingerprint = signature.get("public_key_fingerprint_sha256")
    if expected_fingerprint:
        actual_fingerprint = public_key_fingerprint(public_key_path)
        if expected_fingerprint != actual_fingerprint:
            return False, "Attestation public key fingerprint does not match signature metadata."
    return verify_payload_ed25519(canonical_attestation_payload(attestation), encoded, public_key_path)


def sign_payload_ed25519(payload: bytes, private_key_path: str | Path) -> str:
    openssl = _openssl()
    with tempfile.TemporaryDirectory(prefix="pacta-sign-") as tmp:
        payload_path = Path(tmp) / "payload.bin"
        signature_path = Path(tmp) / "payload.sig"
        payload_path.write_bytes(payload)
        completed = subprocess.run(
            [openssl, "pkeyutl", "-sign", "-inkey", str(private_key_path), "-rawin", "-in", str(payload_path), "-out", str(signature_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise SignatureError((completed.stderr or completed.stdout or "openssl signing failed").strip())
        signature_bytes = signature_path.read_bytes()
    return base64.b64encode(signature_bytes).decode("ascii")


def verify_payload_ed25519(payload: bytes, signature_base64: str, public_key_path: str | Path) -> tuple[bool, str | None]:
    openssl = _openssl()
    try:
        signature_bytes = base64.b64decode(signature_base64, validate=True)
    except ValueError as exc:
        return False, f"Invalid base64 signature: {exc}"
    with tempfile.TemporaryDirectory(prefix="pacta-verify-") as tmp:
        payload_path = Path(tmp) / "payload.bin"
        signature_path = Path(tmp) / "payload.sig"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature_bytes)
        completed = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(payload_path),
                "-sigfile",
                str(signature_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    if completed.returncode != 0:
        return False, (completed.stderr or completed.stdout or "openssl verification failed").strip()
    return True, None


def _openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise SignatureError("openssl is not available on PATH")
    return path
