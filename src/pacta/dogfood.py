from __future__ import annotations

import base64
import binascii
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DOGFOOD_ENV = "PACTA_DOGFOOD_VERIFIER"
DEFAULT_STATE_DIR = Path("dogfood") / "state"
BACKEND_VERIFIED = "verified-dalek-serial"
BACKEND_OPENSSL = "openssl"

# Ed25519 SubjectPublicKeyInfo (RFC 8410): a fixed 12-byte DER prefix then
# the raw 32-byte key. Parsing by prefix is exact for this OID, not a
# heuristic.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


@dataclass(slots=True)
class DogfoodBuildResult:
    built: bool
    binary_path: Path | None
    provenance: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)


def pem_public_key_to_raw(public_key_path: str | Path) -> bytes:
    """Extract the raw 32-byte Ed25519 key from an OpenSSL PEM SPKI file."""
    text = Path(public_key_path).read_text(encoding="utf-8")
    body = "".join(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("-----")
    )
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Not a PEM public key: {public_key_path}: {exc}") from exc
    if not der.startswith(_ED25519_SPKI_PREFIX) or len(der) != len(_ED25519_SPKI_PREFIX) + 32:
        raise ValueError(
            f"Not an Ed25519 SubjectPublicKeyInfo: {public_key_path} "
            f"(got {len(der)} DER bytes)"
        )
    return der[len(_ED25519_SPKI_PREFIX):]


def default_binary_path(state_dir: str | Path | None = None) -> Path:
    return Path(state_dir or DEFAULT_STATE_DIR) / "pacta-verified-verify"


def locate_verifier(state_dir: str | Path | None = None) -> Path | None:
    """Find the dogfood verifier binary: explicit env var first, then the
    default build location. Returns None when unavailable (callers fall
    back to OpenSSL and must record the downgrade)."""
    env = os.environ.get(DOGFOOD_ENV)
    if env:
        path = Path(env)
        return path if path.exists() else None
    path = default_binary_path(state_dir)
    return path if path.exists() else None


def load_provenance(binary_path: str | Path) -> dict[str, Any]:
    sidecar = Path(binary_path).with_suffix(".provenance.json")
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return {}


def build_verifier(
    source_workspace: str | Path,
    crate_dir: str | Path = Path("dogfood") / "pacta-verified-verify",
    state_dir: str | Path | None = None,
    timeout: int = 900,
) -> DogfoodBuildResult:
    """Build the dogfood verifier against the pinned proven source workspace.

    The serial backend is pinned via RUSTFLAGS exactly as the verified
    extraction pins it; provenance (source path, source commit, rustc,
    backend cfg) is recorded next to the binary and surfaces in evidence.
    """
    source = Path(source_workspace).expanduser().resolve()
    crate = Path(crate_dir).resolve()
    diagnostics: list[str] = []
    cargo = shutil.which("cargo")
    if not cargo:
        return DogfoodBuildResult(False, None, {}, ["cargo is not available on PATH; cannot build the dogfood verifier."])
    if not (source / "ed25519-dalek" / "Cargo.toml").exists():
        return DogfoodBuildResult(
            False,
            None,
            {},
            [f"{source} does not look like the pinned curve25519-dalek source workspace (no ed25519-dalek/Cargo.toml)."],
        )
    template = (crate / "Cargo.toml.template").read_text(encoding="utf-8")
    (crate / "Cargo.toml").write_text(template.replace("{{SOURCE}}", str(source)), encoding="utf-8")
    env = dict(os.environ)
    backend_cfg = 'curve25519_dalek_backend="serial"'
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + f" --cfg {backend_cfg}").strip()
    completed = subprocess.run(
        [cargo, "build", "--release", "--quiet"],
        cwd=str(crate),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-12:]
        return DogfoodBuildResult(False, None, {}, ["cargo build failed:"] + tail)
    built = crate / "target" / "release" / "pacta-verified-verify"
    if not built.exists():
        return DogfoodBuildResult(False, None, {}, [f"cargo reported success but {built} does not exist."])
    out = default_binary_path(state_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, out)
    provenance = {
        "type": "pacta.dogfood.verifier_provenance.v1",
        "source_workspace": str(source),
        "source_commit": _git_commit(source),
        "backend_cfg": backend_cfg,
        "rustc_version": _tool_version("rustc"),
        "cargo_version": _tool_version("cargo"),
        "entry_point": "ed25519_dalek::VerifyingKey::verify (pinned workspace)",
        "coverage_note": (
            "The certificates cover verify_sha512, the extraction-refactored image of this verify path "
            "(same internals; the delta is the documented hash-wrapper refactor in the pinned source). "
            "Field, group law, scalars, encoding/decompression, and the four apex tiers are certificate-covered; "
            "SHA-512 and the ~15 lines of wire glue are the theorems' documented trusted base."
        ),
    }
    out.with_suffix(".provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return DogfoodBuildResult(True, out, provenance, diagnostics)


def verify_payload_dogfood(
    payload: bytes,
    signature: bytes,
    public_key_path: str | Path,
    binary: str | Path,
    timeout: int = 30,
) -> tuple[bool, str | None]:
    try:
        raw_key = pem_public_key_to_raw(public_key_path)
    except ValueError as exc:
        return False, str(exc)
    with tempfile.TemporaryDirectory(prefix="pacta-dogfood-") as tmp:
        payload_path = Path(tmp) / "payload.bin"
        payload_path.write_bytes(payload)
        completed = subprocess.run(
            [str(binary), raw_key.hex(), signature.hex(), str(payload_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    if completed.returncode == 0:
        return True, None
    if completed.returncode == 1:
        return False, "signature invalid (verified-path verifier)"
    return False, (completed.stderr or completed.stdout or "dogfood verifier error").strip()


def _git_commit(path: Path) -> str | None:
    git = shutil.which("git")
    if not git:
        return None
    completed = subprocess.run(
        [git, "rev-parse", "HEAD"], cwd=str(path), capture_output=True, text=True, timeout=15
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _tool_version(tool: str) -> str | None:
    path = shutil.which(tool)
    if not path:
        return None
    completed = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15)
    return completed.stdout.strip() if completed.returncode == 0 else None
