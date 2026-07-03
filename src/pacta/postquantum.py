from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
from dataclasses import dataclass


ML_DSA_SCHEME = "ML-DSA-65"
ML_DSA_STANDARD = "FIPS 204"


@dataclass(slots=True)
class MlDsaCapability:
    available: bool
    backend: str | None
    reason: str

    def to_signature_slot(self) -> dict[str, str]:
        if self.available:
            return {
                "scheme": ML_DSA_SCHEME,
                "standard": ML_DSA_STANDARD,
                "status": "not_configured",
                "reason": "A backend appears available, but no ML-DSA signing key was configured for this log.",
            }
        return {
            "scheme": ML_DSA_SCHEME,
            "standard": ML_DSA_STANDARD,
            "status": "unavailable",
            "reason": self.reason,
        }


def detect_ml_dsa() -> MlDsaCapability:
    openssl = shutil.which("openssl")
    if openssl:
        try:
            completed = subprocess.run(
                [openssl, "list", "-signature-algorithms"],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        if completed and completed.returncode == 0:
            output = completed.stdout + completed.stderr
            if re.search(r"\b(?:ML-?DSA|mldsa|dilithium)\b", output, flags=re.IGNORECASE):
                return MlDsaCapability(True, "openssl", "OpenSSL advertises an ML-DSA/Dilithium signature algorithm.")

    for module in ("oqs", "pqcrypto", "dilithium"):
        if importlib.util.find_spec(module):
            return MlDsaCapability(True, f"python:{module}", f"Python module {module!r} appears importable.")

    return MlDsaCapability(
        False,
        None,
        "No usable ML-DSA/FIPS 204 backend was found. Ed25519 log signatures can be verified, but a policy requiring both signatures must fail closed.",
    )
