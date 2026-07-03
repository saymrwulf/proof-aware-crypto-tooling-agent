from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ArtifactBuildResult:
    artifact_dir: Path
    crate_dir: Path | None
    built: bool
    log_path: Path | None
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_dir": str(self.artifact_dir),
            "crate_dir": str(self.crate_dir) if self.crate_dir else None,
            "built": self.built,
            "log_path": str(self.log_path) if self.log_path else None,
            "diagnostics": self.diagnostics,
        }


def build_proof_gated_capsule(
    card: dict[str, Any],
    artifact_root: str | Path,
    timeout: int = 120,
    dry_run: bool = False,
) -> ArtifactBuildResult:
    component = str(card.get("component") or "unknown-component")
    artifact_dir = Path(artifact_root) / _slug(component)
    crate_name = f"pacta_gated_{_crate_suffix(component)}"
    crate_dir = artifact_dir / crate_name
    if dry_run:
        return ArtifactBuildResult(
            artifact_dir=artifact_dir,
            crate_dir=crate_dir,
            built=False,
            log_path=None,
            diagnostics=["dry-run: proof-gated capsule was not written or built."],
        )

    src_dir = crate_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    claims_text = json.dumps(card, indent=2, sort_keys=True) + "\n"
    (artifact_dir / "claims.json").write_text(claims_text, encoding="utf-8")
    (crate_dir / "claims.json").write_text(claims_text, encoding="utf-8")
    (crate_dir / "Cargo.toml").write_text(_cargo_toml(crate_name, component), encoding="utf-8")
    (src_dir / "lib.rs").write_text(_lib_rs(card), encoding="utf-8")
    (crate_dir / "README.md").write_text(_crate_readme(card), encoding="utf-8")

    cargo = shutil.which("cargo")
    log_path = artifact_dir / "capsule-build.log"
    if not cargo:
        log_path.write_text("cargo was not found on PATH; capsule source was written but not built.\n", encoding="utf-8")
        return ArtifactBuildResult(
            artifact_dir=artifact_dir,
            crate_dir=crate_dir,
            built=False,
            log_path=log_path,
            diagnostics=["cargo was not found on PATH."],
        )

    cmd = [cargo, "build", "--release", "--manifest-path", str(crate_dir / "Cargo.toml")]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        log_path.write_text(
            "$ " + " ".join(cmd) + "\n\n" + completed.stdout + completed.stderr + f"\nexit_code: {completed.returncode}\n",
            encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        log_path.write_text("$ " + " ".join(cmd) + f"\n\nTimed out after {timeout}s\n", encoding="utf-8")
        return ArtifactBuildResult(
            artifact_dir=artifact_dir,
            crate_dir=crate_dir,
            built=False,
            log_path=log_path,
            diagnostics=[f"cargo build timed out after {timeout}s."],
        )
    return ArtifactBuildResult(
        artifact_dir=artifact_dir,
        crate_dir=crate_dir,
        built=completed.returncode == 0,
        log_path=log_path,
        diagnostics=[] if completed.returncode == 0 else [f"cargo build exited with {completed.returncode}."],
    )


def write_denied_wallet_demo(
    card: dict[str, Any],
    artifact_root: str | Path,
    reason: str,
    dry_run: bool = False,
) -> ArtifactBuildResult:
    component = str(card.get("component") or "unknown-component")
    artifact_dir = Path(artifact_root) / _slug(component) / "wallet-demo-denied"
    if dry_run:
        return ArtifactBuildResult(
            artifact_dir=artifact_dir,
            crate_dir=None,
            built=False,
            log_path=None,
            diagnostics=["dry-run: wallet denial artifact was not written."],
        )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    decision = {
        "component": component,
        "requested_action": "build-wallet-demo",
        "allowed": False,
        "reason": reason,
        "risk": card.get("risk", {}),
        "message": "PACTA refused to create a wallet demo from insufficient proof coverage.",
    }
    (artifact_dir / "decision.json").write_text(json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (artifact_dir / "README.md").write_text(
        "# Wallet Demo Denied\n\n"
        "PACTA refused to build a wallet demo for this component. Field or curve arithmetic evidence "
        "does not establish wallet policy, key custody, transaction construction, encoding, hashing, "
        "or full signature verification safety.\n\n"
        f"Reason: {reason}\n",
        encoding="utf-8",
    )
    return ArtifactBuildResult(
        artifact_dir=artifact_dir,
        crate_dir=None,
        built=False,
        log_path=artifact_dir / "decision.json",
        diagnostics=[reason],
    )


def _cargo_toml(crate_name: str, component: str) -> str:
    return f"""[package]
name = "{crate_name}"
version = "0.1.0"
edition = "2021"
description = "PACTA proof-gated component capsule for {component}"
license = "MIT"

[lib]
path = "src/lib.rs"
"""


def _lib_rs(card: dict[str, Any]) -> str:
    component = _rust_string(str(card.get("component") or "unknown-component"))
    repo_url = _rust_string(str(card.get("repo_url") or ""))
    risk = card.get("risk") or {}
    risk_level = _rust_string(str(risk.get("level") or "R0"))
    evidence = card.get("evidence") or {}
    evidence_mode = _rust_string(str(evidence.get("evidence_mode") or "local_or_fixture"))
    attestation_provider = _rust_string(str(evidence.get("attestation_provider") or ""))
    kind = _rust_string(str(card.get("kind") or "unknown"))
    backend = _rust_string(str(card.get("verified_backend") or ""))
    constraints = [_rust_string(str(item)) for item in risk.get("deployment_constraints") or []]
    constraints_body = ",\n    ".join(f'"{item}"' for item in constraints)
    return f"""//! Generated by PACTA.
//!
//! This crate is a proof-gated decision capsule, not a cryptographic implementation.
//! It lets downstream automation consume the verification boundary that allowed a
//! lower-layer component build.

pub const COMPONENT: &str = "{component}";
pub const REPO_URL: &str = "{repo_url}";
pub const KIND: &str = "{kind}";
pub const VERIFIED_BACKEND: &str = "{backend}";
pub const RISK_LEVEL: &str = "{risk_level}";
pub const EVIDENCE_MODE: &str = "{evidence_mode}";
pub const ATTESTATION_PROVIDER: &str = "{attestation_provider}";
pub const CLAIM_CARD_JSON: &str = include_str!("../claims.json");

pub const DEPLOYMENT_CONSTRAINTS: &[&str] = &[
    {constraints_body}
];

pub fn allowed_for_lower_layer_crypto() -> bool {{
    matches!(RISK_LEVEL, "R3" | "R4" | "R5")
}}

pub fn allowed_for_wallet_or_trading_agent() -> bool {{
    matches!(RISK_LEVEL, "R4" | "R5")
}}
"""


def _crate_readme(card: dict[str, Any]) -> str:
    risk = card.get("risk") or {}
    return f"""# PACTA Gated Component Capsule

Component: `{card.get("component")}`

Risk level: `{risk.get("level")}`

This generated crate is a consumable decision artifact. It does not implement cryptography and does not
certify a wallet. Downstream automation can import it to enforce that this component is only used inside
the proof boundary captured in `claims.json`.
"""


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-") or "component"


def _crate_suffix(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return cleaned or "component"


def _rust_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
