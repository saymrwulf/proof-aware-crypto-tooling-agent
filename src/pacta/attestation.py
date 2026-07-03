from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import RepoConfig
from .signing import verify_attestation_signature
from .yamlio import load_data


@dataclass(slots=True)
class AttestationResult:
    accepted: bool
    provider: str | None
    diagnostics: list[str] = field(default_factory=list)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    trusted_base: list[str] = field(default_factory=list)
    repo_commit: str | None = None


def load_attestation(path: str | Path) -> dict[str, Any]:
    raw = load_data(path)
    if not isinstance(raw, dict):
        raise ValueError(f"Attestation must be a mapping: {path}")
    return raw


def validate_attestation(
    raw: dict[str, Any],
    repo: RepoConfig,
    path: str | Path | None = None,
    trusted_provider: str | None = None,
    public_key_path: str | Path | None = None,
    allow_unsigned: bool = False,
) -> AttestationResult:
    provider = raw.get("provider")
    subject = raw.get("subject") or {}
    diagnostics: list[str] = []
    if not provider:
        diagnostics.append("Attestation is missing provider.")
    if trusted_provider is None:
        diagnostics.append("No trusted attestation provider was explicitly configured.")
    elif provider != trusted_provider:
        diagnostics.append(f"Attestation provider '{provider}' does not match trusted provider '{trusted_provider}'.")
    if subject.get("component") and subject.get("component") != repo.name:
        diagnostics.append(f"Attestation subject component '{subject.get('component')}' does not match repo '{repo.name}'.")
    if repo.url and subject.get("repo_url") and subject.get("repo_url") != repo.url:
        diagnostics.append("Attestation subject repo_url does not match config.")
    if subject.get("verification_dir") and subject.get("verification_dir") != repo.verification_dir:
        diagnostics.append("Attestation subject verification_dir does not match config.")

    certs = raw.get("certificates") or []
    if not isinstance(certs, list) or not certs:
        diagnostics.append("Attestation contains no certificate results.")
        certs = []
    expected_names = set(repo.certificates)
    observed_names = {str(cert.get("name")) for cert in certs if isinstance(cert, dict)}
    missing = sorted(expected_names - observed_names)
    if missing:
        diagnostics.append("Attestation is missing configured certificate(s): " + ", ".join(missing))

    signature = raw.get("signature") or {}
    environment = raw.get("environment") or {}
    signature_status = signature.get("status", "not_checked")
    if public_key_path:
        ok, error = verify_attestation_signature(raw, public_key_path)
        if ok:
            signature_status = "verified"
        else:
            diagnostics.append(f"Attestation signature verification failed: {error}")
    elif signature_status == "signed":
        diagnostics.append("Signed attestation requires --attestation-public-key.")
    elif signature_status == "not_implemented":
        if allow_unsigned:
            signature_status = "not_implemented"
        else:
            diagnostics.append("Unsigned attestation requires --allow-unsigned-attestation.")
    elif signature_status != "verified":
        diagnostics.append(f"Attestation signature status is not acceptable: {signature_status}")

    accepted = not diagnostics
    evidence = {
        "evidence_mode": "third_party_attestation",
        "attestation_provider": provider,
        "attestation_path": str(path) if path else None,
        "attestation_signature_status": signature_status,
        "attestation_log_url": raw.get("log_url") or signature.get("log_url"),
        "attestation_issued_at": raw.get("issued_at"),
        "check_log_path": (raw.get("replay") or {}).get("check_log_path"),
        "axiom_log_path": (raw.get("replay") or {}).get("axiom_log_path"),
        "lean_version": environment.get("lean_version"),
        "lake_version": environment.get("lake_version"),
    }
    trusted_base = []
    if accepted:
        trusted_base.append(f"Third-party proof-checking attestation provider: {provider}.")
        trusted_base.append("Provider environment, replay implementation, signing key custody, and log retention.")
    return AttestationResult(
        accepted=accepted,
        provider=str(provider) if provider else None,
        diagnostics=diagnostics,
        certificates=[_normalize_certificate(cert, repo.expected_axioms) for cert in certs if isinstance(cert, dict)],
        evidence=evidence,
        trusted_base=trusted_base,
        repo_commit=subject.get("repo_commit"),
    )


def _normalize_certificate(cert: dict[str, Any], expected_axioms: list[str]) -> dict[str, Any]:
    return {
        "name": str(cert.get("name") or ""),
        "status": str(cert.get("status") or "unknown"),
        "axiom_status": str(cert.get("axiom_status") or "not_checked"),
        "observed_axioms": list(cert.get("observed_axioms") or []),
        "expected_axioms": list(cert.get("expected_axioms") or expected_axioms),
    }
