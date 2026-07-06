from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import RepoConfig
from .profiles import get_profile
from .signing import verify_attestation_signature
from .transparency import load_receipt, verify_receipt
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
    coverage_warnings: list[str] = field(default_factory=list)


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
    transparency_receipt_path: str | Path | None = None,
    transparency_log_public_key_path: str | Path | None = None,
    require_transparency_signatures: str = "ed25519",
    require_transparency_receipt: bool = False,
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
    profile = get_profile(repo.kind, repo)
    expected_names = set(repo.certificates or profile.default_certificates)
    observed_names = {str(cert.get("name")) for cert in certs if isinstance(cert, dict)}
    missing = sorted(expected_names - observed_names)
    coverage_warnings: list[str] = []
    if missing:
        # Partial coverage is NOT a rejection: the uncovered certificates
        # simply stay unproven in the claim card and the risk score degrades
        # accordingly (e.g. an arithmetic-only attestation caps at R3).
        coverage_warnings.append(
            "Attestation does not cover configured certificate(s): " + ", ".join(missing)
        )

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

    transparency_evidence: dict[str, Any] = {}
    if require_transparency_receipt and not transparency_receipt_path:
        diagnostics.append("Transparency receipt is required by policy but was not supplied.")
    if transparency_receipt_path:
        if not transparency_log_public_key_path:
            diagnostics.append("Transparency receipt verification requires --transparency-log-public-key.")
        else:
            receipt = load_receipt(transparency_receipt_path)
            receipt_result = verify_receipt(
                raw,
                receipt,
                transparency_log_public_key_path,
                require_signatures=require_transparency_signatures,
            )
            transparency_evidence = receipt_result.evidence()
            transparency_evidence["transparency_receipt_path"] = str(transparency_receipt_path)
            if not receipt_result.accepted:
                diagnostics.extend(receipt_result.diagnostics)

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
        "attestation_coverage_warnings": coverage_warnings,
        **transparency_evidence,
    }
    trusted_base = []
    if accepted:
        trusted_base.append(f"Third-party proof-checking attestation provider: {provider}.")
        trusted_base.append("Provider environment, replay implementation, signing key custody, and log retention.")
        if transparency_receipt_path:
            trusted_base.append("Transparency log append-only behavior, signed tree head key custody, and monitor/auditor availability.")
    return AttestationResult(
        accepted=accepted,
        provider=str(provider) if provider else None,
        diagnostics=diagnostics,
        certificates=[_normalize_certificate(cert, profile) for cert in certs if isinstance(cert, dict)],
        evidence=evidence,
        trusted_base=trusted_base,
        repo_commit=subject.get("repo_commit"),
        coverage_warnings=coverage_warnings,
    )


def _normalize_certificate(cert: dict[str, Any], profile: Any) -> dict[str, Any]:
    """Normalize a provider-reported certificate against LOCAL policy.

    The provider is trusted for its OBSERVATION (which axioms #print axioms
    reported); it is never trusted for the VERDICT. axiom_status is re-derived
    here by comparing the observed axioms against this agent's own allowed
    set for the certificate - a provider that labels a dirty cone "clean"
    gains nothing.
    """
    name = str(cert.get("name") or "")
    status = str(cert.get("status") or "unknown")
    observed = [str(a) for a in (cert.get("observed_axioms") or [])]
    expected = profile.expected_axioms_for(name)
    if status == "proven" and observed:
        axiom_status = "clean" if sorted(observed) == sorted(expected) else "dirty"
    elif status == "proven":
        # proven with no observed axioms reported: cannot re-derive; distrust.
        axiom_status = "unverifiable"
    else:
        axiom_status = str(cert.get("axiom_status") or "not_checked")
    provider_verdict = str(cert.get("axiom_status") or "not_stated")
    return {
        "name": name,
        "status": status,
        "axiom_status": axiom_status,
        "observed_axioms": observed,
        "expected_axioms": list(expected),
        "provider_axiom_verdict": provider_verdict,
    }
