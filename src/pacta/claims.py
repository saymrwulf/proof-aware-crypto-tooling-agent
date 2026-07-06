from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .attestation import AttestationResult
from .config import RepoConfig
from .lean import AxiomAuditResult, CertificateAxiomResult, LeanCheckResult, detect_tools
from .manifest import VerificationLayout
from .profiles import get_profile
from .repo import git_commit
from .risk import score_claim_card


@dataclass(slots=True)
class CertificateClaim:
    name: str
    status: str = "unknown"
    axiom_status: str = "not_checked"
    observed_axioms: list[str] = field(default_factory=list)
    expected_axioms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "axiom_status": self.axiom_status,
            "observed_axioms": self.observed_axioms,
            "expected_axioms": self.expected_axioms,
        }


def build_claim_card(
    repo: RepoConfig,
    local_path: str | Path,
    layout: VerificationLayout | None = None,
    lean_check: LeanCheckResult | None = None,
    axiom_audit: AxiomAuditResult | None = None,
    attestation: AttestationResult | None = None,
    offline_fixture: bool = False,
) -> dict[str, Any]:
    path = Path(local_path)
    profile = get_profile(repo.kind, repo)
    tools = detect_tools()
    certs = _certificate_claims(repo, axiom_audit, offline_fixture, attestation)
    scanned_files = layout.relative_files() if layout else []
    attestation_evidence = attestation.evidence if attestation else {}
    card: dict[str, Any] = {
        "component": repo.name,
        "repo_url": repo.url,
        "local_path": str(path),
        "repo_commit": attestation.repo_commit if attestation and attestation.repo_commit else (None if offline_fixture else git_commit(path)),
        "verification_dir": repo.verification_dir,
        "kind": repo.kind,
        "verified_backend": repo.verified_backend,
        "certificates": [cert.to_dict() for cert in certs],
        "guarantees": profile.guarantees,
        "preconditions": profile.preconditions,
        "exclusions": profile.exclusions,
        "trusted_base": [*profile.trusted_base, *(attestation.trusted_base if attestation and attestation.accepted else [])],
        "evidence": {
            "lean_version": attestation_evidence.get("lean_version") or tools.lean_version,
            "lake_version": attestation_evidence.get("lake_version") or tools.lake_version,
            "check_log_path": attestation_evidence.get("check_log_path") or (lean_check.log_path if lean_check else None),
            "axiom_log_path": attestation_evidence.get("axiom_log_path") or (axiom_audit.log_path if axiom_audit else None),
            "replay_blockers": _replay_blockers(lean_check, axiom_audit, attestation),
            "scanned_files": scanned_files,
            **(attestation_evidence if attestation else {"evidence_mode": "local_or_fixture"}),
        },
        "risk": {
            "level": "R0",
            "rationale": "Not scored yet.",
            "blockers": [],
            "deployment_constraints": profile.deployment_constraints,
        },
        "meta": {
            "profile_axiom_imports": profile.axiom_imports,
            "r4_requirements": profile.r4_requirements,
            "what_would_invalidate_this_evidence": profile.invalidation_conditions,
            "next_proof_milestones": profile.next_milestones,
        },
    }
    assessment = score_claim_card(card)
    if not _has_axiom_clean_certificate(card) and assessment.level in {"R0", "R1", "R2"}:
        card["guarantees"] = ["No configured certificate was replayed and axiom-clean in this run."]
    card["risk"] = assessment.to_dict()
    return card


def _certificate_claims(
    repo: RepoConfig,
    axiom_audit: AxiomAuditResult | None,
    offline_fixture: bool,
    attestation: AttestationResult | None,
) -> list[CertificateClaim]:
    profile = get_profile(repo.kind, repo)
    names = repo.certificates or profile.default_certificates
    if attestation and attestation.accepted:
        by_name = {cert["name"]: cert for cert in attestation.certificates}
        return [
            CertificateClaim(
                name=name,
                status=str(by_name.get(name, {}).get("status", "missing")),
                # axiom_status was re-derived against LOCAL policy in
                # attestation._normalize_certificate; use it verbatim.
                axiom_status=str(by_name.get(name, {}).get("axiom_status", "not_checked")),
                observed_axioms=list(by_name.get(name, {}).get("observed_axioms") or []),
                expected_axioms=list(profile.expected_axioms_for(name)),
            )
            for name in names
        ]
    if axiom_audit:
        by_name = {cert.name: cert for cert in axiom_audit.certificates}
        return [_from_axiom_result(name, by_name.get(name), profile.expected_axioms_for(name)) for name in names]
    if offline_fixture:
        return [
            CertificateClaim(
                name=name,
                status="proven",
                axiom_status="clean",
                observed_axioms=list(profile.expected_axioms_for(name)),
                expected_axioms=list(profile.expected_axioms_for(name)),
            )
            for name in names
        ]
    return [
        CertificateClaim(
            name=name,
            status="unknown",
            axiom_status="not_checked",
            observed_axioms=[],
            expected_axioms=list(profile.expected_axioms_for(name)),
        )
        for name in names
    ]


def _from_axiom_result(name: str, result: CertificateAxiomResult | None, expected_axioms: list[str]) -> CertificateClaim:
    if not result:
        return CertificateClaim(name=name, status="missing", axiom_status="not_checked", expected_axioms=expected_axioms)
    return CertificateClaim(
        name=name,
        status=result.status,
        axiom_status=result.axiom_status,
        observed_axioms=result.observed_axioms,
        expected_axioms=result.expected_axioms,
    )


def _has_axiom_clean_certificate(card: dict[str, Any]) -> bool:
    return any(
        cert.get("status") == "proven" and cert.get("axiom_status") == "clean"
        for cert in card.get("certificates") or []
    )


def _replay_blockers(
    lean_check: LeanCheckResult | None,
    axiom_audit: AxiomAuditResult | None,
    attestation: AttestationResult | None,
) -> list[str]:
    blockers: list[str] = []
    if attestation and not attestation.accepted:
        blockers.extend(attestation.diagnostics)
    if lean_check:
        blockers.extend(lean_check.diagnostics)
        if lean_check.missing_tool:
            blockers.append(f"Missing verifier capability: {lean_check.missing_tool}")
    if axiom_audit:
        blockers.extend(axiom_audit.diagnostics)
        if axiom_audit.missing_tool:
            blockers.append(f"Missing verifier capability: {axiom_audit.missing_tool}")
    seen: set[str] = set()
    out: list[str] = []
    for blocker in blockers:
        if blocker and blocker not in seen:
            seen.add(blocker)
            out.append(blocker)
    return out
