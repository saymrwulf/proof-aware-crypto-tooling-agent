from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


RISK_ORDER = ["R0", "R1", "R2", "R3", "R4", "R5"]


def risk_at_least(level: str, threshold: str) -> bool:
    try:
        return RISK_ORDER.index(level) >= RISK_ORDER.index(threshold)
    except ValueError:
        return False


@dataclass(slots=True)
class RiskAssessment:
    level: str
    rationale: str
    blockers: list[str] = field(default_factory=list)
    deployment_constraints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "rationale": self.rationale,
            "blockers": self.blockers,
            "deployment_constraints": self.deployment_constraints,
        }


def score_claim_card(card: dict[str, Any]) -> RiskAssessment:
    kind = card.get("kind", "unknown")
    certificates = card.get("certificates") or []
    exclusions = [str(item).lower() for item in card.get("exclusions") or []]
    replay_blockers = list((card.get("evidence") or {}).get("replay_blockers") or [])
    constraints = list(card.get("risk", {}).get("deployment_constraints") or [])
    evidence = card.get("evidence") or {}
    attested = evidence.get("evidence_mode") == "third_party_attestation"
    blockers: list[str] = []

    if replay_blockers:
        blockers.extend(replay_blockers)
        if any(_is_attestation_blocker(blocker) for blocker in replay_blockers):
            return RiskAssessment(
                "R0",
                "Third-party attestation evidence was supplied but not accepted, so no usable verification evidence is available.",
                blockers,
                constraints,
            )
        if any(_is_verifier_capability_blocker(blocker) for blocker in replay_blockers):
            return RiskAssessment(
                "R0",
                "Local verifier capability is unavailable, so no usable machine-checked replay evidence was produced on this machine.",
                blockers,
                constraints,
            )

    clean_proven = [
        cert
        for cert in certificates
        if cert.get("status") == "proven" and cert.get("axiom_status") == "clean"
    ]
    failed = [cert.get("name", "<unknown>") for cert in certificates if cert.get("status") == "failed"]
    dirty = [cert.get("name", "<unknown>") for cert in certificates if cert.get("axiom_status") == "dirty"]
    missing = [cert.get("name", "<unknown>") for cert in certificates if cert.get("status") in {"missing", "unknown"}]

    if failed:
        blockers.append("Certificate replay failed: " + ", ".join(failed))
    if dirty:
        blockers.append("Unexpected axioms observed: " + ", ".join(dirty))

    if not certificates:
        if kind == "pasta_pallas":
            return RiskAssessment(
                "R2",
                "Pallas/Pasta foundation profile exists, but no aggregate production field certificate was configured.",
                ["No configured aggregate certificate."],
                constraints,
            )
        return RiskAssessment("R0", "No formal certificates were configured or observed.", ["No usable evidence."], constraints)

    if not clean_proven:
        level = "R2" if kind in {"ed25519", "pasta_pallas"} else "R0"
        rationale = "Formal artifact boundary is known, but no configured certificate is both proven and axiom-clean."
        blockers.extend(f"Missing or unchecked certificate: {name}" for name in missing)
        return RiskAssessment(level, rationale, blockers or ["No axiom-clean certificate evidence."], constraints)

    if kind == "ed25519":
        names = {cert.get("name") for cert in clean_proven}
        required = {"CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"}
        if required.issubset(names):
            blockers.extend(f"Missing or unchecked certificate: {name}" for name in missing)
            full_eddsa_excluded = any("eddsa" in item or "signature" in item for item in exclusions)
            if not full_eddsa_excluded:
                blockers.append("Full EdDSA boundary is not explicitly excluded in the claim card.")
            if attested:
                provider = evidence.get("attestation_provider") or "unknown provider"
                return RiskAssessment(
                    "R3",
                    f"Trusted third-party provider {provider} attests that configured field and Edwards certificates are proven and axiom-clean for a specific lower-layer backend boundary.",
                    blockers,
                    constraints,
                )
            return RiskAssessment(
                "R3",
                "Configured field and Edwards implementation certificates are proven and axiom-clean for a specific lower-layer backend boundary.",
                blockers,
                constraints,
            )
        blockers.append("Ed25519 profile requires both fieldImplementation and edwardsImplementation for the expected R3 arithmetic classification.")
        return RiskAssessment("R2", "Some formal Ed25519 evidence is present, but the expected field plus Edwards certificate pair is incomplete.", blockers, constraints)

    if kind == "pasta_pallas":
        aggregate = [
            cert
            for cert in clean_proven
            if "fieldImplementation" in str(cert.get("name")) or "field_implementation" in str(cert.get("name"))
        ]
        if aggregate:
            return RiskAssessment(
                "R3",
                "An aggregate Pallas/Pasta field certificate is proven and axiom-clean, but end-to-end protocol coverage is still out of scope.",
                blockers,
                constraints,
            )
        return RiskAssessment(
            "R2",
            "Pallas/Pasta formal evidence is present, but no aggregate production field implementation certificate was observed.",
            blockers or ["No aggregate fieldImplementation-style certificate."],
            constraints,
        )

    return RiskAssessment(
        "R2",
        "At least one certificate is proven and axiom-clean, but this component has no stronger profile-specific classification.",
        blockers,
        constraints,
    )


def _is_verifier_capability_blocker(blocker: str) -> bool:
    lowered = blocker.lower()
    return any(
        token in lowered
        for token in (
            "env_script",
            "environment script",
            "neither lean nor lake",
            "missing lean dependency",
            "unknown module prefix",
            "missing verifier capability",
        )
    )


def _is_attestation_blocker(blocker: str) -> bool:
    lowered = blocker.lower()
    return "attestation" in lowered or "trusted provider" in lowered
