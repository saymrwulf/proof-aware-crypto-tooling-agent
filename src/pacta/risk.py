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
        r3_required = {"CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"}
        r4_required = list((card.get("meta") or {}).get("r4_requirements") or [])
        via = ""
        if attested:
            provider = evidence.get("attestation_provider") or "unknown provider"
            via = f" (evidence via trusted third-party provider {provider})"

        if r4_required and set(r4_required).issubset(names):
            blockers.extend(f"Missing or unchecked certificate: {name}" for name in missing)
            r4_residuals = [
                "SHA-512 enters the apex theorems as an opaque oracle; the hash implementation itself is unverified.",
                "Wire parse/filter outcomes are hypothesis-parametric; parser byte-level specs are not yet certified.",
                "Charon/Aeneas translation faithfulness and the production-path-to-verified-path mapping remain trusted base.",
                "No side-channel, reproducible-build, or operational assurance (those gate R5).",
            ]
            return RiskAssessment(
                "R4",
                "The full four-tier signature apex (byte apex, half-lift, point equation, full decompress lift) plus the "
                "constructive encoding/decoding chain and scalar arithmetic are proven with every certificate's axiom cone "
                "pinned to its documented boundary" + via + ". Residual R5 gaps are listed as blockers.",
                blockers + r4_residuals,
                constraints,
            )

        if r3_required.issubset(names):
            blockers.extend(f"Missing or unchecked certificate: {name}" for name in missing)
            full_eddsa_excluded = any("eddsa" in item or "signature" in item or "signing" in item for item in exclusions)
            if not full_eddsa_excluded and not r4_required:
                blockers.append("Full EdDSA boundary is not explicitly excluded in the claim card.")
            if r4_required:
                absent = sorted(set(r4_required) - names)
                blockers.append(
                    "R4 requires the full apex tier set; not proven-and-boundary-clean here: " + ", ".join(absent)
                )
            return RiskAssessment(
                "R3",
                "Configured field and Edwards implementation certificates are proven and axiom-clean for a specific "
                "lower-layer backend boundary" + via + ".",
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
