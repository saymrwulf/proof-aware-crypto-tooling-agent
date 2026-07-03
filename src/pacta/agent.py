from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .artifact import ArtifactBuildResult, build_proof_gated_capsule, write_denied_wallet_demo
from .risk import risk_at_least


@dataclass(slots=True)
class AgentDecision:
    requested_action: str
    allowed: bool
    risk_level: str
    rationale: str
    consequences: list[str] = field(default_factory=list)
    artifact: ArtifactBuildResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_action": self.requested_action,
            "allowed": self.allowed,
            "risk_level": self.risk_level,
            "rationale": self.rationale,
            "consequences": self.consequences,
            "artifact": self.artifact.to_dict() if self.artifact else None,
        }


def run_agent_action(
    card: dict[str, Any],
    action: str,
    artifact_root: str | Path,
    minimum_build_risk: str = "R3",
    timeout: int = 120,
    dry_run: bool = False,
) -> AgentDecision:
    risk = card.get("risk") or {}
    level = str(risk.get("level") or "R0")
    if action == "build-library":
        return _build_library(card, artifact_root, level, minimum_build_risk, timeout, dry_run)
    if action == "build-wallet-demo":
        return _build_wallet_demo(card, artifact_root, level, dry_run)
    raise ValueError(f"Unsupported agent action: {action}")


def write_decision(decision: AgentDecision, artifact_root: str | Path, component: str) -> Path:
    component_dir = component_artifact_dir(artifact_root, component)
    component_dir.mkdir(parents=True, exist_ok=True)
    path = component_dir / f"agent-decision-{_slug(decision.requested_action)}.json"
    path.write_text(json.dumps(decision.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def component_artifact_dir(artifact_root: str | Path, component: str) -> Path:
    return Path(artifact_root) / _slug(component)


def _build_library(
    card: dict[str, Any],
    artifact_root: str | Path,
    level: str,
    minimum_build_risk: str,
    timeout: int,
    dry_run: bool,
) -> AgentDecision:
    if not risk_at_least(level, minimum_build_risk):
        return AgentDecision(
            requested_action="build-library",
            allowed=False,
            risk_level=level,
            rationale=f"Risk level {level} is below the build threshold {minimum_build_risk}.",
            consequences=[
                "No library artifact was built.",
                "Component remains in evaluation/quarantine state.",
            ],
        )
    artifact = build_proof_gated_capsule(card, artifact_root, timeout=timeout, dry_run=dry_run)
    return AgentDecision(
        requested_action="build-library",
        allowed=artifact.built if not dry_run else True,
        risk_level=level,
        rationale=(
            f"Risk level {level} satisfies the {minimum_build_risk} threshold for a lower-layer "
            "proof-gated library capsule."
        ),
        consequences=[
            "Generated a consumable proof-gated component capsule.",
            "Capsule permits lower-layer cryptographic use only inside the recorded theorem/backend boundary.",
            "Capsule explicitly does not permit wallet or trading-agent deployment.",
        ],
        artifact=artifact,
    )


def _build_wallet_demo(card: dict[str, Any], artifact_root: str | Path, level: str, dry_run: bool) -> AgentDecision:
    if not risk_at_least(level, "R4"):
        reason = f"Risk level {level} is below R4; wallet demos require end-to-end primitive/API coverage."
        artifact = write_denied_wallet_demo(card, artifact_root, reason, dry_run=dry_run)
        return AgentDecision(
            requested_action="build-wallet-demo",
            allowed=False,
            risk_level=level,
            rationale=reason,
            consequences=[
                "No wallet was built.",
                "A denial artifact was written so the refusal is machine-readable.",
            ],
            artifact=artifact,
        )
    artifact = build_proof_gated_capsule(card, artifact_root, dry_run=dry_run)
    return AgentDecision(
        requested_action="build-wallet-demo",
        allowed=artifact.built if not dry_run else True,
        risk_level=level,
        rationale="Risk level permits a wallet demo scaffold.",
        consequences=[
            "Generated only a policy capsule; production wallet construction still requires separate controls.",
        ],
        artifact=artifact,
    )


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value).strip("-") or "component"
