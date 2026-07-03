from __future__ import annotations

from typing import Any


def render_markdown(card: dict[str, Any]) -> str:
    risk = card.get("risk", {})
    evidence = card.get("evidence", {})
    meta = card.get("meta", {})
    lines: list[str] = [
        f"# {card.get('component', 'Component')}",
        "",
        "## Verdict",
        "",
        f"Residual risk: **{risk.get('level', 'R0')}**",
        "",
        str(risk.get("rationale", "No rationale recorded.")),
        "",
        "## Proven claims",
        "",
        *_bullets(card.get("guarantees") or ["No proven claims recorded."]),
        "",
        "## Preconditions",
        "",
        *_bullets(card.get("preconditions") or ["No preconditions recorded."]),
        "",
        "## Exclusions",
        "",
        *_bullets(card.get("exclusions") or ["No exclusions recorded."]),
        "",
        "## Trusted base",
        "",
        *_bullets(card.get("trusted_base") or ["No trusted base recorded."]),
        "",
        "## Axiom audit",
        "",
    ]
    for cert in card.get("certificates") or []:
        observed = ", ".join(cert.get("observed_axioms") or [])
        expected = ", ".join(cert.get("expected_axioms") or [])
        lines.extend(
            [
                f"- `{cert.get('name')}`: status `{cert.get('status')}`, axioms `{cert.get('axiom_status')}`",
                f"  Observed: {observed or 'none recorded'}",
                f"  Expected: {expected or 'none recorded'}",
            ]
        )
    lines.extend(
        [
            "",
            "## Replay and attestation status",
            "",
            f"- Evidence mode: {evidence.get('evidence_mode') or 'local_or_fixture'}",
            f"- Attestation provider: {evidence.get('attestation_provider') or 'not used'}",
            f"- Attestation signature: {evidence.get('attestation_signature_status') or 'not used'}",
            f"- Lean: {evidence.get('lean_version') or 'not detected'}",
            f"- Lake: {evidence.get('lake_version') or 'not detected'}",
            f"- Check log: {evidence.get('check_log_path') or 'not recorded'}",
            f"- Axiom log: {evidence.get('axiom_log_path') or 'not recorded'}",
            "",
            "## Deployment constraints",
            "",
            *_bullets(risk.get("deployment_constraints") or ["No deployment constraints recorded."]),
            "",
            "## Residual risk score",
            "",
            f"`{risk.get('level', 'R0')}`",
            "",
        ]
    )
    blockers = risk.get("blockers") or []
    if blockers:
        lines.extend(["Blockers:", "", *_bullets(blockers), ""])
    lines.extend(
        [
            "## What would invalidate this evidence",
            "",
            *_bullets(meta.get("what_would_invalidate_this_evidence") or ["No invalidation conditions recorded."]),
            "",
            "## Next proof milestones",
            "",
            *_bullets(meta.get("next_proof_milestones") or ["No proof milestones recorded."]),
            "",
        ]
    )
    return "\n".join(lines)


def _bullets(values: list[str]) -> list[str]:
    return [f"- {value}" for value in values]
