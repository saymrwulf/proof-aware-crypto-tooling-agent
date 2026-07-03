from pacta.claims import build_claim_card
from pacta.config import RepoConfig
from pacta.lean import AxiomAuditResult, CertificateAxiomResult


def test_failed_replay_does_not_emit_profile_guarantees(tmp_path):
    repo = RepoConfig(
        name="dalek-ed25519-verified",
        kind="ed25519",
        certificates=["CurveFieldProofs.fieldImplementation"],
    )
    audit = AxiomAuditResult(
        attempted=True,
        ok=False,
        missing_tool=None,
        certificates=[
            CertificateAxiomResult(
                name="CurveFieldProofs.fieldImplementation",
                status="failed",
                axiom_status="not_checked",
                observed_axioms=[],
                expected_axioms=["propext", "Classical.choice", "Quot.sound"],
            )
        ],
        log_path=None,
    )
    card = build_claim_card(repo, tmp_path, axiom_audit=audit)
    assert card["risk"]["level"] == "R2"
    assert card["guarantees"] == ["No configured certificate was replayed and axiom-clean in this run."]
