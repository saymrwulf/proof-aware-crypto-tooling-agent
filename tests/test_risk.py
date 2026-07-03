from pacta.risk import risk_at_least, score_claim_card


def test_ed25519_field_and_edwards_clean_scores_r3():
    card = {
        "kind": "ed25519",
        "certificates": [
            {"name": "CurveFieldProofs.fieldImplementation", "status": "proven", "axiom_status": "clean"},
            {"name": "CurveFieldProofs.edwardsImplementation", "status": "proven", "axiom_status": "clean"},
        ],
        "exclusions": ["full EdDSA verification"],
        "risk": {"deployment_constraints": ["Use verified serial/u64 backend only."]},
    }
    result = score_claim_card(card)
    assert result.level == "R3"
    assert "lower-layer" in result.rationale


def test_no_certificates_is_r0_for_unknown():
    result = score_claim_card({"kind": "unknown", "certificates": []})
    assert result.level == "R0"
    assert result.blockers


def test_dirty_axioms_do_not_score_r3():
    card = {
        "kind": "ed25519",
        "certificates": [
            {"name": "CurveFieldProofs.fieldImplementation", "status": "proven", "axiom_status": "dirty"},
        ],
    }
    result = score_claim_card(card)
    assert result.level == "R2"
    assert any("Unexpected axioms" in blocker for blocker in result.blockers)


def test_pasta_without_aggregate_is_foundation_r2():
    result = score_claim_card({"kind": "pasta_pallas", "certificates": []})
    assert result.level == "R2"


def test_risk_ordering():
    assert risk_at_least("R3", "R2")
    assert risk_at_least("R3", "R3")
    assert not risk_at_least("R2", "R3")
    assert not risk_at_least("RX", "R3")


def test_verifier_capability_blocker_scores_r0():
    card = {
        "kind": "ed25519",
        "certificates": [
            {"name": "CurveFieldProofs.fieldImplementation", "status": "unknown", "axiom_status": "not_checked"},
        ],
        "evidence": {"replay_blockers": ["Missing Lean dependency/module prefix: Aeneas"]},
    }
    result = score_claim_card(card)
    assert result.level == "R0"
    assert "verifier capability" in result.rationale
