from pacta.attestation import _normalize_certificate
from pacta.config import RepoConfig
from pacta.claims import build_claim_card
from pacta.profiles import get_profile
from pacta.profiles.ed25519 import APEX_BOUNDARIES, APEX_TIER_CERTIFICATES, R4_REQUIREMENTS


def _repo(boundary="dalek-wrappers"):
    return RepoConfig(name="dalek-ed25519-verified", kind="ed25519", apex_boundary=boundary)


def test_apex_tiers_expect_the_fork_boundary_not_standard_three():
    profile = get_profile("ed25519", _repo())
    for tier in APEX_TIER_CERTIFICATES:
        expected = profile.expected_axioms_for(tier)
        assert "ed25519.Signature" in expected
        assert set(expected) == set(APEX_BOUNDARIES["dalek-wrappers"])
    # non-apex certificates stay standard-three
    assert profile.expected_axioms_for("CurveFieldProofs.fieldImplementation") == [
        "propext", "Classical.choice", "Quot.sound",
    ]


def test_unknown_boundary_is_a_hard_error():
    import pytest

    with pytest.raises(KeyError):
        get_profile("ed25519", _repo(boundary="no-such-boundary"))


def test_agent_rederives_axiom_status_against_local_policy():
    profile = get_profile("ed25519", _repo())
    boundary = list(APEX_BOUNDARIES["dalek-wrappers"])
    lying = {
        "name": "CurveFieldProofs.verify_accepts_iff",
        "status": "proven",
        "axiom_status": "clean",  # the provider's verdict is never trusted
        "observed_axioms": boundary + ["backend.simd.avx2_dispatch"],
    }
    out = _normalize_certificate(lying, profile)
    assert out["axiom_status"] == "dirty"
    assert out["provider_axiom_verdict"] == "clean"
    honest = dict(lying, observed_axioms=boundary)
    assert _normalize_certificate(honest, profile)["axiom_status"] == "clean"
    # a boundary axiom MISSING is just as dirty as an extra one
    short = dict(lying, observed_axioms=boundary[:-1])
    assert _normalize_certificate(short, profile)["axiom_status"] == "dirty"
    # "proven" with no observed axioms cannot be re-derived: distrust
    blind = {"name": "CurveFieldProofs.verify_accepts_iff", "status": "proven", "axiom_status": "clean"}
    assert _normalize_certificate(blind, profile)["axiom_status"] == "unverifiable"


def test_full_fixture_scores_r4_and_partial_scores_r3(tmp_path):
    full = _repo()
    card = build_claim_card(full, tmp_path, offline_fixture=True)
    assert card["risk"]["level"] == "R4"
    assert any("SHA-512" in b for b in card["risk"]["blockers"])
    assert set(R4_REQUIREMENTS) <= {c["name"] for c in card["certificates"]}

    partial = RepoConfig(
        name="dalek-ed25519-verified",
        kind="ed25519",
        apex_boundary="dalek-wrappers",
        certificates=["CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"],
    )
    card = build_claim_card(partial, tmp_path, offline_fixture=True)
    assert card["risk"]["level"] == "R3"
    assert any("R4 requires the full apex tier set" in b for b in card["risk"]["blockers"])


def test_verdict_never_copies_operator_labels():
    """Prop 2 (verdict integrity), literally: the cleanliness verdict is a
    function of (observed cone, local allowed set) in EVERY branch. The
    operator's axiom_status label is never copied - not even for
    non-proven certificates - and a missing cone is always unverifiable."""
    profile = get_profile("ed25519", _repo())
    failed_flattered = {
        "name": "CurveFieldProofs.verify_accepts_iff",
        "status": "failed",
        "axiom_status": "clean",  # operator flattery, must not pass through
    }
    out = _normalize_certificate(failed_flattered, profile)
    assert out["axiom_status"] == "unverifiable"
    assert out["provider_axiom_verdict"] == "clean"  # recorded, not believed

    failed_with_cone = {
        "name": "CurveFieldProofs.verify_accepts_iff",
        "status": "failed",
        "axiom_status": "clean",
        "observed_axioms": ["propext", "sorryAx"],
    }
    assert _normalize_certificate(failed_with_cone, profile)["axiom_status"] == "dirty"
