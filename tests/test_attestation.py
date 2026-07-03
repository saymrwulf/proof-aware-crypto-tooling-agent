from pacta.attestation import load_attestation, validate_attestation
from pacta.claims import build_claim_card
from pacta.config import RepoConfig
from pacta.signing import generate_ed25519_keypair, sign_attestation


def _repo():
    return RepoConfig(
        name="dalek-ed25519-verified",
        url="https://github.com/saymrwulf/dalek-ed25519-verified.git",
        kind="ed25519",
        verified_backend="serial/u64",
        certificates=["CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"],
    )


def test_trusted_attestation_can_drive_r3_claim(tmp_path):
    raw = load_attestation("examples/dalek-ed25519.attestation.yaml")
    result = validate_attestation(
        raw,
        _repo(),
        path="examples/dalek-ed25519.attestation.yaml",
        trusted_provider="example-proof-checker.invalid",
        allow_unsigned=True,
    )
    card = build_claim_card(_repo(), tmp_path, attestation=result)
    assert result.accepted
    assert card["risk"]["level"] == "R3"
    assert "Trusted third-party provider" in card["risk"]["rationale"]
    assert card["evidence"]["evidence_mode"] == "third_party_attestation"
    assert any("Third-party proof-checking" in item for item in card["trusted_base"])


def test_untrusted_attestation_scores_r0(tmp_path):
    raw = load_attestation("examples/dalek-ed25519.attestation.yaml")
    result = validate_attestation(raw, _repo(), path="examples/dalek-ed25519.attestation.yaml")
    card = build_claim_card(_repo(), tmp_path, attestation=result)
    assert not result.accepted
    assert card["risk"]["level"] == "R0"


def test_signed_attestation_requires_public_key(tmp_path):
    private_key = tmp_path / "provider.key"
    public_key = tmp_path / "provider.pub"
    generate_ed25519_keypair(private_key, public_key)
    raw = load_attestation("examples/dalek-ed25519.attestation.yaml")
    raw["provider"] = "signed-test-provider"
    raw["signature"] = {}
    signed = sign_attestation(raw, private_key, public_key)
    result = validate_attestation(signed, _repo(), trusted_provider="signed-test-provider")
    card = build_claim_card(_repo(), tmp_path, attestation=result)
    assert not result.accepted
    assert card["risk"]["level"] == "R0"
    assert any("attestation-public-key" in item for item in result.diagnostics)
