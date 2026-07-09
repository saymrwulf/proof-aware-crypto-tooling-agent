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
    assert "trusted third-party provider" in card["risk"]["rationale"]
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


def test_unverified_head_cannot_touch_pin_store(tmp_path):
    """Regression for the paper's SS5.4 precondition: the pin-store state
    machine (including permanent poisoning) runs only on a VALIDLY SIGNED
    head. A forged head at the pinned size must not poison the pin."""
    import json

    from pacta.signing import generate_ed25519_keypair
    from pacta_provider.transparency_log import TransparencyLog

    key, pub = tmp_path / "log.key", tmp_path / "log.pub"
    generate_ed25519_keypair(key, pub)
    log = TransparencyLog(tmp_path / "log")
    log.init("example-proof-checker.invalid", pub)
    att_path = "examples/dalek-ed25519.attestation.yaml"
    receipt_path = tmp_path / "receipt.yaml"
    log.append_attestation(att_path, key, pub, receipt_out=receipt_path)

    raw = load_attestation(att_path)
    store = tmp_path / "pins.json"
    kwargs = dict(
        path=att_path,
        trusted_provider="example-proof-checker.invalid",
        allow_unsigned=True,
        transparency_receipt_path=receipt_path,
        transparency_log_public_key_path=pub,
        sth_store_path=store,
    )

    def _pin():
        return next(iter(json.loads(store.read_text())["logs"].values()))

    # Control: a validly signed head reaches the store and pins.
    result = validate_attestation(raw, _repo(), **kwargs)
    assert store.exists(), result.diagnostics
    pinned = _pin()
    assert "poisoned" not in pinned
    honest_root = pinned["root_hash"]

    # Attack: same size, different root => signature no longer verifies.
    # Before the fix this PERMANENTLY POISONED the pin (unauthenticated DoS).
    from pacta.yamlio import dump_data, load_data

    forged = load_data(receipt_path)
    forged["sth"]["root_hash"] = "ab" * 32
    forged_path = tmp_path / "forged-receipt.yaml"
    dump_data(forged, forged_path)
    result = validate_attestation(raw, _repo(), **{**kwargs, "transparency_receipt_path": forged_path})
    assert not result.accepted
    assert any("pin store not consulted or updated" in d for d in result.diagnostics)
    pinned = _pin()
    assert "poisoned" not in pinned  # the pin survived the forgery
    assert pinned["root_hash"] == honest_root
    assert result.evidence.get("sth_store") == "skipped_unverified_head"
