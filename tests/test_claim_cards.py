from pacta.claims import build_claim_card
from pacta.config import RepoConfig
from pacta.yamlio import dump_data, load_data


def test_offline_claim_card_serializes(tmp_path):
    repo = RepoConfig(
        name="dalek-ed25519-verified",
        url="https://github.com/saymrwulf/dalek-ed25519-verified.git",
        kind="ed25519",
        verified_backend="serial/u64",
        certificates=["CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"],
    )
    card = build_claim_card(repo, tmp_path / "missing", offline_fixture=True)
    assert card["risk"]["level"] == "R3"
    out = tmp_path / "claims.yaml"
    dump_data(card, out)
    loaded = load_data(out)
    assert loaded["component"] == "dalek-ed25519-verified"
    assert loaded["certificates"][0]["axiom_status"] == "clean"
