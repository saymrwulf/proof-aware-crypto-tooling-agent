from pacta.config import RepoConfig, load_config
from pacta.profiles import get_profile


def test_ed25519_profile_defaults():
    profile = get_profile("ed25519")
    assert "Proofs.FieldMain" in profile.axiom_imports
    assert "CurveFieldProofs.fieldImplementation" in profile.default_certificates
    assert any("Full EdDSA" in exclusion for exclusion in profile.exclusions)


def test_repo_config_merges_backend_warning():
    repo = RepoConfig(
        name="risc0-ed25519-verified",
        kind="ed25519",
        backend_warning="pure Rust path only; do not treat zkVM accelerator/syscall path as verified",
    )
    profile = get_profile("ed25519", repo)
    assert any("zkVM" in item for item in profile.deployment_constraints)


def test_load_examples_config():
    config = load_config("examples/repos.yaml")
    assert config.repo_named("dalek-ed25519-verified").kind == "ed25519"
    assert config.repo_named("pasta-pallas-verified").kind == "pasta_pallas"
