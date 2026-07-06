from pacta.config import RepoConfig, load_config
from pacta.profiles import get_profile


def test_ed25519_profile_defaults():
    profile = get_profile("ed25519")
    assert "Proofs.FieldMain" in profile.axiom_imports
    assert "CurveFieldProofs.fieldImplementation" in profile.default_certificates
    # Since phase 2 landed in the corpus, EdDSA verification IS proven; the
    # honest exclusions are the hash oracle, the parse hypotheses, and signing.
    assert any("SHA-512" in exclusion for exclusion in profile.exclusions)
    assert any("hypothesis-parametric" in exclusion for exclusion in profile.exclusions)
    assert any("Signing" in exclusion for exclusion in profile.exclusions)
    assert "CurveFieldProofs.verify_accepts_iff_decompress" in profile.default_certificates
    assert "CurveFieldProofs.verify_accepts_iff_decompress" in profile.r4_requirements


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
    assert config.repo_named("dalek-ed25519-verified").env_script == "~/aeneas-toolchain/env.sh"
    assert config.repo_named("pasta-pallas-verified").kind == "pasta_pallas"
