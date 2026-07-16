from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "provider" / "src"))

from pacta.config import RepoConfig
from pacta.signing import generate_ed25519_keypair
from pacta_provider.discovery import discover_toolchains
from pacta_provider.service import build_attestation


def test_provider_discovery_finds_env_script(tmp_path):
    root = tmp_path / "toolchains" / "aeneas-toolchain"
    lean = root / "aeneas" / "backends" / "lean"
    lean.mkdir(parents=True)
    (lean / "lakefile.lean").write_text("", encoding="utf-8")
    (root / "env.sh").write_text(
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
        'export AENEAS_HOME="$SCRIPT_DIR/aeneas"\n',
        encoding="utf-8",
    )
    candidates = discover_toolchains([tmp_path], max_depth=5)
    assert candidates
    assert candidates[0].lean_project_dir == lean


def test_provider_builds_signed_attestation_for_fixture(tmp_path):
    private_key = tmp_path / "provider.key"
    public_key = tmp_path / "provider.pub"
    generate_ed25519_keypair(private_key, public_key)
    repo = RepoConfig(
        name="dalek-ed25519-verified",
        url="https://github.com/saymrwulf/dalek-ed25519-verified.git",
        kind="ed25519",
        verification_dir="verification",
        verified_backend="serial/u64",
        certificates=["CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"],
        axiom_imports=["Proofs.FieldMain", "Proofs.EdMain"],
        expected_axioms=[],
    )
    attestation = build_attestation(
        repo,
        Path("tests/fixtures/mini-ed25519-verified"),
        provider="local-test-provider",
        private_key=private_key,
        public_key=public_key,
        timeout=30,
        log_dir=tmp_path / "logs",
    )
    assert attestation["signature"]["status"] == "signed"
    assert attestation["certificates"][0]["status"] == "proven"
    # The leaf carries its own scope block (review round 6): the
    # profile's guarantees/exclusions/deployment_constraints must reach
    # the published leaf, not only the claim card.
    assert "scope" in attestation
    for key in ("guarantees", "exclusions", "deployment_constraints"):
        assert key in attestation["scope"]


def test_attestation_scope_carries_repo_known_status_and_exclusions(tmp_path):
    # A repo's known_status (scoped-claim wording) and known_exclusions
    # must land in the leaf's scope block. Regression for the entry-13
    # requirement that the leaf itself carry its scoped attestation text.
    private_key = tmp_path / "provider.key"
    public_key = tmp_path / "provider.pub"
    generate_ed25519_keypair(private_key, public_key)
    repo = RepoConfig(
        name="dalek-ed25519-verified",
        url="https://github.com/saymrwulf/dalek-ed25519-verified.git",
        kind="ed25519",
        verification_dir="verification",
        verified_backend="serial/u64",
        certificates=["CurveFieldProofs.fieldImplementation"],
        axiom_imports=["Proofs.FieldMain"],
        expected_axioms=[],
        known_status="SCOPE MARKER: mechanized model only, not the deployed verifier.",
        known_exclusions=["EXCLUSION MARKER: side-channel resistance"],
    )
    attestation = build_attestation(
        repo,
        Path("tests/fixtures/mini-ed25519-verified"),
        provider="local-test-provider",
        private_key=private_key,
        public_key=public_key,
        timeout=30,
        log_dir=tmp_path / "logs",
    )
    scope = attestation["scope"]
    assert any("SCOPE MARKER" in c for c in scope["deployment_constraints"])
    assert any("EXCLUSION MARKER" in e for e in scope["exclusions"])
