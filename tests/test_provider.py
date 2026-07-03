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
