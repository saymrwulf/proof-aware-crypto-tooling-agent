from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "provider" / "src"))

from pacta.attestation import validate_attestation
from pacta.config import RepoConfig
from pacta.signing import generate_ed25519_keypair, sign_attestation
from pacta.transparency import (
    consistency_proof,
    inclusion_proof,
    merkle_root,
    verify_consistency,
    verify_inclusion,
    verify_receipt,
)
from pacta_provider.transparency_log import TransparencyLog


def _repo() -> RepoConfig:
    return RepoConfig(
        name="dalek-ed25519-verified",
        url="https://github.com/saymrwulf/dalek-ed25519-verified.git",
        kind="ed25519",
        verification_dir="verification",
        verified_backend="serial/u64",
        certificates=["CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"],
    )


def _signed_attestation(tmp_path):
    private_key = tmp_path / "provider.key"
    public_key = tmp_path / "provider.pub"
    generate_ed25519_keypair(private_key, public_key)
    attestation = {
        "schema_version": 1,
        "provider": "local-test-provider",
        "subject": {
            "component": "dalek-ed25519-verified",
            "repo_url": "https://github.com/saymrwulf/dalek-ed25519-verified.git",
            "verification_dir": "verification",
        },
        "environment": {},
        "replay": {"check_ok": True, "axiom_ok": True},
        "certificates": [
            {
                "name": "CurveFieldProofs.fieldImplementation",
                "status": "proven",
                "axiom_status": "clean",
                "observed_axioms": [],
                "expected_axioms": [],
            },
            {
                "name": "CurveFieldProofs.edwardsImplementation",
                "status": "proven",
                "axiom_status": "clean",
                "observed_axioms": [],
                "expected_axioms": [],
            },
        ],
    }
    return sign_attestation(attestation, private_key, public_key), private_key, public_key


def test_rfc9162_inclusion_and_consistency_proofs_round_trip():
    leaves = [f"leaf-{index}".encode() for index in range(1, 24)]
    for tree_size in range(1, len(leaves) + 1):
        root = merkle_root(leaves[:tree_size])
        for index in range(tree_size):
            proof = inclusion_proof(leaves[:tree_size], index)
            assert verify_inclusion(leaves[index], index, tree_size, proof, root)
        for old_size in range(tree_size + 1):
            proof = consistency_proof(leaves[:tree_size], old_size)
            assert verify_consistency(old_size, tree_size, merkle_root(leaves[:old_size]), root, proof)


def test_provider_log_receipt_verifies_and_detects_tampering(tmp_path):
    attestation, private_key, public_key = _signed_attestation(tmp_path)
    attestation_path = tmp_path / "attestation.yaml"
    receipt_path = tmp_path / "receipt.yaml"
    from pacta.yamlio import dump_data

    dump_data(attestation, attestation_path)
    log = TransparencyLog(tmp_path / "log")
    log.init("local-test-provider", public_key)
    receipt = log.append_attestation(attestation_path, private_key, public_key, receipt_out=receipt_path)

    result = verify_receipt(attestation, receipt, public_key)
    assert result.accepted, result.diagnostics
    assert result.signatures["ed25519"] == "verified"

    tampered = dict(attestation)
    tampered["provider"] = "different-provider"
    tampered_result = verify_receipt(tampered, receipt, public_key)
    assert not tampered_result.accepted
    assert any("leaf hash" in diagnostic for diagnostic in tampered_result.diagnostics)


def test_validate_attestation_can_require_transparency_receipt(tmp_path):
    attestation, private_key, public_key = _signed_attestation(tmp_path)
    from pacta.yamlio import dump_data

    attestation_path = tmp_path / "attestation.yaml"
    receipt_path = tmp_path / "receipt.yaml"
    dump_data(attestation, attestation_path)
    log = TransparencyLog(tmp_path / "log")
    log.init("local-test-provider", public_key)
    log.append_attestation(attestation_path, private_key, public_key, receipt_out=receipt_path)

    accepted = validate_attestation(
        attestation,
        _repo(),
        trusted_provider="local-test-provider",
        public_key_path=public_key,
        transparency_receipt_path=receipt_path,
        transparency_log_public_key_path=public_key,
        require_transparency_receipt=True,
    )
    assert accepted.accepted, accepted.diagnostics
    assert accepted.evidence["transparency_receipt_status"] == "accepted"

    rejected = validate_attestation(
        attestation,
        _repo(),
        trusted_provider="local-test-provider",
        public_key_path=public_key,
        require_transparency_receipt=True,
    )
    assert not rejected.accepted
    assert any("Transparency receipt is required" in item for item in rejected.diagnostics)


def test_requiring_both_signatures_fails_without_ml_dsa_backend(tmp_path):
    attestation, private_key, public_key = _signed_attestation(tmp_path)
    from pacta.yamlio import dump_data

    attestation_path = tmp_path / "attestation.yaml"
    receipt_path = tmp_path / "receipt.yaml"
    dump_data(attestation, attestation_path)
    log = TransparencyLog(tmp_path / "log")
    log.init("local-test-provider", public_key)
    receipt = log.append_attestation(attestation_path, private_key, public_key, receipt_out=receipt_path)

    result = verify_receipt(attestation, receipt, public_key, require_signatures="both")
    assert not result.accepted
    assert result.signatures["ed25519"] == "verified"
    assert result.signatures["ml_dsa"] != "verified"
