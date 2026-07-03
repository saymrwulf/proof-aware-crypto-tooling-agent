import json

from pacta.artifact import build_proof_gated_capsule


def test_capsule_source_written_when_cargo_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("pacta.artifact.shutil.which", lambda name: None)
    card = {
        "component": "dalek-ed25519-verified",
        "repo_url": "https://github.com/saymrwulf/dalek-ed25519-verified.git",
        "kind": "ed25519",
        "verified_backend": "serial/u64",
        "risk": {
            "level": "R3",
            "deployment_constraints": ["Use verified serial/u64 backend only."],
        },
    }
    result = build_proof_gated_capsule(card, tmp_path)
    assert not result.built
    assert result.crate_dir is not None
    assert (result.crate_dir / "Cargo.toml").exists()
    assert (result.crate_dir / "src" / "lib.rs").exists()
    claims = json.loads((result.crate_dir / "claims.json").read_text(encoding="utf-8"))
    assert claims["risk"]["level"] == "R3"
