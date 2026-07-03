from pacta.agent import run_agent_action


def _card(level="R3"):
    return {
        "component": "dalek-ed25519-verified",
        "repo_url": "https://github.com/saymrwulf/dalek-ed25519-verified.git",
        "kind": "ed25519",
        "verified_backend": "serial/u64",
        "risk": {
            "level": level,
            "rationale": "test",
            "deployment_constraints": ["Use verified serial/u64 backend only."],
        },
    }


def test_agent_allows_r3_library_build_dry_run(tmp_path):
    decision = run_agent_action(_card("R3"), "build-library", tmp_path, dry_run=True)
    assert decision.allowed
    assert decision.artifact is not None
    assert "proof-gated library capsule" in decision.rationale


def test_agent_denies_r2_library_build(tmp_path):
    decision = run_agent_action(_card("R2"), "build-library", tmp_path)
    assert not decision.allowed
    assert decision.artifact is None
    assert "below the build threshold" in decision.rationale


def test_agent_denies_wallet_demo_below_r4(tmp_path):
    decision = run_agent_action(_card("R3"), "build-wallet-demo", tmp_path)
    assert not decision.allowed
    assert decision.artifact is not None
    assert (decision.artifact.artifact_dir / "decision.json").exists()
    assert "below R4" in decision.rationale
