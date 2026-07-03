from pacta.cli import main


def test_doctor_reports_missing_env_script(capsys):
    code = main(["doctor", "--config", "examples/repos.yaml", "--repo-name", "dalek-ed25519-verified", "--env-script", "/tmp/pacta-missing-env.sh"])
    output = capsys.readouterr().out
    assert code == 1
    assert "env_script_status: missing" in output
    assert "remediation:" in output
