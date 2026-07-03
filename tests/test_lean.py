from pathlib import Path

from pacta.lean import LeanTools, build_lean_env, build_lean_invocation, lean_check_files, parse_axiom_output


def test_parse_axiom_output_multiline():
    output = """
'CurveFieldProofs.fieldImplementation' depends on axioms:
[propext, Classical.choice, Quot.sound]
'CurveFieldProofs.edwardsImplementation' depends on axioms:
[propext, Classical.choice, Quot.sound]
"""
    parsed = parse_axiom_output(
        output,
        ["CurveFieldProofs.fieldImplementation", "CurveFieldProofs.edwardsImplementation"],
    )
    assert parsed["CurveFieldProofs.fieldImplementation"] == ["propext", "Classical.choice", "Quot.sound"]
    assert parsed["CurveFieldProofs.edwardsImplementation"] == ["propext", "Classical.choice", "Quot.sound"]


def test_parse_axiom_output_no_axioms_wording():
    output = "'CurveFieldProofs.fieldImplementation' does not depend on any axioms\n"
    parsed = parse_axiom_output(output, ["CurveFieldProofs.fieldImplementation"])
    assert parsed["CurveFieldProofs.fieldImplementation"] == []


def test_mac_safe_lean_command_is_argument_list():
    tools = LeanTools(lean="/usr/local/bin/lean", lake=None)
    cmd = build_lean_invocation(Path("Proofs/A.lean"), tools, output_path=Path("Proofs/A.olean"))
    assert cmd == ["/usr/local/bin/lean", "-o", "Proofs/A.olean", "Proofs/A.lean"]
    assert "timeout" not in cmd
    assert "taskset" not in cmd
    assert "free" not in cmd


def test_lean_path_uses_python_pathsep(tmp_path):
    verification = tmp_path / "verification"
    (verification / "gen").mkdir(parents=True)
    env = build_lean_env(verification, base_env={"LEAN_PATH": "old"})
    assert str(verification / "gen") in env["LEAN_PATH"]
    assert str(verification) in env["LEAN_PATH"]
    assert "old" in env["LEAN_PATH"]


def test_lean_check_requires_discovered_files(tmp_path):
    result = lean_check_files([], tmp_path / "verification")
    assert not result.attempted
    assert "No Lean files" in result.diagnostics[0]
