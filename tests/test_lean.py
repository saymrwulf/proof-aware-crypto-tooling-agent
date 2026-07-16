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


def test_parse_axiom_output_axiom_free_cert_does_not_steal_next_cone():
    # Regression (found by the entry-13 rehearsal, 2026-07-16): an
    # axiom-free certificate is followed by a cone-carrying one. The old
    # windowed search reached past the bracketless "does not depend"
    # sentence and attributed the NEXT certificate's cone. The
    # accumulator corpus is the first subject with axiom-free
    # certificates (domsep, Hash, instDecidableEqHash, take_append_drop),
    # so no fork attestation ever exercised this path.
    output = (
        "'LTLAcc.domsep' does not depend on any axioms\n"
        "'LTLAcc.eq_dropLast_append_of_getLast?' depends on axioms: [propext]\n"
    )
    parsed = parse_axiom_output(output, ["LTLAcc.domsep", "LTLAcc.eq_dropLast_append_of_getLast?"])
    assert parsed["LTLAcc.domsep"] == []
    assert parsed["LTLAcc.eq_dropLast_append_of_getLast?"] == ["propext"]


def test_parse_axiom_output_exact_name_not_prefix():
    # 'LTLAcc.MTH' must not match the line for 'LTLAcc.MTH_single' even
    # when the latter comes first in the output.
    output = (
        "'LTLAcc.MTH_single' depends on axioms: [propext, LTLAcc.sha256, Quot.sound]\n"
        "'LTLAcc.MTH' depends on axioms: [propext, LTLAcc.sha256, Quot.sound]\n"
    )
    parsed = parse_axiom_output(output, ["LTLAcc.MTH"])
    assert parsed["LTLAcc.MTH"] == ["propext", "LTLAcc.sha256", "Quot.sound"]


def test_mac_safe_lean_command_is_argument_list():
    tools = LeanTools(lean="/usr/local/bin/lean", lake=None)
    cmd = build_lean_invocation(Path("Proofs/A.lean"), tools, output_path=Path("Proofs/A.olean"), root_path=Path("."))
    assert cmd == ["/usr/local/bin/lean", "--root=.", "-o", "Proofs/A.olean", "Proofs/A.lean"]
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
