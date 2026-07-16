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


def test_classify_absent_axiom_free_cert_is_not_clean():
    # Regression (round-6 Claude R6-B1, executed end-to-end by the
    # reviewer): domsep's line deleted from otherwise-pristine output
    # still yielded 61/61 because a whole-output "no axioms" sentence +
    # ([] == []) scored the ABSENT cert proven+clean. Provenness must be
    # the cert's own anchor, i.e. membership in the parsed dict.
    from pacta.lean import classify_certificates

    output = (
        "'LTLAcc.Hash' does not depend on any axioms\n"
        "'LTLAcc.MTH' depends on axioms: [propext, LTLAcc.sha256, Quot.sound]\n"
    )
    certs = ["LTLAcc.Hash", "LTLAcc.domsep", "LTLAcc.MTH"]
    parsed = parse_axiom_output(output, certs)
    results = classify_certificates(parsed, certs, 0, lambda c: [])
    by_name = {r.name: r for r in results}
    assert by_name["LTLAcc.Hash"].status == "proven"
    assert by_name["LTLAcc.domsep"].status == "unknown"
    assert by_name["LTLAcc.domsep"].axiom_status == "not_checked"
    assert not all(r.axiom_status == "clean" for r in results)


def test_parse_missing_bracket_does_not_steal_next_record():
    # GPT round-6 §6: a cone-bearing anchor with a MISSING bracket must
    # not consume the next certificate's bracket.
    output = (
        "'A.a' depends on axioms:\n"
        "'B.b' depends on axioms: [propext]\n"
    )
    parsed = parse_axiom_output(output, ["A.a", "B.b"])
    assert "A.a" not in parsed
    assert parsed["B.b"] == ["propext"]


def test_parse_truncated_cone_is_missing():
    output = "'A.a' depends on axioms: [propext, Classical.choice\n"
    parsed = parse_axiom_output(output, ["A.a"])
    assert "A.a" not in parsed


def test_parse_long_wrapped_cone_beyond_old_window():
    # The ed25519 apex tiers carry 11 axioms; the old fixed 16-line
    # window was a latent overflow. Records now extend to the next
    # anchor regardless of length.
    items = [f"Ax{i}" for i in range(11)]
    wrapped = "[\n" + ",\n".join(items) + "\n" * 10 + "]"
    output = f"'A.a' depends on axioms: {wrapped}\n'B.b' does not depend on any axioms\n"
    parsed = parse_axiom_output(output, ["A.a", "B.b"])
    assert parsed["A.a"] == items
    assert parsed["B.b"] == []


def test_parse_duplicate_anchor_first_wins():
    output = (
        "'A.a' depends on axioms: [propext]\n"
        "'A.a' depends on axioms: [Quot.sound]\n"
    )
    parsed = parse_axiom_output(output, ["A.a"])
    assert parsed["A.a"] == ["propext"]


def test_parse_interleaved_diagnostics_inside_record():
    output = (
        "'A.a' depends on axioms:\n"
        "warning: something unrelated\n"
        "[propext, Quot.sound]\n"
        "'B.b' does not depend on any axioms\n"
    )
    parsed = parse_axiom_output(output, ["A.a", "B.b"])
    assert parsed["A.a"] == ["propext", "Quot.sound"]
    assert parsed["B.b"] == []


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
