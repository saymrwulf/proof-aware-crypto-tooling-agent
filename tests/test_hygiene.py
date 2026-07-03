from pacta.audit import scan_hygiene, strip_lean_comments
from pacta.manifest import discover_layout


def test_strip_comments_avoids_false_sorry():
    text = "-- sorry\n/- axiom hidden -/\ntheorem ok : True := by trivial\n"
    stripped = strip_lean_comments(text)
    assert "sorry" not in stripped
    assert "axiom hidden" not in stripped
    assert "by trivial" in stripped


def test_hygiene_detects_forbidden_patterns(tmp_path):
    proofs = tmp_path / "repo" / "verification" / "Proofs"
    proofs.mkdir(parents=True)
    (proofs / "SpecMain.lean").write_text(
        """
axiom bad : True
theorem empty : True := by trivial
theorem gap : Nat := by
  sorry
def x := by native_decide
""",
        encoding="utf-8",
    )
    layout = discover_layout(tmp_path / "repo")
    issues = scan_hygiene(layout, certificates=["Missing.cert"])
    codes = {issue.code for issue in issues}
    assert "axiom-in-proofs" in codes
    assert "trivial-true-target" in codes
    assert "by-trivial-in-spec" in codes
    assert "sorry" in codes
    assert "native-decide" in codes
    assert "missing-certificate-name" in codes
