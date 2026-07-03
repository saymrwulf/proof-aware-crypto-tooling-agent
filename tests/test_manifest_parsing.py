from pacta.manifest import discover_layout, parse_imports


def test_manifest_and_topological_order(tmp_path):
    verification = tmp_path / "repo" / "verification"
    proofs = verification / "Proofs"
    proofs.mkdir(parents=True)
    (proofs / "A.lean").write_text("import Proofs.B\n", encoding="utf-8")
    (proofs / "B.lean").write_text("def b := 1\n", encoding="utf-8")
    (verification / "proofs.txt").write_text("Proofs/A.lean\n", encoding="utf-8")
    layout = discover_layout(tmp_path / "repo")
    assert parse_imports(proofs / "A.lean") == ["Proofs.B"]
    ordered = [path.name for path in layout.compile_order]
    assert ordered.index("B.lean") < ordered.index("A.lean")
    assert "Proofs/B.lean" in [str(path.relative_to(verification)) for path in layout.files_not_in_manifest]
