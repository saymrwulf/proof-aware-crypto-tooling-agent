import json
from pathlib import Path


EXPECTED_NOTEBOOKS = [
    "00_course_map.ipynb",
    "01_threat_model_and_truth_boundary.ipynb",
    "02_claim_cards_and_risk_model.ipynb",
    "03_lean_replay_and_axiom_audit.ipynb",
    "04_proof_hygiene_and_boundaries.ipynb",
    "05_third_party_attestation_provider.ipynb",
    "06_merkle_transparency_logs.ipynb",
    "06a_provider_build_the_log.ipynb",
    "06b_agent_verify_inclusion.ipynb",
    "07_agent_consequences.ipynb",
    "08_capstone_research_program.ipynb",
    "09_dogfood_verified_crypto.ipynb",
]


def test_curriculum_notebooks_are_valid_and_output_free():
    root = Path(__file__).resolve().parents[1]
    notebook_dir = root / "notebooks"
    assert sorted(path.name for path in notebook_dir.glob("*.ipynb")) == EXPECTED_NOTEBOOKS
    for name in EXPECTED_NOTEBOOKS:
        notebook = json.loads((notebook_dir / name).read_text(encoding="utf-8"))
        assert notebook["nbformat"] == 4
        assert notebook["nbformat_minor"] >= 5
        assert notebook["cells"]
        combined = "\n".join(
            "".join(cell.get("source", []))
            for cell in notebook["cells"]
            if cell.get("cell_type") == "markdown"
        )
        assert "Learning Objectives" in combined
        if name != "00_course_map.ipynb":
            assert "Exercises" in combined
            assert "# Lecture" in combined
        for cell in notebook["cells"]:
            if cell.get("cell_type") == "code":
                assert cell.get("execution_count") is None
                assert cell.get("outputs") == []


def test_notebook_readme_points_to_course_map():
    readme = (Path(__file__).resolve().parents[1] / "notebooks" / "README.md").read_text(encoding="utf-8")
    assert "00_course_map.ipynb" in readme
    assert "zero-to-hero" in readme
