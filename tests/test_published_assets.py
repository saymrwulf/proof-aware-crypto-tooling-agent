"""The publish step overwrites the mirror's verify.py / verify_selftest.py /
README.md from the frozen constants in published_assets. A hardening
regression here silently fail-opens the PUBLIC verifier on the next publish
(exactly what the 2026-07-19 doc audit found: the constants still carried
the pre-hardening fail-open verify.py). These tests pin the
security-critical markers so that drift fails CI instead of shipping."""

from pacta_provider.published_assets import README_MD, VERIFY_PY, VERIFY_SELFTEST_PY


def test_verify_py_compiles_and_is_the_hardened_verifier():
    compile(VERIFY_PY, "verify.py", "exec")
    for marker in (
        "FATAL: signature checking unavailable",   # fail-closed exit 2
        "RECEIPT_TYPE",                            # required type binding
        "def verify_receipt",                      # full binding checks
        "--structural-only",                       # explicit reduced mode
        'glob("*.receipt.json")',                  # --all covers every receipt
        "public_key_fingerprint_sha256",           # required fingerprint
    ):
        assert marker in VERIFY_PY, f"hardening marker missing: {marker}"


def test_selftest_compiles_and_covers_fail_closed():
    compile(VERIFY_SELFTEST_PY, "verify_selftest.py", "exec")
    for marker in ("FAIL CLOSED", "missing key fingerprint REJECTED",
                   "forged (unsigned) root REJECTED"):
        assert marker in VERIFY_SELFTEST_PY, marker


def test_readme_is_the_corrected_template():
    assert "identity anchor" in README_MD
    assert "verify_selftest.py" in README_MD
    assert "the git hash is the content hash" not in README_MD
    assert "sole trust anchor" not in README_MD
