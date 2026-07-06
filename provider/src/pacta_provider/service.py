from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
from typing import Any

from pacta.attestation import validate_attestation
from pacta.config import RepoConfig
from pacta.lean import LeanCheckResult, build_lean_env, detect_tools, lean_check_files, resolve_lean_project_dir, run_axiom_audit
from pacta.manifest import discover_layout
from pacta.profiles import get_profile
from pacta.repo import git_commit, resolve_lean_guard
from pacta.signing import sign_attestation


def build_attestation(
    repo: RepoConfig,
    repo_path: str | Path,
    provider: str,
    private_key: str | Path,
    public_key: str | Path,
    env_script: str | Path | None = None,
    lean_project_dir: str | Path | None = None,
    timeout: int = 120,
    log_dir: str | Path = "provider/out/logs",
) -> dict[str, Any]:
    path = Path(repo_path)
    profile = get_profile(repo.kind, repo)
    layout = discover_layout(path, repo.verification_dir)
    lean_guard = resolve_lean_guard(repo.lean_guard, path)
    check = lean_check_files(
        layout.compile_order,
        layout.verification_dir,
        timeout=timeout,
        log_dir=log_dir,
        env_script=env_script or repo.env_script,
        lean_project_dir=lean_project_dir or repo.lean_project_dir,
        lean_guard=lean_guard,
    )
    axiom = None
    if check.attempted and check.ok:
        axiom = run_axiom_audit(
            path / repo.verification_dir,
            profile.axiom_imports,
            repo.certificates or profile.default_certificates,
            profile.expected_axioms,
            timeout=timeout,
            log_dir=log_dir,
            env_script=env_script or repo.env_script,
            lean_project_dir=lean_project_dir or repo.lean_project_dir,
            certificate_axioms=profile.certificate_axioms,
            lean_guard=lean_guard,
        )
        certs = [
            {
                "name": cert.name,
                "status": cert.status,
                "axiom_status": cert.axiom_status,
                "observed_axioms": cert.observed_axioms,
                "expected_axioms": cert.expected_axioms,
                "diagnostics": cert.diagnostics,
            }
            for cert in axiom.certificates
        ]
    else:
        certs = _failed_certificates(repo, profile.expected_axioms, check)
    provider_env = build_lean_env(path / repo.verification_dir, env_script=env_script or repo.env_script)
    project_dir = resolve_lean_project_dir(lean_project_dir or repo.lean_project_dir, provider_env)
    tools = detect_tools(provider_env)
    lean_version = _project_version(["lake", "env", "lean", "--version"], project_dir, provider_env) or tools.lean_version
    lake_version = _project_version(["lake", "--version"], project_dir, provider_env) or tools.lake_version
    unsigned = {
        "schema_version": 1,
        "provider": provider,
        "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "machine_protection": {
            "lean_guard": lean_guard or "UNGUARDED",
            "note": "All Lean compiles route through the repo's lean-guard (memory cap, core pinning, timeout, single-flight lock) when configured.",
        },
        "subject": {
            "component": repo.name,
            "repo_url": repo.url,
            "repo_commit": git_commit(path),
            "verification_dir": repo.verification_dir,
            "kind": repo.kind,
            "verified_backend": repo.verified_backend,
        },
        "environment": {
            "lean_version": lean_version,
            "lake_version": lake_version,
            "env_script": str(env_script or repo.env_script or ""),
            "lean_project_dir": str(project_dir or lean_project_dir or repo.lean_project_dir or ""),
        },
        "replay": {
            "check_attempted": check.attempted,
            "check_ok": check.ok,
            "check_log_path": check.log_path,
            "checked_files": len(check.checked_files),
            "failed_files": check.failed_files,
            "diagnostics": check.diagnostics,
            "axiom_attempted": axiom.attempted if axiom else False,
            "axiom_ok": axiom.ok if axiom else False,
            "axiom_log_path": axiom.log_path if axiom else None,
            "axiom_diagnostics": axiom.diagnostics if axiom else [],
        },
        "certificates": certs,
    }
    signed = sign_attestation(unsigned, private_key, public_key)
    # Self-check before emitting a certificate.
    validation = validate_attestation(signed, repo, trusted_provider=provider, public_key_path=public_key)
    if not validation.accepted:
        signed.setdefault("provider_warnings", []).extend(validation.diagnostics)
    return signed


def _failed_certificates(repo: RepoConfig, expected_axioms: list[str], check: LeanCheckResult) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "status": "failed" if check.attempted else "unknown",
            "axiom_status": "not_checked",
            "observed_axioms": [],
            "expected_axioms": expected_axioms,
        }
        for name in repo.certificates
    ]


def _project_version(cmd: list[str], cwd: Path | None, env: dict[str, str]) -> str | None:
    executable = shutil.which(cmd[0], path=env.get("PATH"))
    if not executable:
        return None
    try:
        completed = subprocess.run(
            [executable, *cmd[1:]],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return (completed.stdout or completed.stderr).strip() or None
