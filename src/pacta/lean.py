from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import STANDARD_LEAN_AXIOMS


@dataclass(slots=True)
class LeanTools:
    lean: str | None
    lake: str | None
    lean_version: str | None = None
    lake_version: str | None = None


@dataclass(slots=True)
class LeanCheckResult:
    attempted: bool
    ok: bool
    missing_tool: str | None
    checked_files: list[str] = field(default_factory=list)
    failed_files: list[str] = field(default_factory=list)
    log_path: str | None = None
    diagnostics: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CertificateAxiomResult:
    name: str
    status: str
    axiom_status: str
    observed_axioms: list[str]
    expected_axioms: list[str]
    diagnostics: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AxiomAuditResult:
    attempted: bool
    ok: bool
    missing_tool: str | None
    certificates: list[CertificateAxiomResult]
    log_path: str | None
    diagnostics: list[str] = field(default_factory=list)


def detect_tools() -> LeanTools:
    lean = shutil.which("lean")
    lake = shutil.which("lake")
    return LeanTools(
        lean=lean,
        lake=lake,
        lean_version=_version([lean, "--version"]) if lean else None,
        lake_version=_version([lake, "--version"]) if lake else None,
    )


def build_lean_env(verification_dir: str | Path, base_env: dict[str, str] | None = None) -> dict[str, str]:
    verification = Path(verification_dir).resolve()
    env = dict(base_env or os.environ)
    candidates = [verification / "gen", verification]
    existing = [str(path) for path in candidates if path.exists()]
    old = env.get("LEAN_PATH")
    if old:
        existing.append(old)
    if existing:
        env["LEAN_PATH"] = os.pathsep.join(existing)
    return env


def build_lean_invocation(
    file_path: str | Path,
    tools: LeanTools,
    use_lake_env: bool = False,
    output_path: str | Path | None = None,
) -> list[str]:
    args = ["lean"]
    if output_path is not None:
        args.extend(["-o", str(output_path)])
    args.append(str(file_path))
    if use_lake_env and tools.lake:
        return [tools.lake, "env", *args]
    if not tools.lean:
        raise RuntimeError("lean is not available")
    return [tools.lean, *args[1:]]


def lean_check_files(
    files: list[Path],
    verification_dir: str | Path,
    timeout: int = 120,
    log_dir: str | Path | None = None,
) -> LeanCheckResult:
    if not files:
        return LeanCheckResult(
            attempted=False,
            ok=False,
            missing_tool=None,
            diagnostics=[f"No Lean files discovered under {verification_dir}."],
        )
    tools = detect_tools()
    if not tools.lean and not tools.lake:
        return LeanCheckResult(
            attempted=False,
            ok=False,
            missing_tool="lean",
            diagnostics=["Neither lean nor lake was found on PATH."],
        )
    verification = Path(verification_dir)
    use_lake_env = tools.lake is not None and ((verification / "lakefile.lean").exists() or (verification / "lakefile.toml").exists())
    logs = _log_file(log_dir, "lean-check.log")
    checked: list[str] = []
    failed: list[str] = []
    diagnostics: list[str] = []
    env = build_lean_env(verification)
    with logs.open("w", encoding="utf-8") as log:
        log.write(f"lean: {tools.lean}\n")
        log.write(f"lake: {tools.lake}\n")
        log.write(f"lean_version: {tools.lean_version}\n")
        log.write(f"lake_version: {tools.lake_version}\n\n")
        for path in files:
            cmd = build_lean_invocation(path, tools, use_lake_env=use_lake_env, output_path=path.with_suffix(".olean"))
            log.write("$ " + " ".join(cmd) + "\n")
            try:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(verification),
                    env=env,
                )
            except subprocess.TimeoutExpired:
                failed.append(str(path))
                message = f"Timed out after {timeout}s: {path}"
                diagnostics.append(message)
                log.write(message + "\n")
                continue
            checked.append(str(path))
            log.write(completed.stdout)
            log.write(completed.stderr)
            log.write(f"\nexit_code: {completed.returncode}\n\n")
            if completed.returncode != 0:
                failed.append(str(path))
    return LeanCheckResult(
        attempted=True,
        ok=not failed,
        missing_tool=None,
        checked_files=checked,
        failed_files=failed,
        log_path=str(logs),
        diagnostics=diagnostics,
    )


def run_axiom_audit(
    verification_dir: str | Path,
    imports: list[str],
    certificates: list[str],
    expected_axioms: list[str] | None = None,
    timeout: int = 120,
    log_dir: str | Path | None = None,
) -> AxiomAuditResult:
    tools = detect_tools()
    expected = expected_axioms or STANDARD_LEAN_AXIOMS
    if not tools.lean and not tools.lake:
        cert_results = [
            CertificateAxiomResult(cert, "unknown", "not_checked", [], expected, ["Neither lean nor lake was found on PATH."])
            for cert in certificates
        ]
        return AxiomAuditResult(False, False, "lean", cert_results, None, ["Neither lean nor lake was found on PATH."])
    verification = Path(verification_dir)
    use_lake_env = tools.lake is not None and ((verification / "lakefile.lean").exists() or (verification / "lakefile.toml").exists())
    logs = _log_file(log_dir, "axiom-audit.log")
    imports_text = "\n".join(f"import {module}" for module in imports)
    prints_text = "\n".join(f"#print axioms {cert}" for cert in certificates)
    env = build_lean_env(verification)
    with tempfile.TemporaryDirectory(prefix="pacta-axioms-") as tmp:
        audit_file = Path(tmp) / "AxiomAudit.lean"
        audit_file.write_text(f"{imports_text}\n\n{prints_text}\n", encoding="utf-8")
        cmd = build_lean_invocation(audit_file, tools, use_lake_env=use_lake_env)
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(verification),
                env=env,
            )
            output = completed.stdout + completed.stderr
            return_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "") + f"\nTimed out after {timeout}s\n"
            return_code = 124
    logs.write_text(output, encoding="utf-8")
    parsed = parse_axiom_output(output, certificates)
    cert_results: list[CertificateAxiomResult] = []
    for cert in certificates:
        observed = parsed.get(cert, [])
        if return_code != 0 and not observed:
            status = "failed"
            axiom_status = "not_checked"
        else:
            status = "proven" if observed or _mentions_no_axioms(output) else "unknown"
            axiom_status = "clean" if sorted(observed) == sorted(expected) else "dirty"
        cert_results.append(CertificateAxiomResult(cert, status, axiom_status, observed, expected))
    return AxiomAuditResult(
        attempted=True,
        ok=return_code == 0 and all(cert.axiom_status == "clean" for cert in cert_results),
        missing_tool=None,
        certificates=cert_results,
        log_path=str(logs),
        diagnostics=[] if return_code == 0 else [f"Lean axiom audit exited with {return_code}."],
    )


def parse_axiom_output(output: str, certificates: list[str]) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    lines = output.splitlines()
    for cert in certificates:
        cert_results: list[str] | None = None
        for i, line in enumerate(lines):
            if cert not in line:
                continue
            window = "\n".join(lines[i : i + 4])
            bracket = re.search(r"\[([^\]]*)\]", window)
            if bracket:
                cert_results = [item.strip() for item in bracket.group(1).split(",") if item.strip()]
                break
            if _mentions_no_axioms(window):
                cert_results = []
                break
        if cert_results is not None:
            results[cert] = cert_results
    return results


def _mentions_no_axioms(text: str) -> bool:
    lowered = text.lower()
    return "no axioms" in lowered or "does not depend on any axioms" in lowered


def _version(cmd: list[str | None]) -> str | None:
    if not cmd[0]:
        return None
    try:
        completed = subprocess.run(
            [part for part in cmd if part],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return (completed.stdout or completed.stderr).strip() or None


def _log_file(log_dir: str | Path | None, name: str) -> Path:
    directory = Path(log_dir) if log_dir else Path(".pacta")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / name
