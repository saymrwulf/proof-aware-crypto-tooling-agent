from __future__ import annotations

import os
import re
import shlex
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


def detect_tools(env: dict[str, str] | None = None) -> LeanTools:
    path = env.get("PATH") if env else None
    lean = shutil.which("lean", path=path)
    lake = shutil.which("lake", path=path)
    return LeanTools(
        lean=lean,
        lake=lake,
        lean_version=_version([lean, "--version"], env=env) if lean else None,
        lake_version=_version([lake, "--version"], env=env) if lake else None,
    )


def build_lean_env(
    verification_dir: str | Path,
    base_env: dict[str, str] | None = None,
    env_script: str | Path | None = None,
) -> dict[str, str]:
    verification = Path(verification_dir).resolve()
    env = _base_env(base_env, env_script)
    candidates = [verification / "gen", verification]
    existing = [str(path) for path in candidates if path.exists()]
    old = env.get("LEAN_PATH")
    if old:
        existing.append(old)
    if existing:
        env["LEAN_PATH"] = os.pathsep.join(existing)
    return env


def env_script_available(env_script: str | Path | None) -> tuple[bool, str | None]:
    if not env_script:
        return True, None
    path = Path(str(env_script)).expanduser()
    if not path.exists():
        return False, f"Verifier environment script does not exist: {path}"
    return True, None


def resolve_lean_project_dir(path: str | Path | None, env: dict[str, str] | None = None) -> Path | None:
    return _resolve_project_dir(path, env or os.environ)


def build_lean_invocation(
    file_path: str | Path,
    tools: LeanTools,
    use_lake_env: bool = False,
    output_path: str | Path | None = None,
    root_path: str | Path | None = None,
    lean_guard: str | Path | None = None,
) -> list[str]:
    if lean_guard:
        # MACHINE PROTECTION: route the compile through the repo's lean-guard
        # (hard memory cap via systemd scope + lean -M, core pinning, timeout,
        # single-flight lock, free-RAM preflight with a retry ladder). The
        # guard replaces the bare `lean` binary entirely and computes its own
        # olean output path; caps are tuned via LEAN_MEM_MB, LEAN_MIN_FREE_MB,
        # LEAN_MEM_WAIT_SEC, LEAN_TIMEOUT, LEAN_MAX_CORES in the environment.
        guarded = [str(lean_guard), str(file_path)]
        if root_path is not None:
            # lean-guard forwards extra args to lean after the file; --root
            # lets absolute file paths live outside the toolchain project dir.
            guarded.append(f"--root={root_path}")
        if use_lake_env and tools.lake:
            return [tools.lake, "env", *guarded]
        return guarded
    args = ["lean"]
    if root_path is not None:
        args.append(f"--root={root_path}")
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
    env_script: str | Path | None = None,
    lean_project_dir: str | Path | None = None,
    lean_guard: str | Path | None = None,
) -> LeanCheckResult:
    if not files:
        return LeanCheckResult(
            attempted=False,
            ok=False,
            missing_tool=None,
            diagnostics=[f"No Lean files discovered under {verification_dir}."],
        )
    ok_env, env_error = env_script_available(env_script)
    if not ok_env:
        return LeanCheckResult(
            attempted=False,
            ok=False,
            missing_tool="env_script",
            diagnostics=[
                env_error or "Verifier environment script is not available.",
                "Install or point --env-script at the pinned Lean/Aeneas environment; no extraction will be run.",
            ],
        )
    env = build_lean_env(verification_dir, env_script=env_script)
    tools = detect_tools(env)
    if not tools.lean and not tools.lake:
        return LeanCheckResult(
            attempted=False,
            ok=False,
            missing_tool="lean",
            diagnostics=["Neither lean nor lake was found on PATH."],
        )
    verification = Path(verification_dir).resolve()
    project_dir = _resolve_project_dir(lean_project_dir, env)
    use_lake_env = tools.lake is not None and (
        project_dir is not None or (verification / "lakefile.lean").exists() or (verification / "lakefile.toml").exists()
    )
    cwd = project_dir or verification
    logs = _log_file(log_dir, "lean-check.log")
    checked: list[str] = []
    failed: list[str] = []
    diagnostics: list[str] = []
    with logs.open("w", encoding="utf-8") as log:
        log.write(f"lean: {tools.lean}\n")
        log.write(f"lake: {tools.lake}\n")
        log.write(f"lean_version: {tools.lean_version}\n")
        log.write(f"lake_version: {tools.lake_version}\n\n")
        log.write(f"env_script: {env_script or ''}\n")
        log.write(f"lean_project_dir: {project_dir or ''}\n\n")
        for path in files:
            cmd = build_lean_invocation(
                path,
                tools,
                use_lake_env=use_lake_env,
                output_path=path.with_suffix(".olean"),
                root_path=_lean_root_for_file(path, verification),
                lean_guard=lean_guard,
            )
            log.write("$ " + " ".join(cmd) + "\n")
            try:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(cwd),
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
                diagnostics.extend(_dependency_diagnostics(completed.stdout + completed.stderr))
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
    env_script: str | Path | None = None,
    lean_project_dir: str | Path | None = None,
    certificate_axioms: dict[str, list[str]] | None = None,
    lean_guard: str | Path | None = None,
) -> AxiomAuditResult:
    expected = expected_axioms or STANDARD_LEAN_AXIOMS
    per_cert = certificate_axioms or {}

    def expected_for(cert: str) -> list[str]:
        return list(per_cert.get(cert, expected))
    ok_env, env_error = env_script_available(env_script)
    if not ok_env:
        cert_results = [
            CertificateAxiomResult(cert, "unknown", "not_checked", [], expected_for(cert), [env_error or "Verifier environment unavailable."])
            for cert in certificates
        ]
        return AxiomAuditResult(False, False, "env_script", cert_results, None, [env_error or "Verifier environment unavailable."])
    env = build_lean_env(verification_dir, env_script=env_script)
    tools = detect_tools(env)
    if not tools.lean and not tools.lake:
        cert_results = [
            CertificateAxiomResult(cert, "unknown", "not_checked", [], expected_for(cert), ["Neither lean nor lake was found on PATH."])
            for cert in certificates
        ]
        return AxiomAuditResult(False, False, "lean", cert_results, None, ["Neither lean nor lake was found on PATH."])
    verification = Path(verification_dir).resolve()
    project_dir = _resolve_project_dir(lean_project_dir, env)
    use_lake_env = tools.lake is not None and (
        project_dir is not None or (verification / "lakefile.lean").exists() or (verification / "lakefile.toml").exists()
    )
    cwd = project_dir or verification
    logs = _log_file(log_dir, "axiom-audit.log")
    imports_text = "\n".join(f"import {module}" for module in imports)
    prints_text = "\n".join(f"#print axioms {cert}" for cert in certificates)
    with tempfile.TemporaryDirectory(prefix="pacta-axioms-") as tmp:
        audit_file = Path(tmp) / "AxiomAudit.lean"
        audit_file.write_text(f"{imports_text}\n\n{prints_text}\n", encoding="utf-8")
        cmd = build_lean_invocation(
            audit_file,
            tools,
            use_lake_env=use_lake_env,
            lean_guard=lean_guard,
            # the audit file lives in a temp dir outside the toolchain root;
            # --root makes lean accept it (guard mode forwards the flag).
            root_path=audit_file.parent,
        )
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cwd),
                env=env,
            )
            output = completed.stdout + completed.stderr
            return_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "") + f"\nTimed out after {timeout}s\n"
            return_code = 124
    logs.write_text(output, encoding="utf-8")
    parsed = parse_axiom_output(output, certificates)
    cert_results = classify_certificates(parsed, certificates, return_code, expected_for)
    return AxiomAuditResult(
        attempted=True,
        ok=return_code == 0 and all(cert.axiom_status == "clean" for cert in cert_results),
        missing_tool=None,
        certificates=cert_results,
        log_path=str(logs),
        diagnostics=[] if return_code == 0 else [f"Lean axiom audit exited with {return_code}.", *_dependency_diagnostics(output)],
    )


# Anchor lines as Lean prints them: 'Name' depends on axioms: …  /
# 'Name' does not depend on any axioms. The name is captured between the
# first pair of quotes (an identifier that itself CONTAINS a quote, e.g.
# Foo', would mis-capture — no such name exists on this estate; the old
# substring matching was strictly worse).
_AXIOM_ANCHOR = re.compile(r"'([^']+)'\s+(depends on axioms|does not depend on any axioms)")


def parse_axiom_output(output: str, certificates: list[str]) -> dict[str, list[str]]:
    """Record-scoped parsing (review round 6, GPT §6 / Claude R6-B).

    The output is split into RECORDS: each anchor line starts one, the
    next anchor line ends it. A cone bracket is accepted only inside its
    own record; a record whose bracket is missing or truncated yields a
    MISSING certificate (fail closed at the caller), never a bracket
    borrowed from the next record. Cones may wrap arbitrarily many lines
    (the ed25519 apex tiers carry 11 axioms — the old fixed 16-line
    window was a latent overflow for them). Duplicate anchors: first one
    wins, deterministically.
    """
    lines = output.splitlines()
    anchors: list[tuple[int, str, bool]] = []  # (line index, name, axiom-free?)
    for i, line in enumerate(lines):
        m = _AXIOM_ANCHOR.search(line)
        if m:
            anchors.append((i, m.group(1), "does not depend" in m.group(2)))
    wanted = set(certificates)
    results: dict[str, list[str]] = {}
    for k, (i, name, axiom_free) in enumerate(anchors):
        if name not in wanted or name in results:
            continue
        if axiom_free:
            results[name] = []
            continue
        end = anchors[k + 1][0] if k + 1 < len(anchors) else len(lines)
        record = "\n".join(lines[i:end])
        bracket = re.search(r"\[([^\]]*)\]", record, re.DOTALL)
        if bracket:
            results[name] = [item.strip() for item in bracket.group(1).split(",") if item.strip()]
        # else: no complete bracket before the next record — leave MISSING.
    return results


def classify_certificates(
    parsed: dict[str, list[str]],
    certificates: list[str],
    return_code: int,
    expected_for,
) -> list[CertificateAxiomResult]:
    """Fail-closed per-certificate classification (review round 6, R6-B1).

    Provenness is decided by the certificate's OWN anchor having been
    found (membership in `parsed` — which includes axiom-free certs as
    []), never by a whole-output "no axioms" sentence: an ABSENT
    axiom-free certificate previously scored proven+clean because some
    OTHER certificate's bracketless sentence satisfied the global check
    and [] == [] satisfied the cone comparison. Absent certificates are
    never clean.
    """
    out: list[CertificateAxiomResult] = []
    for cert in certificates:
        if cert in parsed:
            observed = parsed[cert]
            status = "proven"
            axiom_status = "clean" if sorted(observed) == sorted(expected_for(cert)) else "dirty"
        else:
            observed = []
            status = "failed" if return_code != 0 else "unknown"
            axiom_status = "not_checked"
        out.append(CertificateAxiomResult(cert, status, axiom_status, observed, expected_for(cert)))
    return out


def _mentions_no_axioms(text: str) -> bool:
    lowered = text.lower()
    return "no axioms" in lowered or "does not depend on any axioms" in lowered


def _version(cmd: list[str | None], env: dict[str, str] | None = None) -> str | None:
    if not cmd[0]:
        return None
    try:
        completed = subprocess.run(
            [part for part in cmd if part],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
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


def _lean_root_for_file(path: Path, verification_dir: Path) -> Path:
    gen_dir = verification_dir / "gen"
    try:
        path.relative_to(gen_dir)
        return gen_dir
    except ValueError:
        return verification_dir


def _base_env(base_env: dict[str, str] | None, env_script: str | Path | None) -> dict[str, str]:
    env = dict(base_env or os.environ)
    if not env_script:
        return env
    path = Path(str(env_script)).expanduser()
    if not path.exists():
        return env
    command = f"source {shlex.quote(str(path))}; env"
    try:
        completed = subprocess.run(
            ["/bin/bash", "-lc", command],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return env
    if completed.returncode != 0:
        return env
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            env[key] = value
    return env


def _resolve_project_dir(path: str | Path | None, env: dict[str, str]) -> Path | None:
    if not path:
        return None
    expanded = os.path.expandvars(str(path))
    for key, value in env.items():
        expanded = expanded.replace(f"${key}", value).replace(f"${{{key}}}", value)
    resolved = Path(expanded).expanduser()
    return resolved if resolved.exists() else None


def _dependency_diagnostics(output: str) -> list[str]:
    diagnostics: list[str] = []
    modules = sorted(set(re.findall(r"unknown module prefix '([^']+)'", output)))
    for module in modules:
        diagnostics.append(f"Missing Lean dependency/module prefix: {module}")
    missing_objects = sorted(set(re.findall(r"object file '([^']+)' of module ([A-Za-z0-9_'.]+) does not exist", output)))
    for _, module in missing_objects[:8]:
        diagnostics.append(f"Missing compiled Lean object for module: {module}")
    return diagnostics
