from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .agent import component_artifact_dir, run_agent_action, write_decision
from .attestation import load_attestation, validate_attestation
from .audit import scan_hygiene
from .claims import build_claim_card
from .config import RepoConfig, load_config
from .lean import (
    LeanCheckResult,
    build_lean_env,
    detect_tools,
    env_script_available,
    lean_check_files,
    resolve_lean_project_dir,
    run_axiom_audit,
)
from .manifest import discover_layout
from .profiles import get_profile
from .repo import clone_or_fetch, status_for
from .report import render_markdown
from .risk import score_claim_card
from .transparency import load_receipt, verify_receipt
from .yamlio import dump_data, load_data


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (KeyError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pacta", description="Proof-aware crypto tooling evidence interpreter.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Show configured repositories and local verification status.")
    scan.add_argument("--config", required=True)
    scan.add_argument("--base-dir", default="repos")
    scan.add_argument("--clone", action="store_true", help="Clone missing repositories.")
    scan.add_argument("--fetch", action="store_true", help="Fetch existing repositories when cloning/scanning.")
    scan.set_defaults(func=cmd_scan)

    doctor = sub.add_parser("doctor", help="Diagnose local verifier capabilities for a configured repository.")
    doctor.add_argument("--config", required=True)
    doctor.add_argument("--repo-name", required=True)
    doctor.add_argument("--env-script")
    doctor.add_argument("--lean-project-dir")
    doctor.set_defaults(func=cmd_doctor)

    audit = sub.add_parser("audit", help="Run static proof hygiene checks.")
    audit.add_argument("--repo", required=True)
    audit.add_argument("--verification-dir", default="verification")
    audit.add_argument("--config")
    audit.add_argument("--repo-name")
    audit.set_defaults(func=cmd_audit)

    lean_check = sub.add_parser("lean-check", help="Replay portable Lean checks without Linux-only scripts.")
    lean_check.add_argument("--repo", required=True)
    lean_check.add_argument("--verification-dir", default="verification")
    lean_check.add_argument("--timeout", type=int, default=120)
    lean_check.add_argument("--log-dir", default=".pacta")
    lean_check.add_argument("--env-script")
    lean_check.add_argument("--lean-project-dir")
    lean_check.set_defaults(func=cmd_lean_check)

    check = sub.add_parser("check", help="Alias for lean-check.")
    check.add_argument("--repo", required=True)
    check.add_argument("--verification-dir", default="verification")
    check.add_argument("--timeout", type=int, default=120)
    check.add_argument("--log-dir", default=".pacta")
    check.add_argument("--env-script")
    check.add_argument("--lean-project-dir")
    check.set_defaults(func=cmd_lean_check)

    axiom = sub.add_parser("axioms", help="Run configured Lean axiom audit.")
    axiom.add_argument("--repo", required=True)
    axiom.add_argument("--config", required=True)
    axiom.add_argument("--repo-name", required=True)
    axiom.add_argument("--timeout", type=int, default=120)
    axiom.add_argument("--log-dir", default=".pacta")
    axiom.add_argument("--env-script")
    axiom.add_argument("--lean-project-dir")
    axiom.set_defaults(func=cmd_axioms)

    claims = sub.add_parser("claims", help="Generate a machine-readable claim card.")
    claims.add_argument("--config", required=True)
    claims.add_argument("--repo-name", required=True)
    claims.add_argument("--repo")
    claims.add_argument("--base-dir", default="repos")
    claims.add_argument("--out")
    claims.add_argument("--offline-fixture", action="store_true")
    claims.add_argument("--run-axioms", action="store_true")
    claims.add_argument("--timeout", type=int, default=120)
    claims.add_argument("--log-dir", default=".pacta")
    claims.add_argument("--env-script")
    claims.add_argument("--lean-project-dir")
    claims.add_argument("--attestation")
    claims.add_argument("--trust-attestation-provider")
    claims.add_argument("--attestation-public-key")
    claims.add_argument("--allow-unsigned-attestation", action="store_true")
    claims.add_argument("--transparency-receipt")
    claims.add_argument("--transparency-log-public-key")
    claims.add_argument("--require-transparency-signatures", choices=["ed25519", "both"], default="ed25519")
    claims.add_argument("--require-transparency-receipt", action="store_true")
    claims.set_defaults(func=cmd_claims)

    report = sub.add_parser("report", help="Generate a human-readable Markdown risk report.")
    report.add_argument("--claims")
    report.add_argument("--config")
    report.add_argument("--repo-name")
    report.add_argument("--repo")
    report.add_argument("--base-dir", default="repos")
    report.add_argument("--offline-fixture", action="store_true")
    report.add_argument("--out")
    report.set_defaults(func=cmd_report)

    score = sub.add_parser("score", help="Score an existing claim card.")
    score.add_argument("--claims", required=True)
    score.set_defaults(func=cmd_score)

    receipt_verify = sub.add_parser("receipt-verify", help="Verify a transparency-log inclusion receipt for an attestation.")
    receipt_verify.add_argument("--attestation", required=True)
    receipt_verify.add_argument("--receipt", required=True)
    receipt_verify.add_argument("--log-public-key", required=True)
    receipt_verify.add_argument("--require-signatures", choices=["ed25519", "both"], default="ed25519")
    receipt_verify.set_defaults(func=cmd_receipt_verify)

    agent = sub.add_parser("agent", help="Apply a policy-gated consequence to verification evidence.")
    agent.add_argument("--claims", help="Existing claim card to act on.")
    agent.add_argument("--config", help="Repository config used to generate a claim card.")
    agent.add_argument("--repo-name", help="Configured repository name.")
    agent.add_argument("--repo", help="Local repository path.")
    agent.add_argument("--base-dir", default="repos")
    agent.add_argument("--artifact-dir", default="artifacts")
    agent.add_argument("--action", choices=["build-library", "build-wallet-demo"], default="build-library")
    agent.add_argument("--min-risk", default="R3")
    agent.add_argument("--clone", action="store_true", help="Clone/fetch the configured repository before acting.")
    agent.add_argument("--offline-fixture", action="store_true", help="Use synthetic clean evidence for a showcase run.")
    agent.add_argument("--run-axioms", action="store_true", help="Replay Lean and run axiom audit before acting.")
    agent.add_argument("--dry-run", action="store_true")
    agent.add_argument("--timeout", type=int, default=120)
    agent.add_argument("--log-dir", default=".pacta")
    agent.add_argument("--env-script")
    agent.add_argument("--lean-project-dir")
    agent.add_argument("--attestation")
    agent.add_argument("--trust-attestation-provider")
    agent.add_argument("--attestation-public-key")
    agent.add_argument("--allow-unsigned-attestation", action="store_true")
    agent.add_argument("--transparency-receipt")
    agent.add_argument("--transparency-log-public-key")
    agent.add_argument("--require-transparency-signatures", choices=["ed25519", "both"], default="ed25519")
    agent.add_argument("--require-transparency-receipt", action="store_true")
    agent.set_defaults(func=cmd_agent)
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    for repo in config.repos:
        status = clone_or_fetch(repo, args.base_dir, fetch=args.fetch) if args.clone else status_for(repo, args.base_dir)
        marker = "ok" if status.verification_exists else "missing"
        print(f"{repo.name}: {marker}")
        print(f"  url: {repo.url}")
        print(f"  local: {status.local_path}")
        print(f"  verification: {status.verification_dir}")
        print(f"  commit: {status.commit or 'unknown'}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    repo = config.repo_named(args.repo_name)
    env_script = args.env_script or repo.env_script
    lean_project_dir = args.lean_project_dir or repo.lean_project_dir
    ok_env, env_error = env_script_available(env_script)
    env = build_lean_env(repo.verification_dir, env_script=env_script) if ok_env else {}
    tools = detect_tools(env if env else None)
    project_dir = resolve_lean_project_dir(lean_project_dir, env if env else None)
    print(f"repo: {repo.name}")
    print(f"env_script: {env_script or 'not configured'}")
    print(f"env_script_status: {'ok' if ok_env else 'missing'}")
    if env_error:
        print(f"env_script_error: {env_error}")
    print(f"lean_project_dir: {lean_project_dir or 'not configured'}")
    print(f"lean_project_dir_status: {'ok' if project_dir else 'missing'}")
    if project_dir:
        print(f"lean_project_dir_resolved: {project_dir}")
    print(f"lean: {tools.lean or 'missing'}")
    print(f"lake: {tools.lake or 'missing'}")
    print(f"lean_version: {tools.lean_version or 'unknown'}")
    print(f"lake_version: {tools.lake_version or 'unknown'}")
    if not ok_env or not project_dir:
        print("remediation: install or point to the pinned verifier environment, for example --env-script ~/aeneas-toolchain/env.sh --lean-project-dir '$AENEAS_HOME/backends/lean'")
        return 1
    if not tools.lean and not tools.lake:
        print("remediation: ensure lean/lake are on PATH after sourcing the verifier environment.")
        return 1
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    repo_config = _repo_from_optional_config(args.config, args.repo_name, args.verification_dir)
    layout = discover_layout(args.repo, repo_config.verification_dir)
    issues = scan_hygiene(layout, repo_config.certificates)
    for warning in layout.warnings:
        print(f"warning: {warning}")
    if not issues:
        print("No proof hygiene issues found.")
        return 0
    for issue in issues:
        print(f"{issue.severity}: {issue.path}:{issue.line}: {issue.code}: {issue.message}")
    return 1 if any(issue.severity == "error" for issue in issues) else 0


def cmd_lean_check(args: argparse.Namespace) -> int:
    layout = discover_layout(args.repo, args.verification_dir)
    for warning in layout.warnings:
        print(f"warning: {warning}")
    result = lean_check_files(
        layout.compile_order,
        layout.verification_dir,
        timeout=args.timeout,
        log_dir=args.log_dir,
        env_script=args.env_script,
        lean_project_dir=args.lean_project_dir,
    )
    if not result.attempted:
        print("; ".join(result.diagnostics))
        return 2
    print(f"checked: {len(result.checked_files)}")
    print(f"failed: {len(result.failed_files)}")
    print(f"log: {result.log_path}")
    return 0 if result.ok else 1


def cmd_axioms(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    repo = config.repo_named(args.repo_name)
    profile = get_profile(repo.kind, repo)
    layout = discover_layout(args.repo, repo.verification_dir)
    env_script = args.env_script or repo.env_script
    lean_project_dir = args.lean_project_dir or repo.lean_project_dir
    check_result = lean_check_files(
        layout.compile_order,
        layout.verification_dir,
        timeout=args.timeout,
        log_dir=args.log_dir,
        env_script=env_script,
        lean_project_dir=lean_project_dir,
    )
    if check_result.log_path:
        print(f"check log: {check_result.log_path}")
    if not check_result.attempted:
        print("; ".join(check_result.diagnostics))
        return 2
    if not check_result.ok:
        print(f"portable Lean replay failed for {len(check_result.failed_files)} file(s)")
    result = run_axiom_audit(
        Path(args.repo) / repo.verification_dir,
        profile.axiom_imports,
        repo.certificates or profile.default_certificates,
        profile.expected_axioms,
        timeout=args.timeout,
        log_dir=args.log_dir,
        env_script=env_script,
        lean_project_dir=lean_project_dir,
        certificate_axioms=profile.certificate_axioms,
    )
    for cert in result.certificates:
        print(f"{cert.name}: {cert.status}, axioms={cert.axiom_status}, observed={cert.observed_axioms}")
    if result.log_path:
        print(f"log: {result.log_path}")
    return 0 if result.ok and check_result.ok else 1


def cmd_claims(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    repo = config.repo_named(args.repo_name)
    local_path = Path(args.repo) if args.repo else status_for(repo, args.base_dir).local_path
    layout = None
    axiom_result = None
    check_result: LeanCheckResult | None = None
    if local_path.exists():
        layout = discover_layout(local_path, repo.verification_dir)
    elif not args.offline_fixture:
        raise ValueError(f"Local repo does not exist: {local_path}")
    if args.run_axioms:
        if layout is None:
            raise ValueError("--run-axioms requires a local repository")
        profile = get_profile(repo.kind, repo)
        env_script = args.env_script or repo.env_script
        lean_project_dir = args.lean_project_dir or repo.lean_project_dir
        check_result = lean_check_files(
            layout.compile_order,
            layout.verification_dir,
            timeout=args.timeout,
            log_dir=args.log_dir,
            env_script=env_script,
            lean_project_dir=lean_project_dir,
        )
        axiom_result = run_axiom_audit(
            local_path / repo.verification_dir,
            profile.axiom_imports,
            repo.certificates or profile.default_certificates,
            profile.expected_axioms,
            timeout=args.timeout,
            log_dir=args.log_dir,
            env_script=env_script,
            lean_project_dir=lean_project_dir,
            certificate_axioms=profile.certificate_axioms,
        )
    attestation = _attestation_for_args(args, repo)
    card = build_claim_card(
        repo,
        local_path,
        layout=layout,
        lean_check=check_result,
        axiom_audit=axiom_result,
        attestation=attestation,
        offline_fixture=args.offline_fixture,
    )
    if args.out:
        dump_data(card, args.out)
    else:
        print_yaml(card)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.claims:
        card = load_data(args.claims)
    else:
        if not args.config or not args.repo_name:
            raise ValueError("report requires --claims or both --config and --repo-name")
        config = load_config(args.config)
        repo = config.repo_named(args.repo_name)
        local_path = Path(args.repo) if args.repo else status_for(repo, args.base_dir).local_path
        layout = discover_layout(local_path, repo.verification_dir) if local_path.exists() else None
        card = build_claim_card(repo, local_path, layout=layout, offline_fixture=args.offline_fixture)
    markdown = render_markdown(card)
    if args.out:
        Path(args.out).write_text(markdown, encoding="utf-8")
    else:
        print(markdown)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    card = load_data(args.claims)
    assessment = score_claim_card(card)
    print(f"{assessment.level}: {assessment.rationale}")
    if assessment.blockers:
        print("blockers:")
        for blocker in assessment.blockers:
            print(f"  - {blocker}")
    return 0


def cmd_receipt_verify(args: argparse.Namespace) -> int:
    attestation = load_attestation(args.attestation)
    receipt = load_receipt(args.receipt)
    result = verify_receipt(attestation, receipt, args.log_public_key, require_signatures=args.require_signatures)
    print(f"accepted: {str(result.accepted).lower()}")
    print(f"log_id: {result.log_id or 'unknown'}")
    print(f"tree_size: {result.tree_size if result.tree_size is not None else 'unknown'}")
    print(f"leaf_hash: {result.leaf_hash or 'unknown'}")
    print("signatures:")
    for name, status in sorted(result.signatures.items()):
        print(f"  {name}: {status}")
    if result.diagnostics:
        print("diagnostics:")
        for diagnostic in result.diagnostics:
            print(f"  - {diagnostic}")
    return 0 if result.accepted else 1


def cmd_agent(args: argparse.Namespace) -> int:
    card = _card_for_agent(args)
    decision = run_agent_action(
        card,
        action=args.action,
        artifact_root=args.artifact_dir,
        minimum_build_risk=args.min_risk,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )
    component_dir = component_artifact_dir(args.artifact_dir, str(card.get("component") or "component"))
    component_dir.mkdir(parents=True, exist_ok=True)
    dump_data(card, component_dir / "claims.yaml")
    (component_dir / "report.md").write_text(render_markdown(card), encoding="utf-8")
    decision_path = write_decision(decision, args.artifact_dir, str(card.get("component") or "component"))
    print(f"action: {decision.requested_action}")
    print(f"allowed: {str(decision.allowed).lower()}")
    print(f"risk: {decision.risk_level}")
    print(f"decision: {decision_path}")
    if decision.artifact:
        print(f"artifact: {decision.artifact.artifact_dir}")
        if decision.artifact.crate_dir:
            print(f"crate: {decision.artifact.crate_dir}")
        if decision.artifact.log_path:
            print(f"log: {decision.artifact.log_path}")
    print(decision.rationale)
    return 0 if decision.allowed else 1


def _card_for_agent(args: argparse.Namespace) -> dict[str, Any]:
    if args.claims:
        return load_data(args.claims)
    if not args.config or not args.repo_name:
        raise ValueError("agent requires --claims or both --config and --repo-name")
    config = load_config(args.config)
    repo = config.repo_named(args.repo_name)
    if args.clone:
        status = clone_or_fetch(repo, args.base_dir, fetch=True)
        local_path = status.local_path
    else:
        local_path = Path(args.repo) if args.repo else status_for(repo, args.base_dir).local_path
    layout = discover_layout(local_path, repo.verification_dir) if local_path.exists() else None
    if layout is None and not args.offline_fixture:
        raise ValueError(f"Local repo does not exist: {local_path}")
    check_result = None
    axiom_result = None
    if args.run_axioms:
        if layout is None:
            raise ValueError("--run-axioms requires a local repository")
        profile = get_profile(repo.kind, repo)
        env_script = args.env_script or repo.env_script
        lean_project_dir = args.lean_project_dir or repo.lean_project_dir
        check_result = lean_check_files(
            layout.compile_order,
            layout.verification_dir,
            timeout=args.timeout,
            log_dir=args.log_dir,
            env_script=env_script,
            lean_project_dir=lean_project_dir,
        )
        axiom_result = run_axiom_audit(
            local_path / repo.verification_dir,
            profile.axiom_imports,
            repo.certificates or profile.default_certificates,
            profile.expected_axioms,
            timeout=args.timeout,
            log_dir=args.log_dir,
            env_script=env_script,
            lean_project_dir=lean_project_dir,
            certificate_axioms=profile.certificate_axioms,
        )
    attestation = _attestation_for_args(args, repo)
    return build_claim_card(
        repo,
        local_path,
        layout=layout,
        lean_check=check_result,
        axiom_audit=axiom_result,
        attestation=attestation,
        offline_fixture=args.offline_fixture,
    )


def _repo_from_optional_config(config_path: str | None, repo_name: str | None, verification_dir: str) -> RepoConfig:
    if config_path:
        config = load_config(config_path)
        if not repo_name:
            raise ValueError("--repo-name is required with --config")
        return config.repo_named(repo_name)
    return RepoConfig(name=Path(".").resolve().name, verification_dir=verification_dir)


def print_yaml(data: dict[str, Any]) -> None:
    from .yamlio import dumps

    print(dumps(data), end="")


def _attestation_for_args(args: argparse.Namespace, repo: RepoConfig):
    attestation_path = getattr(args, "attestation", None)
    if not attestation_path:
        return None
    raw = load_attestation(attestation_path)
    return validate_attestation(
        raw,
        repo,
        path=attestation_path,
        trusted_provider=getattr(args, "trust_attestation_provider", None),
        public_key_path=getattr(args, "attestation_public_key", None),
        allow_unsigned=bool(getattr(args, "allow_unsigned_attestation", False)),
        transparency_receipt_path=getattr(args, "transparency_receipt", None),
        transparency_log_public_key_path=getattr(args, "transparency_log_public_key", None),
        require_transparency_signatures=str(getattr(args, "require_transparency_signatures", "ed25519")),
        require_transparency_receipt=bool(getattr(args, "require_transparency_receipt", False)),
    )
