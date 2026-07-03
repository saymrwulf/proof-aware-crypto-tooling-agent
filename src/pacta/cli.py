from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .audit import scan_hygiene
from .claims import build_claim_card
from .config import RepoConfig, load_config
from .lean import LeanCheckResult, lean_check_files, run_axiom_audit
from .manifest import discover_layout
from .profiles import get_profile
from .repo import clone_or_fetch, status_for
from .report import render_markdown
from .risk import score_claim_card
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
    lean_check.set_defaults(func=cmd_lean_check)

    check = sub.add_parser("check", help="Alias for lean-check.")
    check.add_argument("--repo", required=True)
    check.add_argument("--verification-dir", default="verification")
    check.add_argument("--timeout", type=int, default=120)
    check.add_argument("--log-dir", default=".pacta")
    check.set_defaults(func=cmd_lean_check)

    axiom = sub.add_parser("axioms", help="Run configured Lean axiom audit.")
    axiom.add_argument("--repo", required=True)
    axiom.add_argument("--config", required=True)
    axiom.add_argument("--repo-name", required=True)
    axiom.add_argument("--timeout", type=int, default=120)
    axiom.add_argument("--log-dir", default=".pacta")
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
    result = lean_check_files(layout.compile_order, layout.verification_dir, timeout=args.timeout, log_dir=args.log_dir)
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
    check_result = lean_check_files(layout.compile_order, layout.verification_dir, timeout=args.timeout, log_dir=args.log_dir)
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
        check_result = lean_check_files(layout.compile_order, layout.verification_dir, timeout=args.timeout, log_dir=args.log_dir)
        axiom_result = run_axiom_audit(
            local_path / repo.verification_dir,
            profile.axiom_imports,
            repo.certificates or profile.default_certificates,
            profile.expected_axioms,
            timeout=args.timeout,
            log_dir=args.log_dir,
        )
    card = build_claim_card(
        repo,
        local_path,
        layout=layout,
        lean_check=check_result,
        axiom_audit=axiom_result,
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
