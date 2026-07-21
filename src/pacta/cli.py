from __future__ import annotations

import argparse
import json
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
from .repo import clone_or_fetch, status_for, resolve_lean_guard
from .report import render_markdown
from .risk import score_claim_card
from .sthstore import check_sth_against_store, check_sth_freshness
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
    claims.add_argument("--sth-store")
    claims.add_argument("--consistency-proof")
    claims.add_argument("--max-sth-age-seconds", type=int)
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
    receipt_verify.add_argument("--sth-store", help="Path to the local STH pin store (split-view/rollback defense).")
    receipt_verify.add_argument("--consistency-proof", help="File with a hex consistency proof from the pinned tree size (provider: log-consistency).")
    receipt_verify.add_argument("--max-sth-age-seconds", type=int, help="Reject signed tree heads older than this (freshness policy).")
    receipt_verify.add_argument("--require-verified-verifier", action="store_true", help="Fail closed unless Ed25519 verification ran on the dogfood (certificate-covered) verifier.")
    receipt_verify.set_defaults(func=cmd_receipt_verify)

    log_fetch = sub.add_parser("log-fetch", help="Fetch attestation + inclusion proof for a component from an ONLINE log; verify locally afterwards.")
    log_fetch.add_argument("--url", required=True, help="Base URL, e.g. https://ltl.zkdefi.org")
    log_fetch.add_argument("--component", required=True)
    log_fetch.add_argument("--out-dir", default="fetched-evidence")
    log_fetch.set_defaults(func=cmd_log_fetch)

    sth_refresh = sub.add_parser("sth-refresh", help="Fetch the latest STH online, verify signature + consistency from the pinned size, advance the pin.")
    sth_refresh.add_argument("--url", required=True)
    sth_refresh.add_argument("--sth-store", required=True)
    sth_refresh.add_argument("--log-public-key", required=True)
    sth_refresh.set_defaults(func=cmd_sth_refresh)

    witness = sub.add_parser("witness-audit", help="Audit a CLONE of the published log repo: recompute every prefix root, check every historical STH + signature.")
    witness.add_argument("--published-dir", required=True)
    witness.add_argument("--log-public-key")
    witness.set_defaults(func=cmd_witness_audit)

    dogfood_build = sub.add_parser("dogfood-build", help="Build the dogfood Ed25519 verifier from the pinned proven source workspace.")
    dogfood_build.add_argument("--source", required=True, help="Local checkout of saymrwulf/curve25519-dalek-source (the pinned proven workspace).")
    dogfood_build.add_argument("--timeout", type=int, default=900)
    dogfood_build.set_defaults(func=cmd_dogfood_build)

    dogfood_status = sub.add_parser("dogfood-status", help="Show which Ed25519 verification backend pacta will use, with provenance.")
    dogfood_status.set_defaults(func=cmd_dogfood_status)

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
    agent.add_argument("--sth-store", help="Path to the local STH pin store (split-view/rollback defense).")
    agent.add_argument("--consistency-proof", help="File with a hex consistency proof from the pinned tree size.")
    agent.add_argument("--max-sth-age-seconds", type=int, help="Reject signed tree heads older than this.")
    agent.add_argument("--require-verified-verifier", action="store_true", help="Fail closed unless Ed25519 verification ran on the dogfood (certificate-covered) verifier.")
    agent.set_defaults(func=cmd_agent)

    wallet = sub.add_parser("wallet", help="warden: the verified-custody wallet (quorum boundary + signing firewall).")
    wsub = wallet.add_subparsers(dest="wallet_cmd", required=True)

    w_build = wsub.add_parser("build-quorum", help="Build the quorum verifier members from the pinned proven source workspaces.")
    w_build.add_argument("--sources-root", required=True, help="Directory holding the pinned fork source checkouts.")
    w_build.add_argument("--backends", nargs="*", help="Subset of dalek anza risc0 betrusted (default: all).")
    w_build.add_argument("--timeout", type=int, default=900)
    w_build.set_defaults(func=cmd_wallet_build_quorum)

    w_init = wsub.add_parser("init", help="Create a wallet - the R4 gate in executable form (refuses below end-to-end coverage).")
    w_init.add_argument("--wallet", required=True)
    w_init.add_argument("--evidence", required=True, help="Directory of <component>.attestation.json + .receipt.json (e.g. from `pacta log-fetch`).")
    w_init.add_argument("--log-public-key", required=True)
    w_init.add_argument("--trusted-provider", required=True, help="Whose observations you trust (verdicts are always re-derived locally).")
    w_init.add_argument("--repos-config", default="examples/repos.yaml")
    w_init.add_argument("--backends", nargs="*")
    w_init.add_argument("--require-tier", default="R4")
    w_init.add_argument("--min-members", type=int, default=2)
    w_init.add_argument("--freshness-days", type=int, default=30)
    w_init.set_defaults(func=cmd_wallet_init)

    w_status = wsub.add_parser("status", help="Show wallet custody posture.")
    w_status.add_argument("--wallet", required=True)
    w_status.set_defaults(func=cmd_wallet_status)

    w_card = wsub.add_parser("card", help="Emit the self-proving custody card (optionally to a .well-known dir).")
    w_card.add_argument("--wallet", required=True)
    w_card.add_argument("--out-dir", help="Write .well-known/custody-card.json under this directory.")
    w_card.add_argument("--log-url", default="https://ltl.zkdefi.org")
    w_card.set_defaults(func=cmd_wallet_card)

    w_mcp = wsub.add_parser("mcp", help="Serve the agent-native MCP surface over stdio JSON-RPC.")
    w_mcp.add_argument("--wallet", required=True)
    w_mcp.add_argument("--log-url", default="https://ltl.zkdefi.org")
    w_mcp.set_defaults(func=cmd_wallet_mcp)

    w_cockpit = wsub.add_parser("cockpit", help="Serve the read-only custody cockpit (local web UI) for the human operator.")
    w_cockpit.add_argument("--wallet", help="Path to an existing wallet directory.")
    w_cockpit.add_argument("--demo", action="store_true", help="No wallet yet? Serve a throwaway DEMO wallet (fake members, custody-inert) to explore the views.")
    w_cockpit.add_argument("--host", default="127.0.0.1", help="Bind address (default localhost; the cockpit is not meant to be exposed).")
    w_cockpit.add_argument("--port", type=int, default=8471)
    w_cockpit.set_defaults(func=cmd_wallet_cockpit)

    w_ledger = wsub.add_parser("verify-ledger", help="Re-check the wallet's hash-chained ledger integrity.")
    w_ledger.add_argument("--wallet", required=True)
    w_ledger.set_defaults(func=cmd_wallet_verify_ledger)

    w_unlatch = wsub.add_parser("unlatch", help="Release a tamper latch (deliberate operator act; the note is recorded permanently).")
    w_unlatch.add_argument("--wallet", required=True)
    w_unlatch.add_argument("--note", required=True)
    w_unlatch.set_defaults(func=cmd_wallet_unlatch)

    w_policy = wsub.add_parser("policy", help="Show the wallet's spending policy (policy.json), or write a starter template.")
    w_policy.add_argument("--wallet", required=True)
    w_policy.add_argument("--init-template", action="store_true", help="Write a commented starter policy.json (refuses to overwrite).")
    w_policy.set_defaults(func=cmd_wallet_policy)

    w_treasury = wsub.add_parser("treasury-verify", help="Quorum-verify every signature of a Solana transaction (RPC demoted to bandwidth).")
    w_treasury.add_argument("--wallet", required=True)
    group = w_treasury.add_mutually_exclusive_group(required=True)
    group.add_argument("--tx-file", help="File with wire-format transaction bytes (raw or base64).")
    group.add_argument("--tx-sig", help="Transaction signature (base58) to fetch via --rpc-url.")
    w_treasury.add_argument("--rpc-url", help="Solana JSON-RPC endpoint (required with --tx-sig).")
    w_treasury.set_defaults(func=cmd_wallet_treasury_verify)

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
        lean_guard=resolve_lean_guard(repo.lean_guard, args.repo),
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
        lean_guard=resolve_lean_guard(repo.lean_guard, args.repo),
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
            lean_guard=resolve_lean_guard(repo.lean_guard, local_path),
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
            lean_guard=resolve_lean_guard(repo.lean_guard, local_path),
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
    accountability_diagnostics = _log_accountability_checks(
        receipt,
        sth_store=args.sth_store,
        consistency_proof_path=args.consistency_proof,
        max_sth_age_seconds=args.max_sth_age_seconds,
        head_signature_verified=result.signatures.get("ed25519") == "verified",
    )
    if args.require_verified_verifier and result.signatures.get("ed25519_backend") != "verified-dalek-serial":
        accountability_diagnostics.append(
            "Policy requires the dogfood (certificate-covered) Ed25519 verifier, but verification ran on backend "
            f"'{result.signatures.get('ed25519_backend', 'none')}'."
        )
    if accountability_diagnostics:
        result.accepted = False
        result.diagnostics.extend(accountability_diagnostics)
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


def cmd_log_fetch(args: argparse.Namespace) -> int:
    from .logclient import LogClientError, fetch_evidence

    try:
        paths = fetch_evidence(args.url, args.component, args.out_dir)
    except LogClientError as exc:
        print(f"error: {exc}")
        return 1
    for kind, path in paths.items():
        print(f"{kind}: {path}")
    print("fetched material is UNVERIFIED until you run receipt-verify on it (transport is not trust).")
    return 0


def cmd_sth_refresh(args: argparse.Namespace) -> int:
    from .logclient import LogClientError, refresh_pin

    try:
        ok, diagnostics = refresh_pin(args.url, args.sth_store, args.log_public_key)
    except LogClientError as exc:
        print(f"error: {exc}")
        return 1
    for diagnostic in diagnostics:
        print(("" if ok else "REFUSED: ") + diagnostic)
    return 0 if ok else 1


def cmd_witness_audit(args: argparse.Namespace) -> int:
    from .witness import audit_published_log

    report = audit_published_log(args.published_dir, args.log_public_key)
    print(f"entries: {report.tree_size} | heads checked: {report.heads_checked}")
    for note in report.notes:
        print(f"note: {note}")
    for problem in report.problems:
        print(f"PROBLEM: {problem}")
    print(f"ok: {str(report.ok).lower()}")
    return 0 if report.ok else 1


def cmd_dogfood_build(args: argparse.Namespace) -> int:
    from .dogfood import build_verifier

    result = build_verifier(args.source, timeout=args.timeout)
    for diagnostic in result.diagnostics:
        print(diagnostic)
    if not result.built:
        print("dogfood verifier NOT built; Ed25519 verification falls back to OpenSSL (recorded as a downgrade).")
        return 1
    print(f"binary: {result.binary_path}")
    for key in ("source_commit", "backend_cfg", "rustc_version"):
        print(f"{key}: {result.provenance.get(key)}")
    print("coverage: " + str(result.provenance.get("coverage_note")))
    return 0


def cmd_dogfood_status(args: argparse.Namespace) -> int:
    from .dogfood import BACKEND_OPENSSL, BACKEND_VERIFIED, load_provenance, locate_verifier

    binary = locate_verifier()
    if binary is None:
        print(f"backend: {BACKEND_OPENSSL} (fallback)")
        print("dogfood verifier not built. Build with: pacta dogfood-build --source <pinned-workspace>")
        return 1
    print(f"backend: {BACKEND_VERIFIED}")
    print(f"binary: {binary}")
    provenance = load_provenance(binary)
    for key in ("source_workspace", "source_commit", "backend_cfg", "rustc_version"):
        print(f"{key}: {provenance.get(key)}")
    return 0


def _log_accountability_checks(
    receipt: dict,
    sth_store: str | None,
    consistency_proof_path: str | None,
    max_sth_age_seconds: int | None,
    head_signature_verified: bool = False,
) -> list[str]:
    diagnostics: list[str] = []
    sth = receipt.get("sth") or {}
    if max_sth_age_seconds is not None:
        fresh, error = check_sth_freshness(sth, max_sth_age_seconds)
        if not fresh:
            diagnostics.append(error or "Signed tree head fails the freshness policy.")
    if sth_store and not head_signature_verified:
        # Only a validly signed head may drive the pin-store state machine;
        # an unauthenticated head must not be able to poison the pin.
        diagnostics.append(
            "STH store: head signature did not verify; pin store not consulted or updated."
        )
    elif sth_store:
        proof_hex = None
        if consistency_proof_path:
            from .yamlio import load_data

            raw = load_data(consistency_proof_path)
            proof_hex = [str(item) for item in (raw.get("proof") if isinstance(raw, dict) else raw) or []]
        check = check_sth_against_store(
            sth,
            sth_store,
            consistency_proof_hex=proof_hex,
            consistency_from=receipt.get("consistency"),
        )
        for note in check.diagnostics:
            prefix = "" if check.ok else "STH store: "
            if check.ok:
                print(f"sth-store: {note}")
            else:
                diagnostics.append(prefix + note)
    return diagnostics


def cmd_wallet_build_quorum(args: argparse.Namespace) -> int:
    from .quorum import QUORUM_BACKENDS, build_quorum_member

    names = args.backends or list(QUORUM_BACKENDS)
    failures = 0
    for name in names:
        try:
            prov = build_quorum_member(name, args.sources_root, timeout=args.timeout)
            print(f"{name}: built  source={(prov['source_commit'] or '?')[:12]}  sha256={prov['binary_sha256'][:12]}")
        except (RuntimeError, KeyError) as exc:
            failures += 1
            print(f"{name}: FAILED  {exc}", file=sys.stderr)
    return 1 if failures else 0


def cmd_wallet_init(args: argparse.Namespace) -> int:
    from .wallet import Wallet, WalletError

    try:
        wallet = Wallet.init(
            args.wallet,
            args.evidence,
            args.log_public_key,
            repos_config=args.repos_config,
            trusted_provider=args.trusted_provider,
            backends=args.backends,
            require_tier=args.require_tier,
            min_members=args.min_members,
            freshness_max_age_days=args.freshness_days,
        )
    except WalletError as exc:
        print(f"R4 gate refused: {exc}", file=sys.stderr)
        return 1
    capsule = wallet.capsule()
    print(f"wallet created: {args.wallet}")
    for member in capsule["members"]:
        print(f"  {member['backend']:>10}  {member['risk_tier']}  leaf {member['evidence']['leaf_index']}  src {(member['source_commit'] or '?')[:12]}")
    print(f"  policy: unanimity of >={capsule['policy']['min_members']} at tier {capsule['policy']['require_tier']}")
    return 0


def cmd_wallet_status(args: argparse.Namespace) -> int:
    from .wallet import Wallet

    print(json.dumps(Wallet(args.wallet).posture(), indent=2, sort_keys=True))
    return 0


def cmd_wallet_card(args: argparse.Namespace) -> int:
    from .custodycard import build_custody_card, write_well_known
    from .wallet import Wallet

    wallet = Wallet(args.wallet)
    if args.out_dir:
        path = write_well_known(wallet, args.out_dir, args.log_url)
        print(f"custody card: {path}")
    else:
        print(json.dumps(build_custody_card(wallet, args.log_url), indent=2, sort_keys=True))
    return 0


def cmd_wallet_cockpit(args: argparse.Namespace) -> int:
    from .walletui import seal_demo_wallet, serve
    if bool(args.wallet) == bool(args.demo):
        print("error: pass exactly one of --wallet DIR or --demo")
        return 2
    wallet_dir = args.wallet
    if args.demo:
        wallet_dir = seal_demo_wallet()
        print("DEMO wallet (throwaway, fake members, custody-inert):")
        print(f"  {wallet_dir}")
    server = serve(wallet_dir, host=args.host, port=args.port)
    host, port = server.server_address[0], server.server_address[1]
    print(f"warden cockpit (READ-ONLY) on http://{host}:{port}  -  Ctrl-C to stop")
    print(f"  the deck:  http://{host}:{port}/deck  - all six roles live, guided by the wizard")
    print(f"  the guide: http://{host}:{port}/guide - every term explained")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def cmd_wallet_mcp(args: argparse.Namespace) -> int:
    from .walletmcp import WalletMCP

    WalletMCP(args.wallet, log_url=args.log_url).serve_stdio()
    return 0


def cmd_wallet_verify_ledger(args: argparse.Namespace) -> int:
    from .wallet import Wallet

    ok, problems = Wallet(args.wallet).verify_ledger()
    print("ledger chain: " + ("intact" if ok else "BROKEN"))
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    return 0 if ok else 1


def cmd_wallet_unlatch(args: argparse.Namespace) -> int:
    from .wallet import Wallet

    Wallet(args.wallet).unlatch(args.note)
    print("latch released; note recorded in the ledger")
    return 0


POLICY_TEMPLATE = {
    "outbound": {
        "max_amount_per_request": 100.0,
        "max_amount_per_day": 500.0,
        "counterparty_allowlist": ["example-counterparty-id"],
        "counterparty_denylist": [],
    },
    "identities": {},
    "ledger": {"rotate_at": 100000},
}


def cmd_wallet_policy(args: argparse.Namespace) -> int:
    from .wallet import Wallet

    wallet = Wallet(args.wallet)
    path = wallet.dir / "policy.json"
    if args.init_template:
        if path.exists():
            print(f"refusing to overwrite existing {path}", file=sys.stderr)
            return 1
        path.write_text(json.dumps(POLICY_TEMPLATE, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"starter policy written: {path} - edit it, the rules you would give a teenager with a debit card")
        return 0
    policy = wallet.policy()
    if not policy:
        print("no policy.json - outbound is unrestricted (run with --init-template for a starter)")
        return 0
    print(json.dumps(policy, indent=2, sort_keys=True))
    return 0


def cmd_wallet_treasury_verify(args: argparse.Namespace) -> int:
    import base64 as _b64

    from .treasury import fetch_transaction, verify_transaction
    from .wallet import Wallet

    if args.tx_sig and not args.rpc_url:
        print("--tx-sig requires --rpc-url", file=sys.stderr)
        return 2
    if args.tx_file:
        raw = Path(args.tx_file).read_bytes()
        try:
            tx = _b64.b64decode(raw, validate=True)
        except Exception:  # noqa: BLE001 - not base64, treat as wire bytes
            tx = raw
    else:
        tx = fetch_transaction(args.rpc_url, args.tx_sig)
    verdict = verify_transaction(Wallet(args.wallet), tx)
    print(json.dumps(verdict.to_dict(), indent=2, sort_keys=True))
    return 0 if verdict.authentic else 1


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
            lean_guard=resolve_lean_guard(repo.lean_guard, local_path),
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
            lean_guard=resolve_lean_guard(repo.lean_guard, local_path),
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
        sth_store_path=getattr(args, "sth_store", None),
        consistency_proof_path=getattr(args, "consistency_proof", None),
        max_sth_age_seconds=getattr(args, "max_sth_age_seconds", None),
        require_verified_verifier=bool(getattr(args, "require_verified_verifier", False)),
    )
