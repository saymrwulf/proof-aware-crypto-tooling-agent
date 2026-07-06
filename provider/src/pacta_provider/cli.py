from __future__ import annotations

import argparse
import json
from pathlib import Path

from pacta.config import load_config
from pacta.signing import generate_ed25519_keypair
from pacta.yamlio import dump_data

from .discovery import discover_toolchains
from .service import build_attestation
from .transparency_log import TransparencyLog


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}")
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pacta-provider", description="PACTA proof-checking attestation provider.")
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser("discover", help="Find reusable local Lean/Aeneas toolchains.")
    discover.add_argument("--root", action="append")
    discover.add_argument("--max-depth", type=int, default=6)
    discover.set_defaults(func=cmd_discover)

    init_key = sub.add_parser("init-key", help="Create an Ed25519 provider signing keypair.")
    init_key.add_argument("--key-dir", default="provider/state/local-provider")
    init_key.set_defaults(func=cmd_init_key)

    check = sub.add_parser("check", help="Run proof checks and emit a signed attestation.")
    check.add_argument("--config", required=True)
    check.add_argument("--repo-name", required=True)
    check.add_argument("--repo", required=True)
    check.add_argument("--provider", required=True)
    check.add_argument("--private-key", required=True)
    check.add_argument("--public-key", required=True)
    check.add_argument("--env-script")
    check.add_argument("--lean-project-dir")
    check.add_argument("--timeout", type=int, default=120)
    check.add_argument("--log-dir", default="provider/out/logs")
    check.add_argument("--out", required=True)
    check.set_defaults(func=cmd_check)

    log_init = sub.add_parser("log-init", help="Initialize a local RFC9162-style transparency log.")
    log_init.add_argument("--log-dir", default="provider/state/transparency-log")
    log_init.add_argument("--provider", required=True)
    log_init.add_argument("--public-key", required=True)
    log_init.set_defaults(func=cmd_log_init)

    log_append = sub.add_parser("log-append", help="Append a signed proof-check attestation and emit an inclusion receipt.")
    log_append.add_argument("--log-dir", default="provider/state/transparency-log")
    log_append.add_argument("--attestation", required=True)
    log_append.add_argument("--private-key", required=True)
    log_append.add_argument("--public-key", required=True)
    log_append.add_argument("--out", required=True)
    log_append.set_defaults(func=cmd_log_append)

    log_publish = sub.add_parser("log-publish", help="Export the log's public face into a git-publishable directory (entries, STH history, receipts).")
    log_publish.add_argument("--log-dir", required=True)
    log_publish.add_argument("--git-dir", required=True)
    log_publish.add_argument("--public-key", help="Provider public key to include in the published repo.")
    log_publish.set_defaults(func=cmd_log_publish)

    serve = sub.add_parser("serve", help="Serve the log read-only over HTTP (CT-style endpoints + customer docs). Never touches private keys.")
    serve.add_argument("--log-dir", required=True)
    serve.add_argument("--base-path", default="lean-transparency-log")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8461)
    serve.set_defaults(func=cmd_serve)

    log_consistency = sub.add_parser("log-consistency", help="Emit a consistency proof from an earlier tree size (for pinning agents).")
    log_consistency.add_argument("--log-dir", required=True)
    log_consistency.add_argument("--from-size", type=int, required=True)
    log_consistency.add_argument("--out", help="Write the proof document here (default: stdout).")
    log_consistency.set_defaults(func=cmd_log_consistency)

    log_audit = sub.add_parser("log-audit", help="Monitor check: recompute the tree, verify the stored STH and append-only structure.")
    log_audit.add_argument("--log-dir", required=True)
    log_audit.set_defaults(func=cmd_log_audit)

    log_sth = sub.add_parser("log-sth", help="Sign and print the latest transparency-log tree head.")
    log_sth.add_argument("--log-dir", default="provider/state/transparency-log")
    log_sth.add_argument("--private-key", required=True)
    log_sth.add_argument("--public-key", required=True)
    log_sth.set_defaults(func=cmd_log_sth)
    return parser


def cmd_discover(args: argparse.Namespace) -> int:
    candidates = discover_toolchains(args.root, max_depth=args.max_depth)
    print(json.dumps([candidate.to_dict() for candidate in candidates], indent=2))
    return 0 if candidates else 1


def cmd_init_key(args: argparse.Namespace) -> int:
    key_dir = Path(args.key_dir)
    private_key = key_dir / "provider.ed25519.key"
    public_key = key_dir / "provider.ed25519.pub"
    if private_key.exists() or public_key.exists():
        raise ValueError(f"Refusing to overwrite existing key files in {key_dir}")
    generate_ed25519_keypair(private_key, public_key)
    print(f"private_key: {private_key}")
    print(f"public_key: {public_key}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    repo = config.repo_named(args.repo_name)
    attestation = build_attestation(
        repo,
        args.repo,
        provider=args.provider,
        private_key=args.private_key,
        public_key=args.public_key,
        env_script=args.env_script,
        lean_project_dir=args.lean_project_dir,
        timeout=args.timeout,
        log_dir=args.log_dir,
    )
    dump_data(attestation, args.out)
    print(f"attestation: {args.out}")
    return 0


def cmd_log_init(args: argparse.Namespace) -> int:
    metadata = TransparencyLog(args.log_dir).init(args.provider, args.public_key)
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


def cmd_log_append(args: argparse.Namespace) -> int:
    receipt = TransparencyLog(args.log_dir).append_attestation(
        args.attestation,
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        receipt_out=args.out,
    )
    print(f"receipt: {args.out}")
    print(f"log_id: {receipt['log_id']}")
    print(f"tree_size: {receipt['tree_size']}")
    print(f"leaf_hash: {receipt['leaf_hash']}")
    print(f"ed25519_sth_signature: {receipt['sth']['signatures']['ed25519']['status']}")
    print(f"ml_dsa_sth_signature: {receipt['sth']['signatures']['ml_dsa']['status']}")
    return 0


def cmd_log_publish(args) -> int:
    log = TransparencyLog(args.log_dir)
    report = log.publish(args.git_dir, public_key_path=args.public_key)
    print(f"published {report['entries']} entries, components: {', '.join(report['components'])}")
    print(f"out: {report['out']}")
    return 0


def cmd_serve(args) -> int:
    from .web import serve as make_server

    server = make_server(args.log_dir, base_path=args.base_path, host=args.host, port=args.port)
    print(f"serving read-only log on http://{args.host}:{args.port}/{args.base_path.strip('/')}/docs")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_log_consistency(args) -> int:
    from pacta.yamlio import dump_data

    log = TransparencyLog(args.log_dir)
    document = log.consistency_from(args.from_size)
    if args.out:
        dump_data(document, args.out)
        print(f"consistency proof: {args.out}")
    else:
        for key in ("log_id", "from_tree_size", "from_root_hash", "to_tree_size", "to_root_hash"):
            print(f"{key}: {document[key]}")
        for item in document["proof"]:
            print(f"  {item}")
    return 0


def cmd_log_audit(args) -> int:
    log = TransparencyLog(args.log_dir)
    report = log.audit()
    print(f"tree_size: {report['tree_size']}")
    print(f"computed_root: {report['computed_root']}")
    print(f"stored_sth_root: {report['stored_sth_root']}")
    if report["problems"]:
        print("problems:")
        for problem in report["problems"]:
            print(f"  - {problem}")
    print(f"ok: {str(report['ok']).lower()}")
    return 0 if report["ok"] else 1


def cmd_log_sth(args: argparse.Namespace) -> int:
    sth = TransparencyLog(args.log_dir).latest_sth(args.private_key, args.public_key)
    print(json.dumps(sth, indent=2, sort_keys=True))
    return 0
