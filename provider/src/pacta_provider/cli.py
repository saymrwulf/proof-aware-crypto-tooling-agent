from __future__ import annotations

import argparse
import json
from pathlib import Path

from pacta.config import load_config
from pacta.signing import generate_ed25519_keypair
from pacta.yamlio import dump_data

from .discovery import discover_toolchains
from .service import build_attestation


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
