"""warden's quorum acceptance boundary.

N-version verification where the versions are provably equivalent on the
proven domain: each quorum member is an Ed25519 verifier compiled from a
source workspace whose correctness certificates are machine-checked in
Lean 4 and replay-attested in the transparency log. Classic N-version
programming fails because independent implementations share design bugs;
here each member's accept() is characterized by a theorem, so runtime
disagreement cannot be a semantics bug on the proven domain - it is
either a documented semantic edge between the forks' accept() predicates
(anza rejects A = 0 and a legacy excluded-R list) or evidence of build
corruption / fault / tampering.

Fail-closed is unconditional: acceptance requires unanimity. The
divergence taxonomy only grades the alarm:

- ``unanimous-accept`` / ``unanimous-reject``: the boring, common cases.
- ``semantic-edge``: members disagree AND the input lies in a documented
  degenerate class (small-order R on the legacy exclusion list, zero A,
  non-canonical scalar). Verdict: reject; incident severity ``note``.
- ``unexplained``: members disagree and no documented edge explains it.
  Verdict: reject; incident severity ``tamper`` - the wallet latches.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dogfood import _git_commit, _tool_version  # shared provenance helpers

QUORUM_STATE_DIR = Path("dogfood") / "state" / "quorum"

# The four proven forks. `source_subdir` is the conventional checkout name
# under --sources-root; `component` names the transparency-log leaf whose
# certificates cover this member's verify path.
QUORUM_BACKENDS: dict[str, dict[str, Any]] = {
    "dalek": {
        "component": "dalek-ed25519-verified",
        "source_subdir": "curve25519-dalek-source",
        "crate": Path("dogfood") / "quorum" / "verify-dalek",
        "backend_cfg": 'curve25519_dalek_backend="serial"',
        "entry_point": "ed25519_dalek::VerifyingKey::verify (pinned workspace)",
        "semantics": "upstream-canonical",
        "workspace_marker": Path("ed25519-dalek") / "Cargo.toml",
    },
    "anza": {
        "component": "anza-ed25519-verified",
        "source_subdir": "anza-cryptography-source",
        "crate": Path("dogfood") / "quorum" / "verify-anza",
        "backend_cfg": "curve25519_serial_only",
        "entry_point": "curve25519::ed_sigs::VerificationKey::verify_sha512 (pinned workspace; NOT the default Zebra-lineage verify())",
        "semantics": "anza-strict (rejects A=0 and the legacy excluded-R list)",
        "workspace_marker": Path("curve25519") / "solana-ed25519" / "Cargo.toml",
    },
    "risc0": {
        "component": "risc0-ed25519-verified",
        "source_subdir": "risc0-curve25519-dalek-source",
        "crate": Path("dogfood") / "quorum" / "verify-risc0",
        "backend_cfg": 'curve25519_dalek_backend="serial"',
        "entry_point": "ed25519_dalek::VerifyingKey::verify (pinned workspace)",
        "semantics": "upstream-canonical",
        "workspace_marker": Path("ed25519-dalek") / "Cargo.toml",
    },
    "betrusted": {
        "component": "betrusted-ed25519-verified",
        "source_subdir": "betrusted-curve25519-dalek-source",
        "crate": Path("dogfood") / "quorum" / "verify-betrusted",
        "backend_cfg": 'curve25519_dalek_backend="serial"',
        "entry_point": "ed25519_dalek::VerifyingKey::verify (pinned workspace)",
        "semantics": "upstream-canonical",
        "workspace_marker": Path("ed25519-dalek") / "Cargo.toml",
    },
}

# The eight small-order points' canonical encodings plus their sign-flipped
# variants - the classic excluded-R list (as used by Solana's legacy
# exclusion and libsodium's checks). Presence of R (or A) on this list is
# what makes an inter-fork divergence a *documented semantic edge*.
SMALL_ORDER_ENCODINGS: frozenset[bytes] = frozenset(
    bytes.fromhex(h)
    for h in (
        "0100000000000000000000000000000000000000000000000000000000000000",  # identity
        "0000000000000000000000000000000000000000000000000000000000000000",  # (0, 0)-ish y=0 encoding
        "0000000000000000000000000000000000000000000000000000000000000080",  # y=0, sign flipped
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # -1 = p-1 (order 2)
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order-8 point
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order-8, sign flipped
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order-8 point
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order-8, sign flipped
        "0100000000000000000000000000000000000000000000000000000000000080",  # identity, sign flipped
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # p-1 with high bit
    )
)

# Group order l (little-endian comparison target for canonical s).
_L = 2**252 + 27742317777372353535851937790883648493


@dataclass(slots=True)
class MemberVerdict:
    backend: str
    verdict: str  # "accept" | "reject" | "error"
    detail: str | None = None
    binary_sha256: str | None = None


@dataclass(slots=True)
class QuorumResult:
    accepted: bool
    classification: str  # unanimous-accept | unanimous-reject | semantic-edge | unexplained
    verdicts: list[MemberVerdict] = field(default_factory=list)
    edge_flags: list[str] = field(default_factory=list)
    incident: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "classification": self.classification,
            "verdicts": [
                {
                    "backend": v.backend,
                    "verdict": v.verdict,
                    "detail": v.detail,
                    "binary_sha256": v.binary_sha256,
                }
                for v in self.verdicts
            ],
            "edge_flags": self.edge_flags,
            "incident": self.incident,
        }


def semantic_edge_flags(public_key: bytes, signature: bytes) -> list[str]:
    """Name the documented degenerate classes this input falls into.

    These are exactly the classes where the four proven accept() predicates
    are allowed to differ; anything outside them that still diverges is
    treated as tampering.
    """
    flags: list[str] = []
    r_bytes, s_bytes = signature[:32], signature[32:]
    if public_key == b"\x00" * 32:
        flags.append("zero-public-key")
    if public_key in SMALL_ORDER_ENCODINGS:
        flags.append("small-order-public-key")
    if r_bytes in SMALL_ORDER_ENCODINGS:
        flags.append("small-order-R (legacy exclusion list)")
    if int.from_bytes(s_bytes, "little") >= _L:
        flags.append("non-canonical-s (s >= group order)")
    return flags


def binary_path(backend: str, state_dir: str | Path | None = None) -> Path:
    return Path(state_dir or QUORUM_STATE_DIR) / f"pacta-verify-{backend}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_quorum_member(
    backend: str,
    sources_root: str | Path,
    state_dir: str | Path | None = None,
    timeout: int = 900,
) -> dict[str, Any]:
    """Build one quorum member from its pinned proven source workspace.

    Returns a provenance dict on success; raises RuntimeError with the
    cargo tail on failure. Serial backend pinned per fork exactly as the
    verified extraction pins it.
    """
    spec = QUORUM_BACKENDS[backend]
    source = (Path(sources_root).expanduser() / spec["source_subdir"]).resolve()
    crate = Path(spec["crate"]).resolve()
    if not (source / spec["workspace_marker"]).exists():
        raise RuntimeError(
            f"{source} does not look like the pinned {backend} source workspace "
            f"(missing {spec['workspace_marker']})"
        )
    cargo = shutil.which("cargo")
    if not cargo:
        raise RuntimeError("cargo is not available on PATH")
    template = (crate / "Cargo.toml.template").read_text(encoding="utf-8")
    (crate / "Cargo.toml").write_text(template.replace("{{SOURCE}}", str(source)), encoding="utf-8")
    env = dict(os.environ)
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + f" --cfg {spec['backend_cfg']}").strip()
    completed = subprocess.run(
        [cargo, "build", "--release", "--quiet"],
        cwd=str(crate),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        tail = "\n".join((completed.stderr or completed.stdout or "").strip().splitlines()[-12:])
        raise RuntimeError(f"cargo build failed for quorum member {backend}:\n{tail}")
    built = crate / "target" / "release" / f"pacta-verify-{backend}"
    if not built.exists():
        raise RuntimeError(f"cargo reported success but {built} does not exist")
    out = binary_path(backend, state_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, out)
    provenance = {
        "type": "pacta.quorum.member_provenance.v1",
        "backend": backend,
        "component": spec["component"],
        "semantics": spec["semantics"],
        "source_workspace": str(source),
        "source_commit": _git_commit(source),
        "backend_cfg": spec["backend_cfg"],
        "entry_point": spec["entry_point"],
        "rustc_version": _tool_version("rustc"),
        "cargo_version": _tool_version("cargo"),
        "binary_sha256": _sha256_file(out),
    }
    out.with_suffix(".provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return provenance


def member_provenance(backend: str, state_dir: str | Path | None = None) -> dict[str, Any]:
    sidecar = binary_path(backend, state_dir).with_suffix(".provenance.json")
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return {}


class QuorumVerifier:
    """Run every member on the same bytes; demand unanimity; grade dissent."""

    def __init__(
        self,
        members: dict[str, Path],
        min_members: int = 2,
        timeout: int = 30,
    ) -> None:
        if len(members) < min_members:
            raise ValueError(
                f"quorum needs at least {min_members} members, got {len(members)}: "
                f"{sorted(members)}"
            )
        missing = {name: path for name, path in members.items() if not Path(path).exists()}
        if missing:
            raise ValueError(f"quorum member binaries missing: {missing}")
        self.members = {name: Path(path) for name, path in members.items()}
        self.timeout = timeout

    def verify(self, payload: bytes, signature: bytes, public_key: bytes) -> QuorumResult:
        if len(signature) != 64 or len(public_key) != 32:
            raise ValueError("signature must be 64 bytes and public key 32 bytes")
        verdicts: list[MemberVerdict] = []
        with tempfile.TemporaryDirectory(prefix="pacta-quorum-") as tmp:
            payload_path = Path(tmp) / "payload.bin"
            payload_path.write_bytes(payload)
            for name, binary in sorted(self.members.items()):
                verdicts.append(self._run_member(name, binary, public_key, signature, payload_path))
        return self._judge(verdicts, payload, signature, public_key)

    def _run_member(
        self, name: str, binary: Path, public_key: bytes, signature: bytes, payload_path: Path
    ) -> MemberVerdict:
        sha = _sha256_file(binary)
        try:
            completed = subprocess.run(
                [str(binary), public_key.hex(), signature.hex(), str(payload_path)],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return MemberVerdict(name, "error", "timeout", sha)
        if completed.returncode == 0:
            return MemberVerdict(name, "accept", None, sha)
        if completed.returncode == 1:
            return MemberVerdict(name, "reject", None, sha)
        detail = (completed.stderr or completed.stdout or "member error").strip()
        return MemberVerdict(name, "error", detail, sha)

    def _judge(
        self,
        verdicts: list[MemberVerdict],
        payload: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> QuorumResult:
        kinds = {v.verdict for v in verdicts}
        if kinds == {"accept"}:
            return QuorumResult(True, "unanimous-accept", verdicts)
        if kinds == {"reject"}:
            return QuorumResult(False, "unanimous-reject", verdicts)
        # Divergence (including any member error): reject, then grade.
        flags = semantic_edge_flags(public_key, signature)
        classification = "semantic-edge" if flags and "error" not in kinds else "unexplained"
        incident = {
            "type": "pacta.quorum.divergence.v1",
            "severity": "note" if classification == "semantic-edge" else "tamper",
            "classification": classification,
            "edge_flags": flags,
            "verdicts": [
                {"backend": v.backend, "verdict": v.verdict, "detail": v.detail, "binary_sha256": v.binary_sha256}
                for v in verdicts
            ],
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "signature_hex": signature.hex(),
            "public_key_hex": public_key.hex(),
        }
        return QuorumResult(False, classification, verdicts, flags, incident)


def load_quorum(
    backends: list[str] | None = None,
    state_dir: str | Path | None = None,
    min_members: int = 2,
) -> QuorumVerifier:
    """Assemble the quorum from built member binaries in the state dir."""
    names = backends or list(QUORUM_BACKENDS)
    members = {
        name: binary_path(name, state_dir)
        for name in names
        if binary_path(name, state_dir).exists()
    }
    return QuorumVerifier(members, min_members=min_members)
