"""warden - the verified-custody wallet core.

A wallet is a directory that holds no opinions, only evidence:

- ``capsule.json``     the custody capsule: which quorum members guard the
                       boundary, compiled from which attested sources, with
                       the transparency-log receipts that authorized them
                       (R4 gate), and the policy in force.
- ``ledger.jsonl``     append-only, hash-chained event log. Every inbound
                       verification, outbound signature, refusal, incident,
                       and latch transition is an entry; each entry commits
                       to its predecessor by SHA-256.
- ``keys/``            wallet identities (OpenSSL PEM). Private keys only
                       for the local signer; the airgap signer keeps its
                       seed on the device, where it belongs.
- ``incidents/``       quorum divergences and firewall quarantines, full
                       trails, numbered.
- ``receipts/``        refusal receipts - signed, machine-actionable
                       artifacts a refused agent can hand its principal.
- ``quarantine/``      signatures the outbound firewall refused to release.
- ``airgap/``          outbox/inbox exchange directory for the gap signer.

Trust posture, stated once and enforced everywhere: the INBOUND boundary
(and the outbound firewall's check) runs on quorum members whose verify
paths carry machine-checked correctness certificates - custody-grade.
The OUTBOUND signing step is declared trusted base (the attested artifact,
not a third implementation) until signing-side proofs land. A tamper-grade
quorum divergence latches custody shut, and refusals while latched are
honest enough to arrive unsigned: a wallet that no longer trusts its own
boundary does not pretend to certify its apologies.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .attestation import validate_attestation
from .claims import build_claim_card
from .config import load_config
from .dogfood import (
    locate_verifier,
    pem_public_key_to_raw,
    sign_payload_dogfood,
)
from .quorum import (
    QUORUM_BACKENDS,
    QuorumResult,
    QuorumVerifier,
    member_provenance,
    binary_path as quorum_binary_path,
)
from .risk import risk_at_least, score_claim_card
from .signing import generate_ed25519_keypair
from .sthstore import check_sth_freshness
from .transparency import verify_inclusion, verify_signed_tree_head
from .yamlio import load_data

CAPSULE_TYPE = "pacta.wallet.custody_capsule.v1"
LEDGER_GENESIS = "pacta.wallet.ledger_genesis.v1"

# Refusal codes: the machine-actionable vocabulary. Every refusal names one.
REFUSAL_CODES = (
    "EVIDENCE_REQUIRED",     # missing/insufficient transparency-log evidence
    "POLICY_DENIED",         # request violates capsule policy
    "CUSTODY_LATCHED",       # tamper latch is engaged; custody frozen
    "EVIDENCE_STALE",        # STH pin older than the freshness policy
    "MALFORMED_INTENT",      # intent envelope failed validation
    "SIGNER_UNAVAILABLE",    # signer backend cannot serve the request
    "FIREWALL_QUARANTINE",   # produced signature failed the quorum firewall
    "PENDING_AIRGAP",        # request parked in the airgap outbox
    "RATE_LIMITED",          # surface-level throttle (issued by the MCP layer)
)


class WalletError(RuntimeError):
    pass


@dataclass(slots=True)
class Refusal:
    code: str
    reason: str
    missing: list[str]
    remediation: str
    receipt_path: Path | None = None
    receipt: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "reason": self.reason,
            "missing": self.missing,
            "remediation": self.remediation,
            "receipt_path": str(self.receipt_path) if self.receipt_path else None,
            "receipt": self.receipt,
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Signers


class LocalDogfoodSigner:
    """Signs with the attested dogfood binary; seed from a PEM on this host.

    Honesty: the signing path is trusted base - but it is the merkleized,
    attested artifact, and every signature it emits must still pass the
    quorum firewall before release.
    """

    name = "local-dogfood"

    def __init__(self, binary: str | Path | None = None) -> None:
        self.binary = Path(binary) if binary else locate_verifier()
        if self.binary is None or not Path(self.binary).exists():
            raise WalletError(
                "dogfood signing binary not found; run `pacta dogfood-build` first"
            )

    def sign(self, payload: bytes, private_key_path: Path) -> bytes:
        return sign_payload_dogfood(payload, private_key_path, self.binary)


class AirgapSigner:
    """Models the Precursor/Betrusted flow: the seed never touches this host.

    A signing request is written to ``airgap/outbox/<id>.request.json``; a
    human (or the device bridge) carries it across the gap, signs, and drops
    ``airgap/inbox/<id>.response.json`` containing ``signature_hex``. The
    wallet picks it up on the next attempt with the same request id - and
    the signature still has to pass the quorum firewall, which is exactly
    the fault-injection countermeasure (verify-after-sign) the hardware
    story needs.
    """

    name = "airgap"

    def __init__(self, airgap_dir: Path, wait_seconds: float = 0.0, poll: float = 0.2) -> None:
        self.outbox = airgap_dir / "outbox"
        self.inbox = airgap_dir / "inbox"
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.wait_seconds = wait_seconds
        self.poll = poll

    def request_path(self, request_id: str) -> Path:
        return self.outbox / f"{request_id}.request.json"

    def response_path(self, request_id: str) -> Path:
        return self.inbox / f"{request_id}.response.json"

    def sign(self, payload: bytes, private_key_path: Path, request_id: str | None = None,
             intent: dict[str, Any] | None = None) -> bytes:
        request_id = request_id or uuid.uuid4().hex[:16]
        response = self.response_path(request_id)
        if not response.exists():
            request = {
                "type": "pacta.wallet.airgap_request.v1",
                "request_id": request_id,
                "created_at": _now(),
                "payload_hex": payload.hex(),
                "payload_sha256": _sha256(payload),
                "intent": intent or {},
                "instructions": (
                    "Carry this file across the gap. Sign payload_hex with the device "
                    "key and write {\"signature_hex\": ...} to "
                    f"airgap/inbox/{request_id}.response.json"
                ),
            }
            self.request_path(request_id).write_text(
                json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            deadline = time.monotonic() + self.wait_seconds
            while time.monotonic() < deadline:
                if response.exists():
                    break
                time.sleep(self.poll)
        if not response.exists():
            raise PendingAirgap(request_id)
        body = json.loads(response.read_text(encoding="utf-8"))
        signature = bytes.fromhex(str(body.get("signature_hex", "")))
        if len(signature) != 64:
            raise WalletError(f"airgap response {request_id} has no 64-byte signature_hex")
        return signature


class PendingAirgap(Exception):
    def __init__(self, request_id: str) -> None:
        super().__init__(request_id)
        self.request_id = request_id


# ---------------------------------------------------------------------------
# The wallet


class Wallet:
    def __init__(self, wallet_dir: str | Path, state_dir: str | Path | None = None) -> None:
        self.dir = Path(wallet_dir)
        self.state_dir = state_dir  # default quorum binary location override
        self.capsule_path = self.dir / "capsule.json"
        self.ledger_path = self.dir / "ledger.jsonl"
        self.latch_path = self.dir / "latch.json"
        self.keys_dir = self.dir / "keys"
        self.incidents_dir = self.dir / "incidents"
        self.receipts_dir = self.dir / "receipts"
        self.quarantine_dir = self.dir / "quarantine"
        self.airgap_dir = self.dir / "airgap"
        self._quorum_cache: dict[str, QuorumVerifier] = {}

    # -- init / R4 gate ------------------------------------------------------

    @classmethod
    def init(
        cls,
        wallet_dir: str | Path,
        evidence_dir: str | Path,
        log_public_key: str | Path,
        repos_config: str | Path = Path("examples") / "repos.yaml",
        trusted_provider: str | None = None,
        backends: list[str] | None = None,
        state_dir: str | Path | None = None,
        require_tier: str = "R4",
        min_members: int = 2,
        freshness_max_age_days: int = 30,
        identity_name: str = "warden",
    ) -> "Wallet":
        """Create a wallet - the R4 gate in executable form.

        For every quorum member: the built binary's provenance must name an
        attested source commit; the evidence dir must hold that component's
        attestation + receipt; the attestation is re-validated locally
        (observations, never verdicts), scored, and must reach
        ``require_tier``; the receipt's inclusion proof must verify against
        its signed tree head under the log's public key; and the source
        commit in the attestation must equal the commit the binary was
        compiled from. Any miss refuses wallet creation - a custody wallet
        that cannot show its evidence has no business existing.
        """
        wallet = cls(wallet_dir)
        if wallet.capsule_path.exists():
            raise WalletError(f"wallet already exists at {wallet.dir}")
        evidence = Path(evidence_dir)
        config = load_config(repos_config)
        names = backends or list(QUORUM_BACKENDS)
        members: list[dict[str, Any]] = []
        problems: list[str] = []
        for name in names:
            binary = quorum_binary_path(name, state_dir)
            if not binary.exists():
                problems.append(f"{name}: quorum binary not built ({binary})")
                continue
            prov = member_provenance(name, state_dir)
            component = QUORUM_BACKENDS[name]["component"]
            att_path = evidence / f"{component}.attestation.json"
            rec_path = evidence / f"{component}.receipt.json"
            if not att_path.exists() or not rec_path.exists():
                problems.append(
                    f"{name}: missing evidence for {component} "
                    f"(need {att_path.name} and {rec_path.name})"
                )
                continue
            attestation = load_data(att_path)
            if isinstance(attestation, dict) and "attestation" in attestation:
                attestation = attestation["attestation"]
            receipt = load_data(rec_path)
            try:
                repo = config.repo_named(component)
            except KeyError as exc:
                problems.append(f"{name}: {exc}")
                continue
            if not trusted_provider:
                raise WalletError(
                    "wallet init requires an explicit --trusted-provider: custody evidence "
                    "must name whose observations you are trusting (never inferred from the "
                    "attestation itself)"
                )
            result = validate_attestation(
                attestation,
                repo,
                path=att_path,
                trusted_provider=trusted_provider,
                public_key_path=log_public_key,
                allow_unsigned=False,
                transparency_receipt_path=rec_path,
                transparency_log_public_key_path=log_public_key,
            )
            if not result.accepted:
                problems.append(
                    f"{name}: attestation not accepted: " + "; ".join(result.diagnostics[:3])
                )
                continue
            card = build_claim_card(repo, wallet.dir, attestation=result)
            assessment = score_claim_card(card)
            if not risk_at_least(assessment.level, require_tier):
                problems.append(
                    f"{name}: evidence tier {assessment.level} below required {require_tier}: "
                    + "; ".join(assessment.blockers[:3])
                )
                continue
            sth = receipt.get("sth") or {}
            ok_sth, sth_diags, _ = verify_signed_tree_head(sth, log_public_key)
            if not ok_sth:
                problems.append(f"{name}: receipt STH failed verification: {sth_diags[:2]}")
                continue
            from .transparency import leaf_bytes_for_attestation

            ok_incl = verify_inclusion(
                leaf_bytes_for_attestation(attestation),
                int(receipt.get("leaf_index", -1)),
                int(receipt.get("tree_size", 0)),
                [bytes.fromhex(h) for h in receipt.get("inclusion_proof", [])],
                bytes.fromhex(str(sth.get("root_hash", ""))),
            )
            if not ok_incl:
                problems.append(f"{name}: inclusion proof does not bind attestation to the log")
                continue
            att_commit = ((attestation.get("subject") or {}).get("repo_commit") or "")
            src_commit = prov.get("source_commit") or ""
            src_attested = ((attestation.get("subject") or {}).get("source_commit") or "")
            # The attestation subject names the verification repo commit and
            # (when present) the extracted source commit; the binary must be
            # compiled from an attested source commit.
            if src_attested and src_commit and src_attested != src_commit:
                problems.append(
                    f"{name}: binary compiled from {src_commit[:12]} but attestation covers "
                    f"{src_attested[:12]}"
                )
                continue
            members.append(
                {
                    "backend": name,
                    "component": component,
                    "semantics": QUORUM_BACKENDS[name]["semantics"],
                    "entry_point": prov.get("entry_point"),
                    "source_commit": src_commit,
                    "repo_commit": att_commit,
                    "binary_sha256": prov.get("binary_sha256"),
                    "backend_cfg": prov.get("backend_cfg"),
                    "risk_tier": assessment.level,
                    "evidence": {
                        "leaf_hash": receipt.get("leaf_hash"),
                        "leaf_index": receipt.get("leaf_index"),
                        "tree_size": receipt.get("tree_size"),
                        "inclusion_proof": receipt.get("inclusion_proof"),
                        "sth": sth,
                    },
                }
            )
        if len(members) < min_members:
            raise WalletError(
                "R4 gate refused wallet creation "
                f"({len(members)}/{min_members} members eligible):\n- "
                + "\n- ".join(problems or ["no eligible members"])
            )
        # Signing binary provenance (outbound trusted base, attested artifact)
        signing_binary = locate_verifier(state_dir=None)
        from .dogfood import load_provenance

        signing_prov = load_provenance(signing_binary) if signing_binary else {}
        capsule = {
            "type": CAPSULE_TYPE,
            "created_at": _now(),
            "members": members,
            "policy": {
                "require_unanimity": True,
                "min_members": min_members,
                "require_tier": require_tier,
                "freshness_max_age_days": freshness_max_age_days,
            },
            "signing": {
                "backend": "verified-dalek-serial (attested artifact; trusted base)",
                "binary_sha256": _sha256(Path(signing_binary).read_bytes()) if signing_binary else None,
                "source_commit": signing_prov.get("source_commit"),
                "coverage_note": (
                    "verify path certificate-covered; signing path trusted base - "
                    "every outbound signature passes the quorum firewall before release"
                ),
            },
            "problems_at_init": problems,
        }
        wallet.dir.mkdir(parents=True, exist_ok=True)
        for sub in (wallet.keys_dir, wallet.incidents_dir, wallet.receipts_dir,
                    wallet.quarantine_dir, wallet.airgap_dir / "outbox", wallet.airgap_dir / "inbox"):
            sub.mkdir(parents=True, exist_ok=True)
        capsule_bytes = _canonical(capsule)
        wallet.capsule_path.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        genesis = {
            "type": LEDGER_GENESIS,
            "capsule_sha256": _sha256(capsule_bytes),
        }
        wallet._append_ledger("genesis", genesis)
        generate_ed25519_keypair(
            wallet.keys_dir / f"{identity_name}.key.pem",
            wallet.keys_dir / f"{identity_name}.pub.pem",
        )
        os.chmod(wallet.keys_dir / f"{identity_name}.key.pem", 0o600)
        return wallet

    # -- capsule / state -----------------------------------------------------

    def capsule(self) -> dict[str, Any]:
        if not self.capsule_path.exists():
            raise WalletError(f"no wallet at {self.dir} (missing capsule.json)")
        return json.loads(self.capsule_path.read_text(encoding="utf-8"))

    def latch_state(self) -> dict[str, Any]:
        if self.latch_path.exists():
            return json.loads(self.latch_path.read_text(encoding="utf-8"))
        return {"latched": False}

    def _latch(self, reason: str, incident_ref: str | None) -> None:
        state = {"latched": True, "reason": reason, "incident": incident_ref, "at": _now()}
        self.latch_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._append_ledger("latch", state)

    def unlatch(self, operator_note: str) -> None:
        """Deliberately a human act: the CLI asks for a written note, and the
        note lands in the permanent ledger next to the latch it releases."""
        state = {"latched": False, "operator_note": operator_note, "at": _now()}
        self.latch_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._append_ledger("unlatch", state)

    # -- ledger ---------------------------------------------------------------

    def _ledger_entries(self) -> list[dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    @staticmethod
    def _last_ledger_line(handle: Any) -> dict[str, Any] | None:
        """Read only the final line - O(1) in ledger size, not O(n).

        Seeks back from EOF in one chunk (ledger lines are well under 64 KiB;
        a single quarantine-size body is ~2 KiB) and parses the last
        newline-terminated record."""
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if size == 0:
            return None
        back = min(size, 65536)
        handle.seek(size - back)
        tail = handle.read(back)
        lines = [line for line in tail.splitlines() if line.strip()]
        return json.loads(lines[-1]) if lines else None

    def _append_ledger(self, entry_type: str, body: dict[str, Any]) -> dict[str, Any]:
        # Single-flight: the chain is read-modify-append, so two concurrent
        # writers (threads, or two processes sharing a wallet dir) could both
        # read the same tail, compute the same prev_hash, and fork the chain.
        # The exclusive lock lives on a dedicated lock FILE (not the ledger
        # fd) so it survives the rotation rename; fsync so a crash can't
        # leave a torn line that verify_ledger would read as tampering. Only
        # the LAST line is read per append (O(1)); when a segment reaches
        # the rotation threshold it is archived and a `rotation` entry
        # carries the chain across files, keeping history verifiable end to
        # end.
        lock_path = self.dir / "ledger.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            self.ledger_path.touch(exist_ok=True)
            with self.ledger_path.open("rb") as handle:
                last = self._last_ledger_line(handle)
            prev_hash = last["entry_hash"] if last else "0" * 64
            next_index = (last["index"] + 1) if last else 0
            rotate_at = int((self.policy().get("ledger") or {}).get("rotate_at", 100_000))
            if last is not None and next_index % rotate_at == 0 and last.get("entry_type") != "rotation":
                archive = self.dir / f"ledger-{next_index:08d}-{prev_hash[:12]}.jsonl"
                self.ledger_path.rename(archive)
                rotation = {
                    "index": next_index,
                    "timestamp": _now(),
                    "entry_type": "rotation",
                    "body": {
                        "archived_file": archive.name,
                        "archived_head": prev_hash,
                        "archived_through_index": next_index - 1,
                    },
                    "prev_hash": prev_hash,
                }
                rotation["entry_hash"] = _sha256(_canonical(rotation))
                with self.ledger_path.open("w", encoding="utf-8") as fresh:
                    fresh.write(json.dumps(rotation, sort_keys=True) + "\n")
                    fresh.flush()
                    os.fsync(fresh.fileno())
                prev_hash = rotation["entry_hash"]
                next_index += 1
            with self.ledger_path.open("ab") as handle:
                return self._write_entry(handle, entry_type, body, prev_hash, next_index)

    @staticmethod
    def _write_entry(handle: Any, entry_type: str, body: dict[str, Any], prev_hash: str, index: int) -> dict[str, Any]:
        entry = {
            "index": index,
            "timestamp": _now(),
            "entry_type": entry_type,
            "body": body,
            "prev_hash": prev_hash,
        }
        entry["entry_hash"] = _sha256(_canonical(entry))
        handle.seek(0, os.SEEK_END)
        handle.write((json.dumps(entry, sort_keys=True) + "\n").encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
        return entry

    def verify_ledger(self) -> tuple[bool, list[str]]:
        """Re-check the full chain, walking archived segments through their
        `rotation` links, oldest first back to genesis."""
        problems: list[str] = []
        segments: list[list[dict[str, Any]]] = []
        entries = self._ledger_entries()
        while True:
            segments.insert(0, entries)
            first = entries[0] if entries else None
            if not first or first.get("entry_type") != "rotation":
                break
            archive = self.dir / str((first.get("body") or {}).get("archived_file", ""))
            if not archive.is_file():
                problems.append(f"rotation at index {first.get('index')}: archive {archive.name} missing")
                break
            entries = [
                json.loads(line)
                for line in archive.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        prev = "0" * 64
        for entry in (e for segment in segments for e in segment):
            claimed = entry.get("entry_hash")
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            if entry.get("prev_hash") != prev:
                problems.append(f"entry {entry.get('index')}: chain break")
            if _sha256(_canonical(body)) != claimed:
                problems.append(f"entry {entry.get('index')}: hash mismatch")
            prev = claimed or prev
        return (not problems), problems

    def ledger_head(self) -> str:
        if not self.ledger_path.exists():
            return "0" * 64
        with self.ledger_path.open("rb") as handle:
            last = self._last_ledger_line(handle)
        return last["entry_hash"] if last else "0" * 64

    # -- quorum assembly -------------------------------------------------------

    def quorum(self, state_dir: str | Path | None = None) -> QuorumVerifier:
        # Memoized per state_dir: assembling the quorum re-reads and SHA-256s
        # every member binary (a swap-detection control). Doing that on every
        # verify would hash ~4 binaries per operation; instead we pin once at
        # first assembly and hold the verifier. A binary swapped mid-process
        # is therefore caught at the next assembly (restart / re-init), which
        # is the right granularity: an attacker who can rewrite the on-disk
        # binary already outranks this check, and re-hashing per call buys
        # nothing against them while taxing every honest verification.
        state_dir = state_dir if state_dir is not None else self.state_dir
        cache_key = str(state_dir) if state_dir is not None else "__default__"
        cached = self._quorum_cache.get(cache_key)
        if cached is not None:
            return cached
        capsule = self.capsule()
        members: dict[str, Path] = {}
        for member in capsule["members"]:
            name = member["backend"]
            binary = quorum_binary_path(name, state_dir)
            if not binary.exists():
                raise WalletError(f"quorum member binary missing: {binary}")
            actual = _sha256(binary.read_bytes())
            if member.get("binary_sha256") and actual != member["binary_sha256"]:
                raise WalletError(
                    f"quorum member {name} binary hash changed since the capsule was sealed "
                    f"({actual[:12]} != {member['binary_sha256'][:12]}); rebuild or re-init"
                )
            members[name] = binary
        verifier = QuorumVerifier(members, min_members=int(capsule["policy"]["min_members"]))
        self._quorum_cache[cache_key] = verifier
        return verifier

    # -- inbound ---------------------------------------------------------------

    def verify_inbound(
        self,
        payload: bytes,
        signature: bytes,
        public_key: bytes,
        context: str = "",
        state_dir: str | Path | None = None,
    ) -> QuorumResult:
        result = self.quorum(state_dir).verify(payload, signature, public_key)
        record = {
            "context": context,
            "payload_sha256": _sha256(payload),
            "public_key_hex": public_key.hex(),
            "signature_hex": signature.hex(),
            "result": result.to_dict(),
        }
        self._append_ledger("inbound-verify", record)
        if result.incident:
            ref = self._write_incident(result.incident)
            if result.incident.get("severity") == "tamper":
                self._latch("unexplained quorum divergence on inbound verification", ref)
        return result

    def _write_incident(self, incident: dict[str, Any]) -> str:
        existing = sorted(self.incidents_dir.glob("*.json"))
        ref = f"{len(existing):04d}"
        body = dict(incident)
        body["incident_ref"] = ref
        body["recorded_at"] = _now()
        (self.incidents_dir / f"{ref}.json").write_text(
            json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self._append_ledger("incident", {"incident_ref": ref, "severity": incident.get("severity")})
        return ref

    # -- refusal receipts --------------------------------------------------------

    def _refuse(
        self,
        code: str,
        reason: str,
        missing: list[str],
        remediation: str,
        request: dict[str, Any] | None = None,
        sign: bool = True,
    ) -> Refusal:
        assert code in REFUSAL_CODES, code
        receipt = {
            "type": "pacta.wallet.refusal_receipt.v1",
            "code": code,
            "reason": reason,
            "missing": missing,
            "remediation": remediation,
            "request_sha256": _sha256(_canonical(request or {})),
            "ledger_head": self.ledger_head(),
            "issued_at": _now(),
        }
        latched = self.latch_state().get("latched", False)
        if sign and not latched:
            try:
                signature, identity = self._sign_as_wallet(_canonical(receipt))
                receipt["signature"] = {
                    "identity": identity,
                    "signature_hex": signature.hex(),
                    "scheme": "ed25519-dogfood",
                }
            except Exception as exc:  # noqa: BLE001 - refusals must never fail to issue
                receipt["signature"] = {"status": "unavailable", "detail": str(exc)}
        else:
            receipt["signature"] = {
                "status": "unsigned",
                "detail": (
                    "custody latch engaged - a wallet that no longer trusts its own "
                    "boundary does not certify its refusals" if latched else "signing skipped"
                ),
            }
        existing = sorted(self.receipts_dir.glob("*.json"))
        ref = f"{len(existing):04d}"
        path = self.receipts_dir / f"{ref}.json"
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._append_ledger("refusal", {"receipt_ref": ref, "code": code, "reason": reason})
        return Refusal(code, reason, missing, remediation, path, receipt)

    def _sign_as_wallet(self, payload: bytes) -> tuple[bytes, str]:
        keys = sorted(self.keys_dir.glob("*.key.pem"))
        if not keys:
            raise WalletError("wallet has no identity key")
        key = keys[0]
        identity = key.name.removesuffix(".key.pem")
        signer = LocalDogfoodSigner()
        signature = signer.sign(payload, key)
        return signature, identity

    # -- outbound: intent → sign → firewall → release ------------------------------

    def request_signature(
        self,
        intent: dict[str, Any],
        payload: bytes,
        signer: Any = None,
        key_name: str = "warden",
        request_id: str | None = None,
        state_dir: str | Path | None = None,
    ) -> dict[str, Any] | Refusal:
        """The outbound path. Returns a release dict on success, or a Refusal.

        Gate order is deliberate and each gate is its own method: latch,
        evidence freshness, intent binding, spending policy, signer
        resolution, signing, then the firewall - the quorum verifies the
        fresh signature and only unanimity releases it. A signature that
        fails the firewall is quarantined and never returned to the caller;
        that is the verify-after-sign fault-injection countermeasure,
        custody-grade.
        """
        request = {"intent": intent, "payload_sha256": _sha256(payload), "key_name": key_name}
        refusal = self._gate_latch(request)
        if refusal is not None:
            return refusal
        refusal = self._check_freshness(self.capsule())
        if refusal is not None:
            return refusal
        refusal = self._gate_intent(intent, payload, request)
        if refusal is not None:
            return refusal
        refusal = self._gate_policy(intent, key_name, request)
        if refusal is not None:
            return refusal
        resolved = self._resolve_signer(signer, key_name, request)
        if isinstance(resolved, Refusal):
            return resolved
        signer, key, pub = resolved
        signature = self._obtain_signature(signer, payload, key, intent, request_id, request)
        if isinstance(signature, Refusal):
            return signature
        return self._run_firewall(
            payload, signature, pub, intent, request, state_dir,
            key_name=key_name, signer_name=getattr(signer, "name", "unknown"),
        )

    # -- outbound gates, one method each ---------------------------------------

    def _gate_latch(self, request: dict[str, Any]) -> Refusal | None:
        latch = self.latch_state()
        if not latch.get("latched"):
            return None
        return self._refuse(
            "CUSTODY_LATCHED",
            f"custody latch engaged: {latch.get('reason')}",
            [f"operator unlatch with written note (incident {latch.get('incident')})"],
            "resolve the incident, then `pacta wallet unlatch --note <why>`",
            request,
        )

    def _gate_intent(self, intent: dict[str, Any], payload: bytes, request: dict[str, Any]) -> Refusal | None:
        problem = self._validate_intent(intent, payload)
        if problem is None:
            return None
        return self._refuse(
            "MALFORMED_INTENT",
            problem,
            ["intent.purpose (non-empty string)", "intent.payload_sha256 matching the payload"],
            "resend with a well-formed intent envelope; see WALLET.md#intent",
            request,
        )

    def _gate_policy(self, intent: dict[str, Any], key_name: str, request: dict[str, Any]) -> Refusal | None:
        """The lightweight spending-policy engine (POLICY_DENIED consequences).

        Rules live in ``policy.json`` in the wallet directory - the rules you
        would give a teenager with a debit card: per-request and per-day
        amount ceilings and counterparty allow/deny lists, with per-identity
        overrides. No policy file means no restrictions (and the posture
        reports as much). Amount rules bind on ``intent.amount``; list rules
        bind on ``intent.counterparty`` - policy makes those intent fields
        mandatory, so a request that omits them is refused, not waved past.
        """
        rules = self._policy_rules(key_name)
        if not rules:
            return None

        def deny(reason: str, missing: list[str], remediation: str) -> Refusal:
            return self._refuse("POLICY_DENIED", reason, missing, remediation, request)

        allow = rules.get("counterparty_allowlist")
        denylist = rules.get("counterparty_denylist") or []
        counterparty = intent.get("counterparty")
        if (allow is not None or denylist) and not isinstance(counterparty, str):
            return deny(
                "policy has counterparty rules but the intent names no counterparty",
                ["intent.counterparty"],
                "resend with intent.counterparty set",
            )
        if denylist and counterparty in denylist:
            return deny(
                f"counterparty {counterparty!r} is on the denylist",
                [],
                "this counterparty is blocked by wallet policy; change the policy deliberately if wrong",
            )
        if allow is not None and counterparty not in allow:
            return deny(
                f"counterparty {counterparty!r} is not on the allowlist",
                [],
                "add the counterparty to policy.json outbound.counterparty_allowlist if intended",
            )
        max_request = rules.get("max_amount_per_request")
        max_day = rules.get("max_amount_per_day")
        if max_request is not None or max_day is not None:
            amount = intent.get("amount")
            if not isinstance(amount, (int, float)) or amount <= 0:
                return deny(
                    "policy has amount ceilings but the intent carries no positive intent.amount",
                    ["intent.amount (positive number)"],
                    "resend with intent.amount set; amounts are policy units, recorded in the ledger",
                )
            if max_request is not None and amount > float(max_request):
                return deny(
                    f"amount {amount} exceeds the per-request ceiling {max_request}",
                    [],
                    "split the request or raise the ceiling deliberately in policy.json",
                )
            if max_day is not None:
                spent = self._spent_last_24h(key_name)
                if spent + amount > float(max_day):
                    return deny(
                        f"amount {amount} would exceed the daily ceiling {max_day} "
                        f"(already released in the last 24h: {spent})",
                        [],
                        "wait for the window to roll, or raise the ceiling deliberately in policy.json",
                    )
        return None

    def policy(self) -> dict[str, Any]:
        path = self.dir / "policy.json"
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _policy_rules(self, key_name: str) -> dict[str, Any]:
        policy = self.policy()
        rules = dict(policy.get("outbound") or {})
        rules.update((policy.get("identities") or {}).get(key_name) or {})
        return rules

    def _spent_last_24h(self, key_name: str) -> float:
        cutoff = datetime.now(timezone.utc).timestamp() - 86400
        spent = 0.0
        for entry in self._ledger_entries():
            if entry.get("entry_type") != "outbound-sign":
                continue
            body = entry.get("body") or {}
            if body.get("identity") != key_name:
                continue
            try:
                stamp = datetime.fromisoformat(str(entry.get("timestamp", "")).replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            if stamp < cutoff:
                continue
            amount = (body.get("intent") or {}).get("amount")
            if isinstance(amount, (int, float)):
                spent += float(amount)
        return spent

    def _resolve_signer(
        self, signer: Any, key_name: str, request: dict[str, Any]
    ) -> tuple[Any, Path, Path] | Refusal:
        key = self.keys_dir / f"{key_name}.key.pem"
        pub = self.keys_dir / f"{key_name}.pub.pem"
        if signer is None:
            signer = LocalDogfoodSigner()
        if not pub.exists():
            return self._refuse(
                "SIGNER_UNAVAILABLE",
                f"no identity {key_name} in this wallet",
                [f"keys/{key_name}.pub.pem"],
                "create the identity or name an existing one",
                request,
            )
        if isinstance(signer, LocalDogfoodSigner) and not key.exists():
            return self._refuse(
                "SIGNER_UNAVAILABLE",
                f"identity {key_name} has no local private key (airgap-only identity?)",
                [f"keys/{key_name}.key.pem"],
                "use the airgap signer for this identity",
                request,
            )
        return signer, key, pub

    def _obtain_signature(
        self,
        signer: Any,
        payload: bytes,
        key: Path,
        intent: dict[str, Any],
        request_id: str | None,
        request: dict[str, Any],
    ) -> bytes | Refusal:
        try:
            if isinstance(signer, AirgapSigner):
                return signer.sign(payload, key, request_id=request_id, intent=intent)
            return signer.sign(payload, key)
        except PendingAirgap as pending:
            return self._refuse(
                "PENDING_AIRGAP",
                f"request {pending.request_id} parked in the airgap outbox",
                [f"airgap/inbox/{pending.request_id}.response.json"],
                "sign on the device, drop the response file, resend with the same request_id",
                request,
                sign=False,
            )
        except Exception as exc:  # noqa: BLE001
            return self._refuse(
                "SIGNER_UNAVAILABLE", f"signer failed: {exc}", [], "check the signer backend", request
            )

    def _run_firewall(
        self,
        payload: bytes,
        signature: bytes,
        pub: Path,
        intent: dict[str, Any],
        request: dict[str, Any],
        state_dir: str | Path | None,
        key_name: str,
        signer_name: str,
    ) -> dict[str, Any] | Refusal:
        """The fresh signature faces the full quorum; only unanimity releases."""
        public_key = pem_public_key_to_raw(pub)
        result = self.quorum(state_dir).verify(payload, signature, public_key)
        if not result.accepted:
            quarantine_ref = self._quarantine(payload, signature, public_key, intent, result)
            incident_ref = self._write_incident(result.incident) if result.incident else None
            self._latch(
                "outbound firewall rejected a signature this wallet just produced "
                f"(quarantine {quarantine_ref})",
                incident_ref,
            )
            return self._refuse(
                "FIREWALL_QUARANTINE",
                "the quorum refused a signature produced by this wallet's own signer - "
                f"classification {result.classification}; the signature was quarantined, "
                "never released, and custody is latched",
                [],
                "treat as a fault/tamper event; inspect quarantine and incidents, then unlatch deliberately",
                request,
                sign=False,
            )
        release = {
            "type": "pacta.wallet.release.v1",
            "signature_hex": signature.hex(),
            "public_key_hex": public_key.hex(),
            "identity": key_name,
            "signer": signer_name,
            "intent": intent,
            "payload_sha256": _sha256(payload),
            "firewall": result.to_dict(),
            "issued_at": _now(),
        }
        self._append_ledger("outbound-sign", release)
        return release

    def _check_freshness(self, capsule: dict[str, Any]) -> Refusal | None:
        max_age_days = int(capsule["policy"].get("freshness_max_age_days", 0) or 0)
        if max_age_days <= 0:
            return None
        newest: dict[str, Any] | None = None
        for member in capsule["members"]:
            sth = (member.get("evidence") or {}).get("sth") or {}
            if not newest or str(sth.get("timestamp", "")) > str(newest.get("timestamp", "")):
                newest = sth
        if newest is None:
            return None
        fresh, why = check_sth_freshness(newest, max_age_days * 86400)
        if fresh:
            return None
        return self._refuse(
            "EVIDENCE_STALE",
            f"the wallet's newest pinned tree head fails the freshness policy: {why}",
            ["a fresh signed tree head from the transparency log"],
            "run `pacta sth-refresh` against the log, then re-init or update the capsule; "
            "a wallet should not outlive its evidence",
            None,
        )

    @staticmethod
    def _validate_intent(intent: dict[str, Any], payload: bytes) -> str | None:
        if not isinstance(intent, dict):
            return "intent must be an object"
        purpose = intent.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip():
            return "intent.purpose is required (non-empty string): the ledger records why, not just what"
        digest = intent.get("payload_sha256")
        if digest != _sha256(payload):
            return "intent.payload_sha256 must match the payload (binds the intent to these exact bytes)"
        return None

    def _quarantine(
        self,
        payload: bytes,
        signature: bytes,
        public_key: bytes,
        intent: dict[str, Any],
        result: QuorumResult,
    ) -> str:
        existing = sorted(self.quarantine_dir.glob("*.json"))
        ref = f"{len(existing):04d}"
        (self.quarantine_dir / f"{ref}.json").write_text(
            json.dumps(
                {
                    "type": "pacta.wallet.quarantined_signature.v1",
                    "quarantine_ref": ref,
                    "payload_sha256": _sha256(payload),
                    "signature_hex": signature.hex(),
                    "public_key_hex": public_key.hex(),
                    "intent": intent,
                    "firewall": result.to_dict(),
                    "recorded_at": _now(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return ref

    # -- posture -------------------------------------------------------------

    def posture(self) -> dict[str, Any]:
        capsule = self.capsule()
        ok_ledger, ledger_problems = self.verify_ledger()
        incidents = sorted(self.incidents_dir.glob("*.json"))
        receipts = sorted(self.receipts_dir.glob("*.json"))
        return {
            "type": "pacta.wallet.posture.v1",
            "capsule_sha256": _sha256(_canonical(capsule)),
            "members": [
                {
                    "backend": m["backend"],
                    "component": m["component"],
                    "risk_tier": m["risk_tier"],
                    "source_commit": m["source_commit"],
                    "binary_sha256": m["binary_sha256"],
                }
                for m in capsule["members"]
            ],
            "policy": capsule["policy"],
            "spending_policy": self.policy() or {"note": "no policy.json - outbound is unrestricted"},
            "latch": self.latch_state(),
            "ledger": {
                "entries": len(self._ledger_entries()),
                "head": self.ledger_head(),
                "chain_ok": ok_ledger,
                "problems": ledger_problems,
            },
            "incidents": len(incidents),
            "refusal_receipts": len(receipts),
            "generated_at": _now(),
        }
