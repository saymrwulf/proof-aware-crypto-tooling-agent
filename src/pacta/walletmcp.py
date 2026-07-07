"""warden's Model Context Protocol surface - the agent-native front door.

A dependency-free MCP server over stdio JSON-RPC 2.0. It follows the AX
canon distilled in docs/agent-native.md: outcome-first tools, strict
input schemas, and results that carry their own evidence so a calling
agent never has to trust an adjective. Errors are structured objects
(``code`` / ``missing`` / ``remediation``), not prose - a refused agent
gets a machine-actionable receipt it can hand its principal.

This is intentionally tiny and stdlib-only: an agent should be able to
read the whole trust surface in one sitting. It speaks enough of MCP
(``initialize``, ``tools/list``, ``tools/call``) to be driven by any MCP
client, and degrades to a plain JSON-RPC endpoint for scripts.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any, Callable

from .custodycard import build_custody_card, posture_challenge
from .wallet import Refusal, Wallet

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "warden", "version": "1.0.0"}


def _b64_to_bytes(field: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise _ToolError("MALFORMED_INTENT", f"{field} must be base64 string", [field], "send base64")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise _ToolError("MALFORMED_INTENT", f"{field} is not valid base64: {exc}", [field], "re-encode as base64")


class _ToolError(Exception):
    def __init__(
        self,
        code: str,
        reason: str,
        missing: list[str],
        remediation: str,
        receipt: dict[str, Any] | None = None,
        receipt_path: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.payload = {"code": code, "reason": reason, "missing": missing, "remediation": remediation}
        if receipt is not None:
            # The signed refusal receipt travels WITH the error: the refused
            # agent can hand its principal a provable, stamped "the wallet
            # said no, and this is why" instead of an unsigned anecdote.
            self.payload["receipt"] = receipt
            self.payload["receipt_path"] = receipt_path


def _refusal_error(refusal: Any) -> _ToolError:
    return _ToolError(
        refusal.code,
        refusal.reason,
        refusal.missing,
        refusal.remediation,
        receipt=refusal.receipt,
        receipt_path=str(refusal.receipt_path) if refusal.receipt_path else None,
    )


class _RateLimiter:
    """Sliding-window throttle per tool class. Liveness reads are cheap and
    generous; custody mutations are scarce on purpose. Limits exist so a
    hostile counterparty cannot grind the ledger or the signer; they are a
    surface control, not a custody event - refusals here are NOT ledgered."""

    WINDOW = 60.0
    LIMITS = {"custody": 30, "verify": 120, "liveness": 240}

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}

    def check(self, category: str) -> None:
        import time

        now = time.monotonic()
        hits = self._hits.setdefault(category, [])
        cutoff = now - self.WINDOW
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= self.LIMITS[category]:
            raise _ToolError(
                "RATE_LIMITED",
                f"{category} budget exhausted ({self.LIMITS[category]} calls / {int(self.WINDOW)}s)",
                [],
                "back off and retry after the window rolls; liveness reads have a higher budget than custody calls",
            )
        hits.append(now)


_TOOL_CATEGORY = {
    "request_signature": "custody",
    "verify_inbound": "verify",
    "posture_challenge": "custody",   # it produces a firewalled signature
    "wallet_status": "liveness",
    "custody_card": "liveness",
    "list_incidents": "liveness",
    "explain_refusal": "liveness",
    "airgap_pending": "liveness",
}


TOOLS: list[dict[str, Any]] = [
    {
        "name": "wallet_status",
        "description": "Custody posture: quorum members and tiers, latch state, ledger head and chain integrity, incident and refusal counts. Read this first.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "verify_inbound",
        "description": "Run the quorum on an inbound (payload, signature, public_key). Acceptance requires unanimity of the proven verifiers; divergence is classified and, if unexplained, latches custody. All inputs base64.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload_b64": {"type": "string", "description": "message bytes, base64"},
                "signature_b64": {"type": "string", "description": "64-byte Ed25519 signature, base64"},
                "public_key_b64": {"type": "string", "description": "32-byte raw Ed25519 public key, base64"},
                "context": {"type": "string", "description": "free-text label recorded in the ledger"},
            },
            "required": ["payload_b64", "signature_b64", "public_key_b64"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "request_signature",
        "description": "Outbound signing with intent binding, spending policy, and the quorum firewall. Provide intent.purpose (recorded as WHY) and the payload; amount/counterparty feed the policy engine when rules exist; signer 'airgap' parks the request for the gap device (resend with the returned request_id after the device answers). The produced signature is quorum-verified before release and quarantined if it fails.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload_b64": {"type": "string", "description": "message bytes to sign, base64"},
                "purpose": {"type": "string", "description": "why this signature is requested (recorded in the ledger)"},
                "identity": {"type": "string", "description": "wallet identity name (default: warden)"},
                "amount": {"type": "number", "description": "policy units for spending rules (required when the policy has amount ceilings)"},
                "counterparty": {"type": "string", "description": "who this benefits (required when the policy has counterparty lists)"},
                "signer": {"type": "string", "enum": ["local", "airgap"], "description": "signing backend (default local)"},
                "request_id": {"type": "string", "description": "airgap request id when completing a parked request"},
            },
            "required": ["payload_b64", "purpose"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    },
    {
        "name": "airgap_pending",
        "description": "List parked airgap signing requests (outbox) and whether the device has answered (inbox). Use the request_id with request_signature to complete one.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "custody_card",
        "description": "The self-proving business card: quorum membership with embedded transparency-log inclusion proofs a counterparty can recompute, signing provenance, honesty ledger. No trust required.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "posture_challenge",
        "description": "Proof-of-posture: send a nonce (8..128 chars), receive a signed posture attestation whose signature passed the outbound firewall, with the full quorum trail attached. An auditable heartbeat.",
        "inputSchema": {
            "type": "object",
            "properties": {"nonce": {"type": "string"}},
            "required": ["nonce"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "list_incidents",
        "description": "Quorum divergences and firewall quarantines recorded by this wallet, newest-first, with severities and trails.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "explain_refusal",
        "description": "Fetch a previously issued refusal receipt by index, or the latest. Returns the machine-actionable receipt (code, missing, remediation, signature).",
        "inputSchema": {
            "type": "object",
            "properties": {"index": {"type": "integer", "description": "receipt number; omit for latest"}},
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
]


class WalletMCP:
    def __init__(
        self,
        wallet_dir: str | Path,
        log_url: str = "https://ltl.zkdefi.org",
        state_dir: str | Path | None = None,
    ) -> None:
        self.wallet = Wallet(wallet_dir, state_dir=state_dir)
        self.log_url = log_url
        self.limiter = _RateLimiter()
        self.handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "wallet_status": self._wallet_status,
            "verify_inbound": self._verify_inbound,
            "request_signature": self._request_signature,
            "airgap_pending": self._airgap_pending,
            "custody_card": self._custody_card,
            "posture_challenge": self._posture_challenge,
            "list_incidents": self._list_incidents,
            "explain_refusal": self._explain_refusal,
        }

    # -- tool implementations ------------------------------------------------

    def _wallet_status(self, _: dict[str, Any]) -> dict[str, Any]:
        return self.wallet.posture()

    def _verify_inbound(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = _b64_to_bytes("payload_b64", args.get("payload_b64"))
        signature = _b64_to_bytes("signature_b64", args.get("signature_b64"))
        public_key = _b64_to_bytes("public_key_b64", args.get("public_key_b64"))
        if len(signature) != 64:
            raise _ToolError("MALFORMED_INTENT", "signature must be 64 bytes", ["signature_b64"], "send a 64-byte Ed25519 signature")
        if len(public_key) != 32:
            raise _ToolError("MALFORMED_INTENT", "public key must be 32 bytes", ["public_key_b64"], "send a 32-byte raw Ed25519 key")
        result = self.wallet.verify_inbound(payload, signature, public_key, context=str(args.get("context", "")))
        return result.to_dict()

    def _request_signature(self, args: dict[str, Any]) -> dict[str, Any]:
        import hashlib

        payload = _b64_to_bytes("payload_b64", args.get("payload_b64"))
        purpose = args.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip():
            raise _ToolError("MALFORMED_INTENT", "purpose is required", ["purpose"], "state why the signature is requested")
        intent: dict[str, Any] = {"purpose": purpose, "payload_sha256": hashlib.sha256(payload).hexdigest()}
        if args.get("amount") is not None:
            intent["amount"] = args["amount"]
        if args.get("counterparty") is not None:
            intent["counterparty"] = args["counterparty"]
        signer = None
        if args.get("signer") == "airgap":
            from .wallet import AirgapSigner

            signer = AirgapSigner(self.wallet.airgap_dir)
        result = self.wallet.request_signature(
            intent,
            payload,
            signer=signer,
            key_name=str(args.get("identity", "warden")),
            request_id=args.get("request_id"),
        )
        if isinstance(result, Refusal):
            raise _refusal_error(result)
        return result

    def _airgap_pending(self, _: dict[str, Any]) -> dict[str, Any]:
        pending = []
        outbox = self.wallet.airgap_dir / "outbox"
        inbox = self.wallet.airgap_dir / "inbox"
        for req in sorted(outbox.glob("*.request.json")):
            request_id = req.name.removesuffix(".request.json")
            body = json.loads(req.read_text(encoding="utf-8"))
            pending.append({
                "request_id": request_id,
                "created_at": body.get("created_at"),
                "payload_sha256": body.get("payload_sha256"),
                "intent": body.get("intent"),
                "device_answered": (inbox / f"{request_id}.response.json").exists(),
            })
        return {"pending": pending, "count": len(pending)}

    def _custody_card(self, _: dict[str, Any]) -> dict[str, Any]:
        return build_custody_card(self.wallet, self.log_url)

    def _posture_challenge(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = posture_challenge(self.wallet, str(args.get("nonce", "")))
        except ValueError as exc:
            raise _ToolError("MALFORMED_INTENT", str(exc), ["nonce"], "send an 8..128 character nonce")
        if isinstance(result, Refusal):
            raise _refusal_error(result)
        return result

    def _list_incidents(self, _: dict[str, Any]) -> dict[str, Any]:
        incidents = []
        for path in sorted(self.wallet.incidents_dir.glob("*.json"), reverse=True):
            incidents.append(json.loads(path.read_text(encoding="utf-8")))
        return {"incidents": incidents, "count": len(incidents)}

    def _explain_refusal(self, args: dict[str, Any]) -> dict[str, Any]:
        receipts = sorted(self.wallet.receipts_dir.glob("*.json"))
        if not receipts:
            raise _ToolError("EVIDENCE_REQUIRED", "no refusal receipts issued yet", [], "there is nothing to explain")
        idx = args.get("index")
        if idx is None:
            path = receipts[-1]
        else:
            match = [p for p in receipts if p.stem == f"{int(idx):04d}"]
            if not match:
                raise _ToolError("EVIDENCE_REQUIRED", f"no receipt {idx}", [], f"valid indices 0..{len(receipts)-1}")
            path = match[0]
        return json.loads(path.read_text(encoding="utf-8"))

    # -- JSON-RPC plumbing ---------------------------------------------------

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        msg_id = message.get("id")
        if method == "initialize":
            return self._ok(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            })
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "tools/list":
            return self._ok(msg_id, {"tools": TOOLS})
        if method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            handler = self.handlers.get(name)
            if handler is None:
                return self._err(msg_id, -32602, f"unknown tool {name}")
            try:
                self.limiter.check(_TOOL_CATEGORY.get(name, "custody"))
                payload = handler(args)
                return self._ok(msg_id, {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}],
                    "structuredContent": payload,
                    "isError": False,
                })
            except _ToolError as exc:
                return self._ok(msg_id, {
                    "content": [{"type": "text", "text": json.dumps(exc.payload, indent=2, sort_keys=True)}],
                    "structuredContent": exc.payload,
                    "isError": True,
                })
            except Exception as exc:  # noqa: BLE001 - never crash the server
                err = {"code": "INTERNAL", "reason": f"{type(exc).__name__}: {exc}", "missing": [], "remediation": "inspect the wallet directory"}
                return self._ok(msg_id, {
                    "content": [{"type": "text", "text": json.dumps(err, indent=2, sort_keys=True)}],
                    "structuredContent": err,
                    "isError": True,
                })
        if msg_id is None:
            return None
        return self._err(msg_id, -32601, f"method not found: {method}")

    @staticmethod
    def _ok(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _err(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def serve_stdio(self, stdin: Any = None, stdout: Any = None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = self.handle(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()
