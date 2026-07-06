"""The online face of the transparency log: a READ-ONLY, zero-dependency
HTTP service exposing CT-style endpoints under a base path (deployed at
zkdefi.org/lean-transparency-log behind a reverse proxy).

Security posture: this process never loads a private key. Tree heads are
signed OFFLINE by the provider CLI (log-append / log-sth); the service
serves stored, already-signed material. Compromise of the web process can
therefore withhold or replay data (which agents detect via pinning and
freshness policies) but can never forge a signature.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .transparency_log import TransparencyLog

API_VERSION = "v1"


def make_handler(log: TransparencyLog, base_path: str, docs_html: str):
    base = "/" + base_path.strip("/") if base_path.strip("/") else ""

    class Handler(BaseHTTPRequestHandler):
        server_version = "pacta-log/1"

        def do_GET(self) -> None:  # noqa: N802 (stdlib API)
            try:
                self._route()
            except Exception as exc:  # noqa: BLE001 - the service must not die on a bad request
                self._send(500, {"error": f"internal error: {type(exc).__name__}"})

        def _route(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
            if not path.startswith(base):
                self._send(404, {"error": "unknown path", "base_path": base or "/"})
                return
            route = path[len(base):] or "/"

            if route in ("/", "/docs"):
                self._send_html(docs_html)
            elif route == "/healthz":
                self._send(200, {"ok": True, "tree_size": len(log.entries())})
            elif route == f"/{API_VERSION}/metadata":
                self._send(200, log.metadata())
            elif route == f"/{API_VERSION}/sth":
                history = log.sth_history()
                if history:
                    self._send(200, history[-1])
                else:
                    from pacta.yamlio import load_data

                    if log.sth_path.exists():
                        self._send(200, load_data(log.sth_path))
                    else:
                        self._send(404, {"error": "no signed tree head yet"})
            elif route == f"/{API_VERSION}/sth-history":
                self._send(200, {"sth_history": log.sth_history()})
            elif route == f"/{API_VERSION}/sth-consistency":
                first = int(query.get("first", "-1"))
                if first < 0:
                    self._send(400, {"error": "missing or invalid ?first=<old tree size>"})
                    return
                try:
                    self._send(200, log.consistency_from(first))
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
            elif route == f"/{API_VERSION}/proof":
                leaf_hash = query.get("leaf_hash")
                component = query.get("component")
                if component and not leaf_hash:
                    entry = log.newest_entry_for_component(component)
                    leaf_hash = entry.leaf_hash if entry else None
                if not leaf_hash:
                    self._send(400, {"error": "supply ?leaf_hash=<hex> or ?component=<name>"})
                    return
                proof = log.proof_for_leaf_hash(leaf_hash)
                if proof is None:
                    self._send(404, {"error": f"no leaf with hash {leaf_hash}"})
                    return
                self._send(200, proof)
            elif route == f"/{API_VERSION}/attestation":
                component = query.get("component")
                if not component:
                    self._send(400, {"error": "supply ?component=<name>"})
                    return
                entry = log.newest_entry_for_component(component)
                if entry is None:
                    self._send(404, {"error": f"no attestation for component {component}"})
                    return
                self._send(200, {
                    "leaf_index": entry.index,
                    "leaf_hash": entry.leaf_hash,
                    "attestation": entry.leaf.get("attestation"),
                })
            elif route == f"/{API_VERSION}/entries":
                start = int(query.get("start", "0"))
                end = int(query.get("end", str(len(log.entries()))))
                entries = log.entries()[start:end]
                self._send(200, {
                    "entries": [
                        {"index": entry.index, "leaf_hash": entry.leaf_hash, "leaf": entry.leaf}
                        for entry in entries
                    ]
                })
            else:
                self._send(404, {
                    "error": "unknown endpoint",
                    "endpoints": [
                        f"{base}/docs",
                        f"{base}/healthz",
                        f"{base}/{API_VERSION}/metadata",
                        f"{base}/{API_VERSION}/sth",
                        f"{base}/{API_VERSION}/sth-history",
                        f"{base}/{API_VERSION}/sth-consistency?first=N",
                        f"{base}/{API_VERSION}/proof?component=NAME | ?leaf_hash=HEX",
                        f"{base}/{API_VERSION}/attestation?component=NAME",
                        f"{base}/{API_VERSION}/entries?start=N&end=M",
                    ],
                })

        def _send(self, code: int, payload: dict[str, Any], code_if_error: int | None = None) -> None:
            if code_if_error and "error" in payload:
                code = code_if_error
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

    return Handler


def serve(
    log_dir: str,
    base_path: str = "lean-transparency-log",
    host: str = "127.0.0.1",
    port: int = 8461,
    docs_html: str | None = None,
) -> ThreadingHTTPServer:
    log = TransparencyLog(log_dir)
    log.metadata()  # fail fast if the log is not initialized
    if docs_html is None:
        from .webdocs import render_docs

        docs_html = render_docs(log, base_path)
    handler = make_handler(log, base_path, docs_html)
    return ThreadingHTTPServer((host, port), handler)
