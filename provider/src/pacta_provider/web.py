"""The online face of the transparency log: a READ-ONLY, zero-dependency
HTTP service exposing CT-style endpoints under a base path (deployed at
ltl.zkdefi.org behind a reverse proxy).

Security posture: this process never loads a private key. Tree heads are
signed OFFLINE by the provider CLI (log-append / log-sth); the service
serves stored, already-signed material. Compromise of the web process can
therefore withhold or replay data (which agents detect via pinning and
freshness policies) but can never forge a signature.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .transparency_log import TransparencyLog

API_VERSION = "v1"


def make_handler(log: TransparencyLog, base_path: str, docs_html: str, paper_pdf: bytes | None = None):
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
            elif route in ("/paper", "/paper/ltl.pdf"):
                if paper_pdf is None:
                    self._send(404, {"error": "paper not available on this deployment"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", 'inline; filename="ltl.pdf"')
                self.send_header("Content-Length", str(len(paper_pdf)))
                self.end_headers()
                self.wfile.write(paper_pdf)
            elif route == "/log-public-key":
                # TOFU mitigation depends on the key being published in two
                # independent locations; this is the site's copy (the mirror
                # carries the other). Serving only a fingerprint would not do.
                key_path = Path(log.log_dir) / "provider.ed25519.pub"
                if not key_path.is_file():
                    self._send(404, {"error": "log public key not present in this log directory"})
                    return
                body = key_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
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
            elif self._serve_site_document(route, log):
                pass  # operator-dropped document; checked LAST so it can never shadow an API route
            else:
                self._send(404, {
                    "error": "unknown endpoint",
                    "endpoints": [
                        f"{base}/docs",
                        f"{base}/paper",
                        f"{base}/log-public-key",
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

        def _serve_site_document(self, route: str, log_obj: TransparencyLog) -> bool:
            """Serve operator-dropped PDFs from ``<log>/site/`` by bare name.

            Deliberately UNLISTED: these documents do not appear in the
            endpoint index or anywhere on the docs page - the operator
            decides who receives a link. The name must be a single plain
            path segment (no traversal); only ``.pdf`` payloads are served.
            Returns True when it handled the request.
            """
            name = route.lstrip("/")
            if not name or not name.replace("-", "").replace("_", "").isalnum():
                return False
            candidate = (log_obj.log_dir / "site" / f"{name}.pdf").resolve()
            site_dir = (log_obj.log_dir / "site").resolve()
            if site_dir not in candidate.parents or not candidate.is_file():
                return False
            body = candidate.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f'inline; filename="{name}.pdf"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Robots-Tag", "noindex, nofollow")
            self.end_headers()
            self.wfile.write(body)
            return True

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
    base_path: str = "",
    host: str = "127.0.0.1",
    port: int = 8461,
    docs_html: str | None = None,
) -> ThreadingHTTPServer:
    log = TransparencyLog(log_dir)
    log.metadata()  # fail fast if the log is not initialized
    if docs_html is None:
        from .webdocs import render_docs

        docs_html = render_docs(log, base_path)
    paper_path = Path(__file__).resolve().parents[3] / "paper" / "ltl.pdf"
    paper_pdf = paper_path.read_bytes() if paper_path.is_file() else None
    handler = make_handler(log, base_path, docs_html, paper_pdf)
    return ThreadingHTTPServer((host, port), handler)
