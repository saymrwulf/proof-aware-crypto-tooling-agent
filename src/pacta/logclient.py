"""Agent-side client for the online transparency log (zero dependencies).

Everything fetched here is verified LOCALLY afterwards - the client never
extends trust to the transport: signatures, inclusion proofs, pin-store
consistency, and freshness are all checked by the same code paths used for
file-based evidence. HTTPS certificate handling is the standard library's;
the security of the system does not rest on it (a hostile server can only
withhold or replay, which pinning + freshness detect).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = 20


class LogClientError(RuntimeError):
    pass


def _get(base_url: str, path: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", "")
        except Exception:  # noqa: BLE001
            detail = ""
        raise LogClientError(f"{url}: HTTP {exc.code} {detail}".strip()) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise LogClientError(f"{url}: {exc}") from exc


def fetch_sth(base_url: str) -> dict[str, Any]:
    return _get(base_url, "/v1/sth")


def fetch_consistency(base_url: str, first: int) -> dict[str, Any]:
    return _get(base_url, f"/v1/sth-consistency?first={int(first)}")


def fetch_attestation(base_url: str, component: str) -> dict[str, Any]:
    return _get(base_url, f"/v1/attestation?component={urllib.parse.quote(component)}")


def fetch_proof(base_url: str, component: str | None = None, leaf_hash: str | None = None) -> dict[str, Any]:
    if leaf_hash:
        return _get(base_url, f"/v1/proof?leaf_hash={urllib.parse.quote(leaf_hash)}")
    if component:
        return _get(base_url, f"/v1/proof?component={urllib.parse.quote(component)}")
    raise LogClientError("fetch_proof needs component or leaf_hash")


def fetch_evidence(base_url: str, component: str, out_dir: str | Path) -> dict[str, Path]:
    """Download attestation + inclusion proof for a component into out_dir
    (JSON files compatible with every offline pacta flow)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    attestation = fetch_attestation(base_url, component)["attestation"]
    proof = fetch_proof(base_url, component=component)
    attestation_path = out / f"{component}.attestation.json"
    receipt_path = out / f"{component}.receipt.json"
    attestation_path.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"attestation": attestation_path, "receipt": receipt_path}


def refresh_pin(base_url: str, sth_store_path: str | Path, log_public_key_path: str | Path) -> tuple[bool, list[str]]:
    """Fetch the latest STH; verify its signature; advance the local pin
    using an online consistency proof from the pinned size. Fail closed on
    any mismatch - a hostile or broken log cannot move the pin."""
    from .sthstore import check_sth_against_store, load_store
    from .transparency import verify_signed_tree_head

    sth = fetch_sth(base_url)
    ok, diagnostics, _statuses = verify_signed_tree_head(sth, log_public_key_path)
    if not ok:
        return False, ["Fetched STH failed signature verification:"] + diagnostics
    store = load_store(sth_store_path)
    pinned = store["logs"].get(str(sth.get("log_id") or ""))
    proof_hex = None
    if pinned is not None and int(sth.get("tree_size", -1)) > int(pinned["tree_size"]):
        consistency = fetch_consistency(base_url, int(pinned["tree_size"]))
        proof_hex = [str(item) for item in consistency.get("proof") or []]
    result = check_sth_against_store(sth, sth_store_path, consistency_proof_hex=proof_hex)
    return result.ok, result.diagnostics
