"""liveness - the Operator station's board: is everything that should be
running actually running?

Probes are READ-ONLY observations (HTTP GET on the public services, `git`
queries on local working copies) and run ONLY when the operator presses
«Probe now» - the cockpit never phones home on an ordinary page load.
Nothing here touches wallet state; the byte-level read-only guarantee in
tests/test_walletui.py covers the probe route too.

Each probe answers exactly one question - reachable? present? - and shows
the observed facts (status, head, latency). Whether the observed facts
are HONEST is a different station's job (the Cryptographer replays; this
board only watches pulses).
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .uikit import esc, explain, provenance

_TIMEOUT = 4  # seconds per probe; the board is on-demand, not a pager

# (label, url, expectation as stated on the estate map)
SERVICES: list[tuple[str, str, str]] = [
    ("log head", "https://ltl.zkdefi.org/v1/sth", "ALWAYS ON (provider, read-only)"),
    ("paper", "https://ltl.zkdefi.org/paper", "ALWAYS ON (static, behind caddy)"),
    ("blog", "https://blog.zkdefi.org", "ALWAYS ON (static, behind caddy)"),
    ("public mirror (Forgejo)", "https://zkdefi.org", "ALWAYS ON"),
]

# local working copies expected as siblings of this repo checkout
LOCAL_REPOS: list[str] = [
    "lean-transparency-log",
    "ltl-accumulator-verified",
    "verifying-crypto-with-lean",
    "dalek-ed25519-verified",
    "anza-ed25519-verified",
    "risc0-ed25519-verified",
    "betrusted-ed25519-verified",
    "pasta-pallas-verified",
    "proof-aware-crypto-tooling-agent",
]


def default_repos_root() -> Path:
    """Siblings of this repo checkout (…/FormalVerification)."""
    return Path(__file__).resolve().parents[3]


def _probe_service(label: str, url: str, expect: str) -> dict[str, Any]:
    start = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            body = resp.read()
            status = resp.status
        ms = int((time.monotonic() - start) * 1000)
        fact = f"HTTP {status}"
        if label == "log head":
            try:
                sth = json.loads(body)
                fact = (f"HTTP {status} · tree_size {sth.get('tree_size')} · "
                        f"root {str(sth.get('root_hash', ''))[:8]}…")
            except Exception:  # noqa: BLE001 - fact stays the bare status
                pass
        elif label == "paper":
            fact = f"HTTP {status} · sha256 {hashlib.sha256(body).hexdigest()[:8]}… · {len(body)//1024} KiB"
        return {"label": label, "expect": expect, "ok": status == 200,
                "fact": fact, "ms": ms}
    except Exception as error:  # noqa: BLE001 - a dead service is a result, not a crash
        ms = int((time.monotonic() - start) * 1000)
        return {"label": label, "expect": expect, "ok": False,
                "fact": f"UNREACHABLE — {type(error).__name__}: {error}", "ms": ms}


def _probe_repo(root: Path, name: str) -> dict[str, Any]:
    path = root / name
    if not path.is_dir():
        return {"label": name, "expect": "local working copy", "ok": False,
                "fact": f"MISSING — no directory at {path}", "ms": 0}
    start = time.monotonic()
    try:
        head = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10, check=True).stdout
        ms = int((time.monotonic() - start) * 1000)
        n_dirty = len([line for line in dirty.splitlines() if line.strip()])
        if n_dirty:
            return {"label": name, "expect": "local working copy", "ok": True,
                    "warn": True, "fact": f"HEAD {head} · {n_dirty} uncommitted change(s)",
                    "ms": ms}
        return {"label": name, "expect": "local working copy", "ok": True,
                "fact": f"HEAD {head} · clean", "ms": ms}
    except Exception as error:  # noqa: BLE001
        ms = int((time.monotonic() - start) * 1000)
        return {"label": name, "expect": "local working copy", "ok": False,
                "fact": f"NOT READABLE AS GIT — {type(error).__name__}: {error}", "ms": ms}


def collect_liveness(repos_root: Path | None = None) -> dict[str, Any]:
    """Run every probe, in parallel, once — called only on explicit demand."""
    root = repos_root or default_repos_root()
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            services = list(pool.map(lambda s: _probe_service(*s), SERVICES))
            repos = list(pool.map(lambda n: _probe_repo(root, n), LOCAL_REPOS))
        return {"ok": True, "via": "live HTTP GET + git rev-parse/status, on demand",
                "data": {"services": services, "repos": repos, "root": str(root)}}
    except Exception as error:  # noqa: BLE001
        return {"ok": False, "via": "live HTTP GET + git", "error": error}


def _row(p: dict[str, Any]) -> str:
    if p["ok"] and p.get("warn"):
        pill = '<span class="pill warn">alive, dirty</span>'
    elif p["ok"]:
        pill = '<span class="pill ok">alive</span>'
    else:
        pill = '<span class="pill bad">DOWN / MISSING</span>'
    return (f"<tr><td>{esc(p['label'])}</td><td>{pill}</td>"
            f"<td class='mono'>{esc(p['fact'])}</td>"
            f"<td class='muted'>{esc(p['expect'])}</td>"
            f"<td class='mono'>{p['ms']} ms</td></tr>")


def render_liveness(result: dict[str, Any] | None) -> str:
    """The board. result=None means: not probed yet this page load."""
    from .uikit import failed_panel
    if result is None:
        body = (
            "<p class='empty'>This board has not probed yet — probes run only when "
            "you press the button, so the cockpit never phones home on an ordinary "
            "page load. Press «Probe now» to check every service and repo live.</p>"
            "<p><a class='btnlink' href='/station/operator?probe=1'>Probe now</a></p>")
        return (f"<div class='panel'><h3 style='margin-top:0'>Liveness board — what is "
                f"actually running?</h3>{body}"
                + explain(
                    "<ul><li>Service probes are plain HTTP GETs (4-second timeout) "
                    "reporting status, observed facts, and latency.</li>"
                    "<li>Local repos are checked with <code>git rev-parse</code> / "
                    "<code>git status</code>: present, at which commit, clean or "
                    "dirty.</li>"
                    "<li><span class='pill ok'>alive</span> = responded / present · "
                    "<span class='pill warn'>alive, dirty</span> = present with "
                    "uncommitted changes · <span class='pill bad'>DOWN / MISSING</span> "
                    "= no response or not found.</li>"
                    "<li>Liveness is not honesty: this board only checks pulses. "
                    "Whether the answers are cryptographically true is the "
                    "Cryptographer's replay work.</li></ul>")
                + provenance("no probe run this page load (press the button)")
                + "</div>")
    if not result["ok"]:
        return failed_panel("Liveness board", result["via"], result["error"])
    d = result["data"]
    service_rows = "".join(_row(p) for p in d["services"])
    repo_rows = "".join(_row(p) for p in d["repos"])
    down = [p["label"] for p in d["services"] + d["repos"] if not p["ok"]]
    verdict = ('<p class="plain"><span class="pill bad">ATTENTION</span> not alive: '
               + ", ".join(f"<code>{esc(x)}</code>" for x in down) + "</p>"
               if down else
               '<p class="plain"><span class="pill ok">all probed targets alive</span></p>')
    return (
        f"<div class='panel'><h3 style='margin-top:0'>Liveness board — what is "
        f"actually running?</h3>{verdict}"
        "<h3>Public services</h3>"
        f"<div class='tablewrap'><table><tr><th>service</th><th>state</th>"
        f"<th>observed</th><th>expected</th><th>latency</th></tr>{service_rows}</table></div>"
        f"<h3>Local working copies <span class='muted mono breakany'>under {esc(d['root'])}</span></h3>"
        f"<div class='tablewrap'><table><tr><th>repo</th><th>state</th>"
        f"<th>observed</th><th>expected</th><th>took</th></tr>{repo_rows}</table></div>"
        "<p><a class='btnlink' href='/station/operator?probe=1'>Probe again</a></p>"
        + explain(
            "<ul><li>«observed» is what the probe just saw: HTTP status and payload "
            "facts for services, HEAD commit and cleanliness for repos.</li>"
            "<li>«expected» is what the estate map says this target should be — a "
            "target can be alive and still wrong (that is the Cryptographer's "
            "beat).</li>"
            "<li>DOWN on a public service: check your own network first, then the "
            "server. MISSING on a repo: this machine simply has no checkout — clone "
            "it if this machine should hold one.</li></ul>")
        + provenance(result["via"]) + "</div>"
    )
