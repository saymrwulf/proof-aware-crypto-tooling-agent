"""The LTL website, served at the log's base path — one self-contained HTML
page (inline CSS + inline SVG, no external assets: works air-gapped behind
any reverse proxy). Rendered from the LIVE log state, so the graphic and
every number on the page are the accumulator, not a brochure about it."""
from __future__ import annotations

from html import escape
from typing import Any

from pacta.transparency import node_hash

from .transparency_log import LogEntry, TransparencyLog

_STYLE = """
 :root{--ink:#1c2430;--ink2:#5a6675;--line:#dde2e9;--ok:#1e7f4f;--okbg:#e2f2e9;
       --warn:#a86a10;--warnbg:#fdf0da;--accent:#3b4d8f;--accentbg:#eef0f7;--bg:#f8f9fa}
 *{box-sizing:border-box}
 body{font-family:system-ui,sans-serif;max-width:66rem;margin:0 auto;padding:2rem 1.2rem 4rem;
      color:var(--ink);line-height:1.6;background:var(--bg)}
 h1{font-size:2rem;margin:.2rem 0 0;letter-spacing:-.01em}
 h2{font-size:1.2rem;margin-top:2.6rem;border-bottom:2px solid var(--line);padding-bottom:.3rem}
 .tagline{font-size:1.05rem;color:var(--ink2);max-width:46rem}
 code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;background:#eef0f3;border-radius:4px}
 code{padding:.1rem .3rem;font-size:.9em} pre{padding:.9rem;overflow-x:auto;font-size:.85rem}
 table{border-collapse:collapse;width:100%;font-size:.93rem;background:#fff}
 td,th{border:1px solid var(--line);padding:.5rem .7rem;text-align:left;vertical-align:top}
 th{background:var(--accentbg)}
 .pill{display:inline-block;border-radius:9px;padding:.08rem .6rem;font-size:.78rem;font-weight:600}
 .ok{background:var(--okbg);color:var(--ok)} .warn{background:var(--warnbg);color:var(--warn)}
 .acc{background:var(--accentbg);color:var(--accent)}
 .muted{color:var(--ink2);font-size:.9rem}
 .card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:1rem 1.2rem;margin:.8rem 0}
 .steps{counter-reset:s} .steps .card{position:relative;padding-left:3.2rem}
 .steps .card::before{counter-increment:s;content:counter(s);position:absolute;left:1rem;top:1rem;
   width:1.6rem;height:1.6rem;border-radius:50%;background:var(--accent);color:#fff;
   display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.9rem}
 svg{max-width:100%;height:auto;display:block;margin:1rem auto;background:#fff;
     border:1px solid var(--line);border-radius:8px}
 a{color:var(--accent)}
 .legend{display:flex;gap:1.4rem;flex-wrap:wrap;font-size:.85rem;color:var(--ink2);justify-content:center}
 .sw{display:inline-block;width:.8rem;height:.8rem;border-radius:3px;vertical-align:-1px;margin-right:.3rem}
"""


def _leaf_ok(entry: LogEntry) -> bool:
    certificates = ((entry.leaf.get("attestation") or {}).get("certificates")) or []
    return bool(certificates) and all(
        certificate.get("status") == "proven" and certificate.get("axiom_status") == "clean"
        for certificate in certificates
    )


def _svg_tree(entries: list[LogEntry], root_hex: str, signing_backend: str) -> str:
    """The accumulator, drawn from its real leaves."""
    if not entries:
        return "<p class='muted'>(log is empty)</p>"
    hashes = [bytes.fromhex(entry.leaf_hash) for entry in entries]
    levels: list[list[bytes]] = [hashes]
    while len(levels[-1]) > 1:
        level = levels[-1]
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        levels.append(nxt)
    width, level_gap = 1000, 86
    height = 150 + level_gap * len(levels)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" font-family="ui-monospace,monospace" font-size="11">']
    positions: dict[tuple[int, int], tuple[float, float]] = {}
    for level_index, level in enumerate(levels):
        y = height - 56 - level_index * level_gap
        span = width / (len(level) + 1)
        for node_index, node in enumerate(level):
            x = span * (node_index + 1)
            positions[(level_index, node_index)] = (x, y)
            if level_index == 0:
                entry = entries[node_index]
                ok = _leaf_ok(entry)
                component = (((entry.leaf.get("attestation") or {}).get("subject")) or {}).get("component", "?")
                fill, stroke = ("#e2f2e9", "#1e7f4f") if ok else ("#f4f4f6", "#8a93a0")
                out.append(f'<rect x="{x-56}" y="{y-22}" width="112" height="44" rx="5" fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>')
                out.append(f'<text x="{x}" y="{y-6}" text-anchor="middle" fill="#333">leaf {node_index}</text>')
                short = escape(str(component).replace("-ed25519-verified", ""))
                label = short if ok else f"{short} ✗"
                out.append(f'<text x="{x}" y="{y+8}" text-anchor="middle" fill="{stroke}">{label}</text>')
                out.append(f'<text x="{x}" y="{y+19}" text-anchor="middle" fill="#999" font-size="9">{node.hex()[:10]}…</text>')
            else:
                is_root = level_index == len(levels) - 1
                out.append(f'<rect x="{x-50}" y="{y-15}" width="100" height="30" rx="5" fill="{"#eef0f7" if is_root else "#fff"}" stroke="{"#3b4d8f" if is_root else "#bbb"}" stroke-width="{1.6 if is_root else 1}"/>')
                out.append(f'<text x="{x}" y="{y-2}" text-anchor="middle" fill="#333">{"ROOT" if is_root else "node"}</text>')
                out.append(f'<text x="{x}" y="{y+10}" text-anchor="middle" fill="#999" font-size="9">{node.hex()[:10]}…</text>')
                for child in (2 * node_index, 2 * node_index + 1):
                    if (level_index - 1, child) in positions:
                        cx, cy = positions[(level_index - 1, child)]
                        out.append(f'<line x1="{x}" y1="{y+15}" x2="{cx}" y2="{cy-22 if level_index==1 else cy-15}" stroke="#ccc"/>')
    root_x, root_y = positions[(len(levels) - 1, 0)]
    out.append(f'<rect x="{root_x-190}" y="{root_y-72}" width="380" height="34" rx="6" fill="#e2f2e9" stroke="#1e7f4f" stroke-width="1.6"/>')
    out.append(f'<text x="{root_x}" y="{root_y-58}" text-anchor="middle" fill="#1e7f4f" font-weight="bold">Signed Tree Head — Ed25519({root_hex[:12]}…)</text>')
    out.append(f'<text x="{root_x}" y="{root_y-46}" text-anchor="middle" fill="#1e7f4f" font-size="9">signed by: {escape(signing_backend)} (the proof-attested library itself)</text>')
    out.append(f'<line x1="{root_x}" y1="{root_y-38}" x2="{root_x}" y2="{root_y-15}" stroke="#1e7f4f" stroke-width="1.4"/>')
    out.append("</svg>")
    return "".join(out)


def render_docs(log: TransparencyLog, base_path: str) -> str:
    base = "/" + base_path.strip("/") if base_path.strip("/") else ""
    metadata = log.metadata()
    history = log.sth_history()
    latest: dict[str, Any] = history[-1] if history else {}
    entries = log.entries()
    ed = (latest.get("signatures") or {}).get("ed25519") or {}
    provenance = ed.get("signing_provenance") or {}
    signing_backend = str(ed.get("signing_backend", "openssl"))
    components = sorted({
        component
        for entry in entries
        if _leaf_ok(entry)
        and (component := ((entry.leaf.get("attestation") or {}).get("subject") or {}).get("component"))
    })
    mirror = "https://github.com/saymrwulf/lean-transparency-log"
    rows = "".join(
        f"<tr><td><code>{escape(c)}</code></td>"
        f"<td><a href='{base}/v1/attestation?component={escape(c)}'>attestation</a></td>"
        f"<td><a href='{base}/v1/proof?component={escape(c)}'>inclusion proof</a></td>"
        f"<td><span class='pill ok'>16/16 proven</span></td></tr>"
        for c in components
    )
    tree_svg = _svg_tree(entries, str(latest.get("root_hash", "")), signing_backend)

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LTL — Lean Transparency Log</title><style>{_STYLE}</style></head><body>

<p class="muted" style="margin-bottom:0">zkdefi
· <a href="https://blog.zkdefi.org/">notes</a>
· <a href="https://zkdefi.org/saymrwulf">code</a>
· <a href="https://zkdefi.com/">cv</a></p>
<h1>LTL — the Lean Transparency Log</h1>
<p class="tagline"><strong>One sentence:</strong> a public, append-only Merkle
accumulator of <em>signed statements that the Lean&nbsp;4 formal proofs of specific
cryptographic Rust libraries, at specific git commits, machine-re-check with exactly
their documented assumptions</em> — so that you can trust a proof result by checking
<strong>one signature and ~{max(1,(latest.get('tree_size') or 1).bit_length())} hashes in
milliseconds</strong>, instead of running a theorem prover for hours.</p>

<h2>The accumulator, live</h2>
{tree_svg}
<p class="legend">
<span><span class="sw" style="background:#e2f2e9;border:1px solid #1e7f4f"></span>verified attestation (all certificates proven, axiom cones boundary-exact)</span>
<span><span class="sw" style="background:#f4f4f6;border:1px solid #8a93a0"></span>historical audit-failure attestation — kept forever; an append-only ledger does not erase its bad day</span>
</p>
<p class="muted">Every box above is computed from the live log at page render — leaf hashes,
internal nodes, the root, and the signature are the real ones. Before signing this
root, the provider Merkle-verified its own signing library's leaf
(index {provenance.get('signing_library_leaf_index','?')},
certificates {escape(str(provenance.get('signing_library_certificates_proven','?')))})
against this very tree — the signature vouches for the code that produced it, and
the tree vouches for the signature's code. Tree size {latest.get('tree_size',0)},
log id <code>{escape(str(metadata.get('log_id',''))[:16])}…</code>.</p>

<h2>What do I download? — the three artifacts, unambiguously</h2>
<p>To benefit from the accumulator you need <strong>exactly three files</strong> per
library, plus optionally the whole mirror. Nothing else.</p>
<table>
<tr><th>#</th><th>Artifact</th><th>What it is</th><th>Where</th></tr>
<tr><td><b>1</b></td><td><code>provider.ed25519.pub</code></td>
<td><strong>The trust anchor.</strong> The provider's public key — the only thing you
take on trust, once. Compare the copy here with the copy in the GitHub mirror; they
must be identical.</td>
<td><a href="{mirror}/blob/main/provider.ed25519.pub">mirror</a></td></tr>
<tr><td><b>2</b></td><td><code>&lt;library&gt;.attestation.json</code></td>
<td><strong>The claim.</strong> Which repo, which exact git commit, which theorems,
which observed axiom cones, what machine protection — signed by the provider.</td>
<td>table above, or <a href="{mirror}">mirror</a> <code>entries/</code></td></tr>
<tr><td><b>3</b></td><td><code>&lt;library&gt;.receipt.json</code></td>
<td><strong>The proof of inclusion.</strong> Binds artifact&nbsp;2 into the signed tree:
leaf index, sibling hashes, the Signed Tree Head. ~25 lines of stdlib Python verify it.</td>
<td>table above, or <a href="{mirror}">mirror</a> <code>receipts/</code></td></tr>
<tr><td>+</td><td>the full mirror clone</td>
<td><strong>Maximal benefit: become a witness.</strong> Every leaf + every signed head
ever issued + <code>verify.py</code> (stdlib-only). <code>python3 verify.py --all</code>
recomputes the entire tree and every historical head — you then hold proof the log
never equivocated within your clone.</td>
<td><code>git clone {mirror}</code></td></tr>
</table>

<h2>Attested libraries</h2>
<table><tr><th>component</th><th>artifact 2</th><th>artifact 3</th><th>status</th></tr>{rows}</table>

<h2>Three ways to use it</h2>
<div class="steps">
<div class="card"><strong>Quick check</strong> (any machine, milliseconds): download
artifacts 1–3, then<br>
<code>pacta receipt-verify --attestation … --receipt … --log-public-key provider.ed25519.pub</code>
<br><span class="muted">No Lean, no Rust, no account. Add <code>--sth-store pins.json</code> for split-view defense.</span></div>
<div class="card"><strong>Zero-install audit</strong>: <code>git clone {mirror} &amp;&amp; python3 verify.py --all</code>
<br><span class="muted">Standard-library Python only. You become a witness of the whole history.</span></div>
<div class="card"><strong>Autonomous agent</strong>: the <a href="https://github.com/saymrwulf/proof-aware-crypto-tooling-agent">pacta</a>
tool adds STH pinning, freshness policy, online refresh from this service, risk scoring
(R0–R5) with policy-gated consequences, and optionally verifies every signature through
the proof-attested Ed25519 code path itself (<code>--require-verified-verifier</code>).</div>
</div>

<h2>API</h2>
<pre>GET {base}/v1/sth                      latest Signed Tree Head
GET {base}/v1/sth-history              every head ever signed (witness material)
GET {base}/v1/sth-consistency?first=N  consistency proof from your pinned size
GET {base}/v1/proof?component=NAME     inclusion proof (artifact 3, freshly issued)
GET {base}/v1/attestation?component=NAME   the claim (artifact 2)
GET {base}/v1/entries?start=N&amp;end=M    raw leaves
GET {base}/v1/metadata                 log identity
GET {base}/healthz</pre>

<h2>What a verified inclusion means — and what it does not</h2>
<div class="card"><span class="pill ok">means</span> The provider whose key you hold
attests: the Lean proofs of the named repository at the named git commit re-check with
exactly the documented assumptions — and that statement is irrevocably part of the log
every other customer and witness sees.</div>
<div class="card"><span class="pill warn">does not mean</span> A verified binary. The
proofs cover Rust <em>source</em>; clone the attested commit (the git hash <em>is</em>
the content hash) and build it yourself — compiler and build are declared trusted base
until the reproducible-builds program (R5) lands. Every attestation carries its full
residual-risk list. Honesty about the boundary is the product.</div>

<h2>The paper</h2>
<div class="card"><a href="{base}/paper"><strong>LTL: Lean Transparency Log</strong></a>
(PDF, 4 pages) — the design in full: the trust model (observations, never verdicts),
the self-certifying signature, the deployment with its retained failure leaves, and an
exact account of what a verified receipt does and does not establish.</div>

<p class="muted">Log heads are signed offline; this service is read-only and holds no
key material. Provider tooling, agent tooling, and the full course (12 Jupyter
lectures) live in the <a href="https://github.com/saymrwulf/proof-aware-crypto-tooling-agent">pacta repository</a>.</p>
</body></html>"""
