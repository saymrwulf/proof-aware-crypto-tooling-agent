"""Customer documentation served at the log's base path — self-contained
HTML, no external assets (the service must work air-gapped behind any
reverse proxy)."""
from __future__ import annotations

from html import escape

from .transparency_log import TransparencyLog

_STYLE = """
 body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;
      color:#1c2430;line-height:1.55;background:#f8f9fa}
 h1{font-size:1.6rem} h2{font-size:1.15rem;margin-top:2rem}
 code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;background:#eef0f3;border-radius:4px}
 code{padding:.1rem .3rem} pre{padding:.8rem;overflow-x:auto}
 table{border-collapse:collapse;width:100%;font-size:.92rem}
 td,th{border-bottom:1px solid #dde2e9;padding:.4rem .6rem;text-align:left;vertical-align:top}
 .pill{display:inline-block;background:#e2f2e9;color:#1e7f4f;border-radius:9px;
       padding:.05rem .55rem;font-size:.8rem;font-weight:600}
 .muted{color:#5a6675;font-size:.9rem}
"""


def render_docs(log: TransparencyLog, base_path: str) -> str:
    base = "/" + base_path.strip("/")
    metadata = log.metadata()
    history = log.sth_history()
    latest = history[-1] if history else {}
    entries = log.entries()
    components = sorted({
        component
        for entry in entries
        if (component := ((entry.leaf.get("attestation") or {}).get("subject") or {}).get("component"))
    })
    provenance = ((latest.get("signatures") or {}).get("ed25519") or {}).get("signing_provenance") or {}
    rows = "".join(
        f"<tr><td><code>{escape(component)}</code></td>"
        f"<td><a href='{base}/v1/attestation?component={escape(component)}'>attestation</a></td>"
        f"<td><a href='{base}/v1/proof?component={escape(component)}'>inclusion proof</a></td></tr>"
        for component in components
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Lean Transparency Log</title><style>{_STYLE}</style></head><body>
<h1>Lean Transparency Log <span class="pill">read-only</span></h1>
<p>This service publishes <strong>signed attestations of formal (Lean&nbsp;4) proof
verification</strong> for cryptographic Rust libraries, bound into an append-only
RFC&nbsp;9162-style Merkle log. Customers verify a signature and a
&asymp;{max(1, (latest.get('tree_size') or 1).bit_length())}-hash inclusion proof in milliseconds
&mdash; the hours of Lean kernel re-checking happened once, on the provider's side,
under memory-capped guards.</p>

<h2>Current state</h2>
<table>
<tr><th>log id</th><td><code>{escape(str(metadata.get('log_id', ''))[:32])}&hellip;</code></td></tr>
<tr><th>tree size</th><td>{latest.get('tree_size', 0)} leaves</td></tr>
<tr><th>latest root</th><td><code>{escape(str(latest.get('root_hash', ''))[:32])}&hellip;</code></td></tr>
<tr><th>root signed by</th><td><code>{escape(str(((latest.get('signatures') or {}).get('ed25519') or {}).get('signing_backend', 'n/a')))}</code>
 &mdash; the merkleized, proof-attested Ed25519 library itself; before signing, the provider
 Merkle-verified that library's own leaf (index {provenance.get('signing_library_leaf_index', '?')},
 certificates {escape(str(provenance.get('signing_library_certificates_proven', '?')))}) against this very tree</td></tr>
<tr><th>attested components</th><td>{len(components)}</td></tr>
</table>

<h2>Attested libraries</h2>
<table><tr><th>component</th><th>claim document</th><th>proof of inclusion</th></tr>{rows}</table>
<p class="muted">Each attestation names the exact git commit it covers, every certificate
with its observed axiom cone, and the machine-protection used during replay. The log
also retains earlier leaves that honestly record a failed audit run &mdash; an
append-only trust ledger keeps its history.</p>

<h2>API</h2>
<pre>GET {base}/v1/sth                      latest Signed Tree Head
GET {base}/v1/sth-history              every head ever signed (witness material)
GET {base}/v1/sth-consistency?first=N  consistency proof from your pinned size
GET {base}/v1/proof?component=NAME     inclusion proof for the newest attestation
GET {base}/v1/attestation?component=NAME
GET {base}/v1/entries?start=N&amp;end=M
GET {base}/v1/metadata                 log identity
GET {base}/healthz</pre>

<h2>Verify without trusting this site</h2>
<p>Everything is verifiable offline. Clone the mirror repository (published on GitHub
and on this Forgejo), which contains every leaf, every signed tree head, the provider
public key, and a standalone <code>verify.py</code> (Python standard library only,
&asymp;100 lines). It recomputes the entire tree from the leaves, checks every historical
head against its prefix, verifies the signatures, and checks any inclusion proof:</p>
<pre>git clone &lt;mirror-url&gt;/lean-transparency-log
python3 verify.py --all</pre>
<p>For agents: the <code>pacta</code> tool adds pinning (split-view defense),
freshness policy, and the option to verify signatures through the
proof-attested Ed25519 code path itself
(<code>pacta receipt-verify &hellip; --sth-store &hellip; --require-verified-verifier</code>).</p>

<h2>What a verified inclusion means &mdash; and what it does not</h2>
<p><strong>Means:</strong> the provider whose key you hold attests that the Lean proofs
of the named repository at the named commit re-check with exactly the documented
assumptions, and this attestation is irrevocably part of the log everyone sees.</p>
<p><strong>Does not mean:</strong> a verified binary. The proofs cover Rust source;
you clone the attested commit (the git hash <em>is</em> the content hash) and build it
yourself &mdash; compiler and build remain declared trusted base until the R5
program (reproducible builds) lands. Every attestation carries the full residual-risk
list; honesty about the boundary is the product.</p>
</body></html>"""
