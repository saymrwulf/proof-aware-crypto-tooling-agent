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
 code{padding:.1rem .3rem;font-size:.9em;overflow-wrap:anywhere}
 pre{padding:.9rem;overflow-x:auto;font-size:.85rem;max-width:100%}
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


def _leaf_short(component: str) -> str:
    """Compact display name for a leaf box at small spans."""
    return (component.replace("-ed25519-verified", "")
            .replace("ltl-accumulator-verified", "accum")
            .replace("fips205-slhdsa-verified", "slh-dsa"))


def _svg_tree(entries: list[LogEntry], root_hex: str, signing_backend: str, head_label: str = "Ed25519") -> str:
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
                # Boxes must FIT the per-leaf span at any tree size (the
                # 2026-08-16 lesson: fixed 112px boxes shingled at 19
                # leaves). Rich boxes while they fit, compact ones after.
                box_w = min(112.0, span * 0.94)
                compact = box_w < 100
                short = escape(_leaf_short(str(component)))
                label = short if ok else f"{short} ✗"
                if compact:
                    out.append(f'<rect x="{x-box_w/2:.1f}" y="{y-18}" width="{box_w:.1f}" height="36" rx="4" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>')
                    out.append(f'<text x="{x}" y="{y-4}" text-anchor="middle" fill="#333" font-size="8">leaf {node_index}</text>')
                    out.append(f'<text x="{x}" y="{y+9}" text-anchor="middle" fill="{stroke}" font-size="7">{label}</text>')
                else:
                    out.append(f'<rect x="{x-box_w/2:.1f}" y="{y-22}" width="{box_w:.1f}" height="44" rx="5" fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>')
                    out.append(f'<text x="{x}" y="{y-6}" text-anchor="middle" fill="#333">leaf {node_index}</text>')
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
                        leaf_top = 18 if len(entries) > 9 else 22
                        out.append(f'<line x1="{x}" y1="{y+15}" x2="{cx}" y2="{cy-leaf_top if level_index==1 else cy-15}" stroke="#ccc"/>')
    root_x, root_y = positions[(len(levels) - 1, 0)]
    # The head box sizes itself to its longest line (the 2026-08-16
    # lesson: a fixed 380px box let a growing caption spill both sides).
    title = f"Signed Tree Head — {head_label}({root_hex[:12]}…)"
    line2 = f"signed by: {signing_backend}"
    line3 = "(verify path attested; signing itself not proven)"
    head_w = max(len(title) * 7.0, len(line2) * 5.3, len(line3) * 5.3) + 28
    out.append(f'<rect x="{root_x-head_w/2:.1f}" y="{root_y-84}" width="{head_w:.1f}" height="46" rx="6" fill="#e2f2e9" stroke="#1e7f4f" stroke-width="1.6"/>')
    out.append(f'<text x="{root_x}" y="{root_y-70}" text-anchor="middle" fill="#1e7f4f" font-weight="bold">{escape(title)}</text>')
    out.append(f'<text x="{root_x}" y="{root_y-58}" text-anchor="middle" fill="#1e7f4f" font-size="9">{escape(line2)}</text>')
    out.append(f'<text x="{root_x}" y="{root_y-47}" text-anchor="middle" fill="#1e7f4f" font-size="9">{escape(line3)}</text>')
    out.append(f'<line x1="{root_x}" y1="{root_y-38}" x2="{root_x}" y2="{root_y-15}" stroke="#1e7f4f" stroke-width="1.4"/>')
    out.append("</svg>")
    return "".join(out)


def _trust_anchor_html(log: TransparencyLog, metadata: dict[str, Any], base: str, mirror: str) -> str:
    """The provider public key, displayed in full on the front page. The key
    is the one thing a consumer takes on trust, once - hiding it behind a
    path would invert the page's priorities."""
    key_path = log.log_dir / "provider.ed25519.pub"
    fingerprint = str(metadata.get("ed25519_public_key_fingerprint_sha256", ""))
    if not key_path.is_file():
        return (
            '<div class="card"><span class="pill warn">missing</span> This deployment '
            "does not expose its public key in the log directory - fetch it from the "
            f'<a href="{mirror}/blob/main/provider.ed25519.pub">mirror</a> instead.</div>'
        )
    pem = escape(key_path.read_text(encoding="utf-8").strip())
    # The SLH-DSA verification key (additive post-quantum head signature,
    # 2026-08) is published THE SAME WAY: full PEM on the page, raw endpoint,
    # mirror comparison. Heads before tree 14 carry no SLH-DSA signature and
    # verify.py reports them ABSENT — allowed; an append-only log keeps its
    # history.
    slh_path = log.log_dir / "provider.slhdsa.pub"
    if slh_path.is_file():
        import hashlib as _h
        slh_pem = escape(slh_path.read_text(encoding="utf-8").strip())
        slh_fp = _h.sha256(slh_path.read_bytes()).hexdigest()
        slh_block = f"""<hr style="border:none;border-top:1px solid #ddd;margin:.8rem 0">
<p style="margin-top:0"><strong>Key&nbsp;2 — SLH-DSA (FIPS&nbsp;205), post-quantum.</strong> Heads from tree size&nbsp;14 on carry a second signature from this key;
older heads legitimately have none — an append-only log keeps its history. Check it where your
tooling allows (OpenSSL&nbsp;≥&nbsp;3.5). The kind of code that verifies such signatures is itself
a proof subject of this log (leaf&nbsp;18).</p>
<pre style="margin-bottom:.4rem">{slh_pem}</pre>
<p class="muted" style="margin:.2rem 0 0">SHA-256 fingerprint <code>{slh_fp}</code>
&nbsp;·&nbsp; raw: <a href="{base}/log-slhdsa-public-key"><code>{base or ''}/log-slhdsa-public-key</code></a>
&nbsp;·&nbsp; mirror: <a href="{mirror}/blob/main/provider.slhdsa.pub">provider.slhdsa.pub</a></p>"""
    else:
        slh_block = ""
    return f"""<div class="card">
<p style="margin-top:0"><strong>Two keys sign everything in this log.</strong> Neither makes a
claim <em>true</em>; they prove a claim comes from this operator, unchanged. Save your own copy
of both — that is called <em>pinning</em>: from then on you trust only what verifies against
your saved copies. Fetch each key from this page AND from the independently hosted mirror and
compare byte-for-byte; the copies must be identical. (The first fetch is trust-on-first-use;
comparing two independent hosts is what bounds it.)</p>
<p><strong>Key&nbsp;1 — Ed25519, required.</strong> Every signed head and every attestation must
verify against it.</p>
<pre style="margin-bottom:.4rem">{pem}</pre>
<p class="muted" style="margin:.2rem 0 0">SHA-256 fingerprint <code>{escape(fingerprint)}</code>
&nbsp;·&nbsp; raw: <a href="{base}/log-public-key"><code>{base or ''}/log-public-key</code></a>
&nbsp;·&nbsp; <code>curl -s https://ltl.zkdefi.org/log-public-key</code></p>
{slh_block}</div>"""


def render_docs(log: TransparencyLog, base_path: str) -> str:
    base = "/" + base_path.strip("/") if base_path.strip("/") else ""
    metadata = log.metadata()
    history = log.sth_history()
    latest: dict[str, Any] = history[-1] if history else {}
    entries = log.entries()
    ed = (latest.get("signatures") or {}).get("ed25519") or {}
    provenance = ed.get("signing_provenance") or {}
    signing_backend = str(ed.get("signing_backend", "openssl"))
    # newest entry per component, with its real proven/total from the leaf
    newest: dict[str, Any] = {}
    for entry in entries:
        if not _leaf_ok(entry):
            continue
        comp = ((entry.leaf.get("attestation") or {}).get("subject") or {}).get("component")
        if comp:
            newest[comp] = entry
    def _counts(entry) -> str:
        certs = ((entry.leaf.get("attestation") or {}).get("certificates")) or []
        total = len(certs)
        proven = sum(1 for c in certs
                     if c.get("status") == "proven" and c.get("axiom_status") == "clean")
        return f"{proven}/{total} proven"
    components = sorted(newest)
    mirror = "https://github.com/saymrwulf/lean-transparency-log"
    rows = "".join(
        f"<tr><td><code>{escape(c)}</code></td>"
        f"<td><a href='{base}/v1/attestation?component={escape(c)}'>attestation</a></td>"
        f"<td><a href='{base}/v1/proof?component={escape(c)}'>inclusion proof</a></td>"
        f"<td><span class='pill ok'>{escape(_counts(newest[c]))}</span></td></tr>"
        for c in components
    )
    slh_signed = ((latest.get("signatures") or {}).get("slh_dsa") or {}).get("status") == "signed"
    head_label = "Ed25519 + SLH-DSA" if slh_signed else "Ed25519"
    tree_svg = _svg_tree(entries, str(latest.get("root_hash", "")), signing_backend, head_label)

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LTL — Lean Transparency Log</title><style>{_STYLE}</style></head><body>

<p class="muted" style="margin-bottom:0">zkdefi
· <a href="https://blog.zkdefi.org/">notes</a>
· <a href="https://zkdefi.org/saymrwulf">code</a>
· <a href="https://zkdefi.com/">cv</a></p>
<h1>LTL — the Lean Transparency Log</h1>
<p>This site is a <strong>public notary for machine-checked proofs about cryptographic
software</strong>. A proof assistant — <a href="https://lean-lang.org">Lean&nbsp;4</a>, a program
that checks mathematical proofs mechanically — has verified precise statements about the code
that <em>checks signatures</em>: in four widely deployed <strong>Ed25519</strong> libraries, in an
implementation of <strong>SLH-DSA</strong> (FIPS&nbsp;205, the hash-based post-quantum signature
standard), and in <strong>the Merkle-tree machinery of this log itself</strong>. Every completed
proof check is recorded here as a signed, numbered entry that can never be altered or removed —
{len(entries)} entries so far, drawn live further down this page.</p>

<p>Re-checking such proofs yourself takes a toolchain and real compute time. This log gives you
cheaper positions to stand on: in milliseconds you can verify that the operator is permanently
bound to every claim he ever made — and you can escalate, step by step, up to redoing
everything yourself. The ladder below lists every position, cheapest first.</p>

<h2>Choose where you stand — the trust ladder</h2>

<div class="steps">
<div class="card"><strong>Hold a copy of the history.</strong> — anyone; one minute.<br>
You still trust: the content of every claim. You defeat: silent rewriting.<br>
You need: Python&nbsp;3 and the <code>openssl</code> command (preinstalled on most Linux and macOS systems).
<pre>git clone https://github.com/saymrwulf/lean-transparency-log &amp;&amp; cd lean-transparency-log &amp;&amp; python3 verify.py --all</pre>
<span class="muted">This fetches the log&rsquo;s public mirror — a git repository holding every entry
and every signed head ever issued — and re-computes every hash and signature in it. A green
result means the history you now hold is internally consistent and signed. Keep the folder:
if the operator ever shows a different history to anyone else, your copy proves it. A log
that shows different histories to different people (a &ldquo;split view&rdquo;) survives only until
two holders compare.</span></div>

<div class="card"><strong>Check that a claim is real and binding.</strong> — milliseconds.<br>
You still trust: that the operator&rsquo;s recorded observation is honest.<br>
You need: four small files from the tables below — the two public keys, plus one library&rsquo;s
claim file (&ldquo;attestation&rdquo;) and its proof of inclusion (&ldquo;receipt&rdquo;).
<pre>pacta receipt-verify --attestation … --receipt … --log-public-key provider.ed25519.pub --slhdsa-public-key provider.slhdsa.pub</pre>
<span class="muted">Your machine checks the required Ed25519 signature, the second (post-quantum) signature
(needs OpenSSL&nbsp;≥&nbsp;3.5; drop the second flag to skip it), and
~{max(1,(latest.get('tree_size') or 1).bit_length())} hashes — no proof assistant involved.
The <code>pacta</code> tool ships in the
<a href="https://github.com/saymrwulf/proof-aware-crypto-tooling-agent">pacta repository</a>
(<code>pip install .</code> from a clone); about forty lines of ordinary Python do the same
check, and the mirror&rsquo;s <code>verify.py</code> contains exactly that core. Afterwards the
claim — which repository, which exact source version, which theorems, which assumptions —
is bound to the operator&rsquo;s key inside a history he can neither rewrite nor deny.</span></div>

<div class="card"><strong>Judge by your own standards.</strong> — minutes.<br>
Every entry records more than pass/fail: it lists the exact assumptions each proof rests on
(its <em>axiom cone</em>). So you may ignore the operator&rsquo;s verdicts entirely: write down
which assumptions <em>you</em> accept, and have your tooling compare list against list, name
by name. <code>pacta</code> automates the comparison; lecture&nbsp;11 of the Jupyter course (same
repository) teaches it step by step.
<span class="muted">Afterwards every verdict is your verdict — the operator&rsquo;s labels can at
most veto, never grant. The section &ldquo;You hold the ruler&rdquo; below is this rung in full.</span></div>

<div class="card"><strong>Re-run the proof check yourself.</strong> — about 30&nbsp;minutes per library.<br>
You still trust: that the published Lean statements mean what they say.<br>
You need: a Lean&nbsp;4 toolchain (free).
<span class="muted">Every attested repository ships one script, <code>verification/check.sh</code>.
Clone the repository at the exact source version recorded in its log entry and run the script:
the proof assistant re-checks every theorem on your machine and prints every assumption list.
The operator is now out of the loop entirely.</span></div>

<div class="card"><strong>Rebuild everything from source.</strong> — weeks.<br>
What remains trusted: Lean&rsquo;s proof kernel, the Rust-to-Lean translation tools (Charon and
Aeneas), and your compiler — the floor, which we name rather than hide.
<span class="muted">Every repository documents its full path: the pinned upstream Rust code,
the extraction script that regenerates the Lean definitions byte-for-byte, and the theorem
statements to read against the standards themselves (FIPS&nbsp;205, RFC&nbsp;9162, the curve
equations). Reproduce any part; compare with what is published. After this rung you no longer
need this site — that is the point. There is no rung&nbsp;6: even here you trust a kernel, a
compiler, and your hardware.</span></div>
</div>

<h2>Two keys sign this log — pin these keys</h2>
{_trust_anchor_html(log, metadata, base, mirror)}

<h2>The accumulator, live</h2>
<p>The log is a <strong>Merkle tree</strong>: every entry (&ldquo;leaf&rdquo;) is hashed, hashes pair
up level by level, and a single 32-byte root fingerprints the entire history; the operator signs
that root. Changing any past entry would change the root — that is the tamper evidence. This
picture is computed from the live log at page render — the leaf hashes, nodes, root, and
signature are the real ones:</p>
{tree_svg}
<p class="legend">
<span><span class="sw" style="background:#e2f2e9;border:1px solid #1e7f4f"></span>verified attestation (all certificates proven, axiom cones boundary-exact)</span>
<span><span class="sw" style="background:#f4f4f6;border:1px solid #8a93a0"></span>historical audit-failure attestation — kept forever; an append-only ledger does not erase its bad day (leaves&nbsp;0–3: an early audit round that failed; leaves&nbsp;4–7 re-attest the same four libraries cleanly)</span>
</p>
<p class="muted">The library that signs the log is itself an entry in the log — what that entry proves is its <em>verify</em> path (no signing code is proven, here or anywhere) — and it checks its own entry before signing. In detail: before signing this
root, the provider Merkle-verified its own signing library's leaf
(index {provenance.get('signing_library_leaf_index','?')},
certificates {escape(str(provenance.get('signing_library_certificates_proven','?')))})
against this very tree — so the signed tree <em>contains</em> an attestation of the source the
operator reports its signing binary was built from. (An Ed25519 signature cannot by itself prove
which binary generated it; execution provenance is reported, not proven, and the provenance
fields live in the unsigned signature metadata.) Tree size {latest.get('tree_size',0)},
log id <code>{escape(str(metadata.get('log_id',''))[:16])}…</code>.</p>

<h2>What do I download? — the three artifacts, unambiguously</h2>
<p>To benefit from the accumulator you need <strong>exactly three files</strong> per
library, plus optionally the post-quantum key
(<code>provider.slhdsa.pub</code>) and the whole mirror. Nothing else.</p>
<table>
<tr><th>#</th><th>Artifact</th><th>What it is</th><th>Where</th></tr>
<tr><td><b>1</b></td><td><code>provider.ed25519.pub</code></td>
<td><strong>The identity anchor.</strong> The provider's public key — the required cryptographic
identity you pin. It authenticates the operator's statements; their truth rests on each leaf's
stated assumptions. Fetch it from BOTH independent locations and compare; the copies must be
identical.</td>
<td><a href="{base}/log-public-key">this site</a> · <a href="{mirror}/blob/main/provider.ed25519.pub">mirror</a></td></tr>
<tr><td><b>2</b></td><td><code>&lt;library&gt;.attestation.json</code></td>
<td><strong>The claim.</strong> Which repo, which exact git commit, which theorems,
which observed axiom cones (the exact set of assumptions each proof ultimately rests on), what machine protection — signed by the provider.</td>
<td>table below, or <a href="{mirror}">mirror</a> <code>entries/</code></td></tr>
<tr><td><b>3</b></td><td><code>&lt;library&gt;.receipt.json</code></td>
<td><strong>The proof of inclusion.</strong> Binds artifact&nbsp;2 into the signed tree:
leaf index, sibling hashes, the Signed Tree Head (STH). About forty lines of ordinary
Python verify it; the mirror&rsquo;s <code>verify.py</code> contains exactly that core, wrapped in
fail-closed safety checks (stdlib hashing; signature checks shell out to the <code>openssl</code> binary).</td>
<td>table below, or <a href="{mirror}">mirror</a> <code>receipts/</code></td></tr>
<tr><td>+</td><td>the full mirror clone</td>
<td><strong>Maximal benefit: become a witness.</strong> Every leaf + every signed head
ever issued + <code>verify.py</code> (Python stdlib + the <code>openssl</code> binary for
signatures; fails closed without them). <code>python3 verify.py --all</code>
recomputes the entire tree and every historical head — you then hold a retained view that can
later EXPOSE a conflicting head shown to someone else. (A single clone cannot by itself prove the
log never split its view toward another consumer; that requires comparing heads across
consumers.)</td>
<td><code>git clone {mirror}</code></td></tr>
</table>

<h2>Attested libraries</h2>
<table><tr><th>component</th><th>artifact 2</th><th>artifact 3</th><th>status</th></tr>{rows}</table>

<p class="muted">One certificate = one machine-checked theorem together with its exact assumption set (its axiom cone).</p>

<h2>What a verified inclusion means — and what it does not</h2>
<div class="card"><span class="pill ok">means</span> The provider whose key you hold
attests: the Lean proofs of the named repository at the named git commit re-check with
exactly the documented assumptions — and this signed head irrevocably commits that statement to
this view. Consumers who compare heads, or retain the public mirror, can expose any conflicting
view.</div>
<div class="card"><span class="pill warn">does not mean</span> A verified binary. The
proofs cover Rust <em>source</em>; clone the attested commit (the commit id identifies the
committed git tree — not external dependencies, toolchain downloads, or generated artifacts) and
build it yourself — compiler and build are declared trusted base (assumed, not proven)
until the reproducible-builds program lands and retires risk class R5. Every attestation carries its full
residual-risk list — the enumerated assumptions inside its <code>attestation.json</code>. Honesty about the boundary is the product.</div>

<h2>You hold the ruler</h2>
<div class="card">The list of assumptions a certificate is <em>allowed</em> to rest on
is not something this site hands you at verification time — it is a
<strong>requirements card</strong> that lives in <em>your</em> tooling, on
<em>your</em> disk, and that you can read in five minutes or rewrite from first
principles: Lean's three foundational axioms, plus — for the signature tiers only (the top proof layers, where full signature verification is proven) —
named placeholders for SHA-512 and the wire format. Your tooling ignores this
operator's pass/fail labels entirely and re-derives every verdict by comparing the
attestation's <em>observed</em> axiom list (its cone) against <em>your</em> card, name by name.
The operator is trusted to copy down what the proof kernel printed — never to
interpret it.</div>
<div class="card">A card you write yourself will match this log's supply
<strong>exactly</strong> — and that is engineered, not coincidence: the corpus was
shrunk until every remaining axiom justifies its existence. If your card is
<em>stricter</em> (say: "SHA-512 itself must be proven"), there is nothing here to
negotiate — the gap is itemized, never blurred, and you have three honest options:
accept a <em>named</em> line item, walk away, or prove the missing piece and enter it
into this same log. <strong>If your ruler is stricter than our supply, your ruler is
our roadmap.</strong> (The full walk-through is lecture&nbsp;11 of the Jupyter course in the
<a href="https://github.com/saymrwulf/proof-aware-crypto-tooling-agent">pacta repo</a>.)</div>

<h2>The paper</h2>
<div class="card"><a href="{base}/paper"><strong>Accountable Distribution of Machine-Checked
Correctness Evidence: A Transparency Model and the Lean Transparency Log</strong></a>
(PDF, 25 pages, <strong>v0.12 — revised August&nbsp;2026</strong>; the version is printed on the
title page) — the trust decomposition (expensive verification produces an
observation; transparency makes the observation accountable; consumer-local policy decides
acceptance), collision-extracting soundness for inclusion and consistency, scheme-level
accountability GAMES with an explicit composition theorem (head authenticity, position
binding, history binding with a fully proved prefix-transport induction, context-scoped
fork evidence — all discharged by named reductions), the policy boundary where
operator labels can veto but never grant acceptance, and the measured model/deployment
divergence reported as a result rather than hidden — now together with its closure: the
divergence traced to one omitted RFC&nbsp;9162 conjunct (Step&nbsp;7's <code>sn&nbsp;=&nbsp;0</code>),
zero divergences after the one-line restoration, confirmed by a three-way regression.
New in the August 2026 revisions: the deployment evaluated to its current nineteen-leaf, dual-signed state, an
instantiation section for the SLH-DSA (FIPS&nbsp;205) verify path — eleven certificates,
five uninterpreted hash oracles, exact cones — and a certificate appendix mirroring the
Ed25519 tiers.</div>

<div class="card"><strong>Paper and log, one story.</strong> Since the August 2026 revisions the paper
describes this deployment as it runs — nineteen leaves, dual-signed heads, the
post-quantum verify path as leaf&nbsp;18 with its own certificate appendix. The log is
append-only and keeps growing past any paper revision; every number the paper states
stays checkable against the retained history: the mirror clone from rung&nbsp;1 of the
ladder re-verifies all of it, paper-era and after.</div>

<p class="muted">Log heads are signed offline; this service is read-only and holds no
key material. Provider tooling, agent tooling, and the full Jupyter course live in the
<a href="https://github.com/saymrwulf/proof-aware-crypto-tooling-agent">pacta repository</a>.
Software integrators: the machine interface behind every link on this page is described by the
OpenAPI document at <a href="{base}/openapi.json"><code>/openapi.json</code></a> — the
<code>pacta</code> tool builds on it (head pinning, freshness policy, risk scoring R0–R5).</p>
</body></html>"""
