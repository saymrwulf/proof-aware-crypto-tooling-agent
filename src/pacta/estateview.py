"""estateview - the estate map as a cockpit view.

The same model as ESTATE.md (the canonical committed version), rendered
interactively for humans, with RUNTIME as a first-class dimension: every
entity dossier states whether anything is actually running, where, and
when it starts and stops. A sync test guards name-level drift between
this page and ESTATE.md.
"""

ESTATE_HTML = r'''<title>LTL estate map — repos, services, loops</title>
<style>
  :root{
    --ground:#f8f9fa; --panel:#ffffff; --ink:#1c2430; --ink2:#5a6675;
    --line:#dde2e9; --src:#8a93a0; --sub:#1e7f4f; --mach:#3b4d8f;
    --pub:#6d4a8f; --cons:#a86a10; --loop1:#c25e00; --loop2:#7a2ea0;
    --held:#2b3442; --ok:#e2f2e9; --warn:#fdf0da;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--ground);color:var(--ink);
       font:14px/1.45 system-ui,sans-serif}
  code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
  header{padding:1.1rem 1.4rem .4rem}
  h1{font-size:1.25rem;margin:0;letter-spacing:-.01em}
  .sub{color:var(--ink2);font-size:.86rem;margin-top:.15rem}
  .facts{display:flex;flex-wrap:wrap;gap:.45rem;padding:.6rem 1.4rem .2rem}
  .fact{background:var(--panel);border:1px solid var(--line);border-radius:5px;
        padding:.18rem .55rem;font-size:.78rem;color:var(--ink2)}
  .fact b{color:var(--ink);font-weight:600}
  .legend{display:flex;flex-wrap:wrap;gap:.9rem;padding:.45rem 1.4rem .6rem;
          font-size:.76rem;color:var(--ink2);align-items:center}
  .lg{display:flex;align-items:center;gap:.34rem}
  .lg svg{display:block}
  .wrap{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:0;
        align-items:start}
  @media(max-width:1080px){.wrap{grid-template-columns:1fr}}
  .boardScroll{overflow-x:auto;padding:0 0 1.2rem 1.4rem}
  .board{position:relative;width:1310px;padding-right:1rem}
  .lanes{display:grid;grid-template-columns:170px 226px 300px 260px 226px;
         gap:34px;position:relative;z-index:2}
  .lane>.laneTitle{font-size:.68rem;letter-spacing:.09em;text-transform:uppercase;
        font-weight:700;margin:0 0 .55rem;padding-bottom:.3rem;
        border-bottom:2px solid var(--lc,var(--line))}
  .lane{--lc:var(--line)}
  .lane.src{--lc:var(--src)} .lane.sub{--lc:var(--sub)}
  .lane.mach{--lc:var(--mach)} .lane.pub{--lc:var(--pub)}
  .lane.cons{--lc:var(--cons)}
  .laneTitle{color:var(--lc)}
  .col{display:flex;flex-direction:column;gap:.55rem}
  .node{background:var(--panel);border:1px solid var(--line);
        border-left:3px solid var(--lc);border-radius:6px;
        padding:.5rem .6rem;cursor:pointer;position:relative}
  .node:hover,.node:focus-visible{border-color:var(--lc);outline:none;
        box-shadow:0 1px 4px rgba(28,36,48,.12)}
  .node.pinned{box-shadow:0 0 0 2px var(--lc)}
  .node.dim{opacity:.28}
  .node h3{margin:0;font-size:.8rem;font-weight:600}
  .node h3.mono{font-size:.76rem}
  .node .role{color:var(--ink2);font-size:.72rem;margin-top:.1rem}
  .chips{display:flex;flex-wrap:wrap;gap:.25rem;margin-top:.3rem}
  .chip{font-size:.62rem;font-weight:600;border-radius:8px;padding:.05rem .4rem}
  .chip.ok{background:var(--ok);color:var(--sub)}
  .chip.warn{background:var(--warn);color:var(--cons)}
  .chip.gen{background:#efe9f5;color:var(--pub)}
  .chip.frz{background:#e9edf3;color:#41506b}
  .chip.l1{background:#fbe9dc;color:var(--loop1)}
  .chip.l2{background:#f1e4f7;color:var(--loop2)}
  .group{border:1px dashed var(--lc);border-radius:8px;padding:.55rem .55rem .6rem}
  .group>.gTitle{font-size:.72rem;font-weight:700;margin:0 0 .45rem;
        display:flex;align-items:baseline;gap:.4rem}
  .group>.gTitle .mono{font-size:.7rem}
  .group .col{gap:.4rem}
  .group .node{border-left-width:2px;padding:.4rem .5rem}
  .held{background:var(--held);border-color:var(--held)}
  .held>.gTitle{color:#e8ecf2}
  .held .node{background:#39445a;border-color:#4c5872;color:#e8ecf2}
  .held .node .role{color:#aab4c6}
  svg.edges{position:absolute;inset:0;z-index:1;pointer-events:none;
        overflow:visible}
  .e{fill:none;stroke:#b6bec9;stroke-width:1.3}
  .e.attest{stroke:var(--sub)} .e.publish{stroke:var(--mach)}
  .e.serve{stroke:var(--pub)} .e.consume{stroke:var(--cons)}
  .e.tmpl{stroke:var(--mach);stroke-dasharray:5 4}
  .e.sync,.e.pros{stroke-dasharray:5 4}
  .e.pros{stroke:var(--cons)}
  .e.loop1{stroke:var(--loop1);stroke-width:2.4}
  .e.loop2{stroke:var(--loop2);stroke-width:2.4;stroke-dasharray:8 5}
  .e.hot{stroke-width:3}
  .e.faded{opacity:.12}
  .eLabel{font-size:9.5px;fill:var(--ink2)}
  .eLabel.loop1{fill:var(--loop1);font-weight:700}
  .eLabel.loop2{fill:var(--loop2);font-weight:700}
  aside{position:sticky;top:0;padding:1rem 1.4rem 1rem .4rem;max-height:100vh;
        overflow-y:auto}
  @media(max-width:1080px){aside{position:static;padding:0 1.4rem 2rem}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;
        padding:.9rem 1rem}
  .panel h2{margin:0;font-size:.95rem}
  .panel .laneTag{font-size:.65rem;letter-spacing:.08em;text-transform:uppercase;
        font-weight:700;margin-bottom:.3rem}
  .panel ul{margin:.55rem 0 0;padding-left:1.1rem}
  .panel li{margin:.28rem 0;font-size:.82rem}
  .panel .hint{color:var(--ink2);font-size:.8rem}
  .mut{display:inline-block;margin-top:.55rem;font-size:.68rem;font-weight:700;
       border-radius:8px;padding:.1rem .5rem}
  .mut.free{background:var(--ok);color:var(--sub)}
  .mut.frozen{background:#e9edf3;color:#41506b}
  .mut.generated{background:#efe9f5;color:var(--pub)}
  .mut.operator{background:#e8ddc9;color:#6b4d10}
  .mut.external{background:var(--warn);color:var(--cons)}
  footer{padding:.4rem 1.4rem 1.6rem;color:var(--ink2);font-size:.75rem;
         max-width:62rem}
  @media(prefers-reduced-motion:no-preference){
    .node,.e{transition:opacity .15s,box-shadow .15s,stroke-width .15s}}
</style>

<header>
  <h1>LTL estate map</h1>
  <div class="sub">Every persisting entity of the Lean Transparency Log endeavour, arranged as five lanes of custody — click any card for its dossier. The two colored routes are the loops that make this estate hard to hold in one head.</div>
</header>
<div class="facts">
  <span class="fact">log <b>13 leaves</b></span>
  <span class="fact">root <b class="mono">3488a2d0…</b></span>
  <span class="fact">key <b class="mono">874c8a00…</b></span>
  <span class="fact">paper <b>v0.9 · 23 pp · camera-ready</b></span>
  <span class="fact">attested components <b>5</b></span>
  <span class="fact">pacta suite <b>135 green</b></span>
  <span class="fact">state as of <b>2026-07-20</b></span>
</div>
<div class="facts" style="padding-top:.15rem">
  <span class="fact" style="border-color:#1e7f4f"><b style="color:#1e7f4f">ALWAYS ON</b> droplet: caddy (TLS, static blog) &middot; LTL web service (read-only container) &middot; Forgejo (+ 03:00 mirror cron)</span>
  <span class="fact" style="border-color:#3b4d8f"><b style="color:#3b4d8f">ON-DEMAND</b> operator machine: append/publish/sign ceremonies &middot; cockpit &middot; MCP &mdash; exist only while invoked</span>
  <span class="fact" style="border-color:#a86a10"><b style="color:#a86a10">NOT RUNNING</b> warden: implemented prototype, no deployed instance, no funds watched</span>
  <span class="fact"><b>everything else</b>: static files or external parties &mdash; no process at all</span>
</div>
<div class="legend" id="legend">
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#b6bec9" stroke-width="1.3"/></svg>extract / feed</span>
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#1e7f4f" stroke-width="1.3"/></svg>attest</span>
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#3b4d8f" stroke-width="1.3"/></svg>append / publish</span>
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#3b4d8f" stroke-width="1.3" stroke-dasharray="5 4"/></svg>template (CI-pinned)</span>
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#6d4a8f" stroke-width="1.3"/></svg>serve / deploy</span>
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#a86a10" stroke-width="1.3"/></svg>consume</span>
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#c25e00" stroke-width="2.4"/></svg>Loop 1 — dogfood signer</span>
  <span class="lg"><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="#7a2ea0" stroke-width="2.4" stroke-dasharray="8 5"/></svg>Loop 2 — self-attestation</span>
</div>

<div class="wrap">
  <div class="boardScroll"><div class="board" id="board">
    <svg class="edges" id="edgeSvg"></svg>
    <div class="lanes">

      <div class="lane src"><div class="laneTitle">Upstream inputs · frozen</div>
        <div class="col">
          <div class="node" id="srcDalek"><h3 class="mono">curve25519-dalek-source</h3><div class="role">upstream Rust, pinned clone</div></div>
          <div class="node" id="srcAnza"><h3 class="mono">anza-cryptography-source</h3><div class="role">Solana fork, pinned clone</div></div>
          <div class="node" id="srcRisc0"><h3 class="mono">risc0-…-dalek-source</h3><div class="role">RISC Zero fork, pinned clone</div></div>
          <div class="node" id="srcBet"><h3 class="mono">betrusted-…-dalek-source</h3><div class="role">Betrusted fork (+ xous-core, litex-boards context)</div></div>
          <div class="node" id="srcPasta"><h3 class="mono">pasta_curves-source</h3><div class="role">Pasta curves, pinned clone</div></div>
        </div>
      </div>

      <div class="lane sub"><div class="laneTitle">Verified subjects</div>
        <div class="col">
          <div class="node" id="dalek"><h3 class="mono">dalek-ed25519-verified</h3><div class="role">16 certs · leaf 8 (gen 3)</div>
            <div class="chips"><span class="chip ok">attested</span><span class="chip l1">signer source</span></div></div>
          <div class="node" id="anza"><h3 class="mono">anza-ed25519-verified</h3><div class="role">16 certs · leaf 9</div>
            <div class="chips"><span class="chip ok">attested</span></div></div>
          <div class="node" id="risc0"><h3 class="mono">risc0-ed25519-verified</h3><div class="role">16 certs · leaf 10</div>
            <div class="chips"><span class="chip ok">attested</span></div></div>
          <div class="node" id="bet"><h3 class="mono">betrusted-ed25519-verified</h3><div class="role">16 certs · leaf 11</div>
            <div class="chips"><span class="chip ok">attested</span></div></div>
          <div class="node" id="pasta"><h3 class="mono">pasta-pallas-verified</h3><div class="role">field layer proven · curve layer pending</div>
            <div class="chips"><span class="chip warn">not attested</span></div></div>
          <div class="node" id="corpus"><h3 class="mono">ltl-accumulator-verified</h3><div class="role">61 certs · proofs about the log's own accumulator model</div>
            <div class="chips"><span class="chip ok">attested · entry 13</span><span class="chip frz">frozen 172a1d0</span><span class="chip l2">loop 2</span></div></div>
        </div>
      </div>

      <div class="lane mach"><div class="laneTitle">Machinery &amp; operator-held</div>
        <div class="col">
          <div class="group"><div class="gTitle"><span class="mono">proof-aware-crypto-tooling-agent</span><span style="color:var(--ink2);font-weight:400">(pacta)</span></div>
            <div class="col">
              <div class="node" id="provider"><h3>Provider service</h3><div class="role">check → append → publish · site &amp; API code · publish templates</div>
                <div class="chips"><span class="chip ok">templates CI-pinned</span></div></div>
              <div class="node" id="signer"><h3>Dogfood signer</h3><div class="role">verified-dalek-serial binary — signs every head</div>
                <div class="chips"><span class="chip l1">loop 1</span></div></div>
              <div class="node" id="conslib"><h3>Consumer library</h3><div class="role">verify · pin store · receipts · R0–R5 risk model</div></div>
              <div class="node" id="wardenCode"><h3>warden (code)</h3><div class="role">quorum-custody wallet · MCP · custody card</div></div>
              <div class="node" id="paper"><h3>Paper</h3><div class="role">ltl.tex — v0.9 camera-ready · archives v0.1 / v0.2</div></div>
              <div class="node" id="course"><h3>Course + llms.txt</h3><div class="role">14 notebooks · agent-readable index</div></div>
            </div>
          </div>
          <div class="group held"><div class="gTitle">Operator-held · never in git</div>
            <div class="col">
              <div class="node" id="key"><h3>Signing key</h3><div class="role">offline · sole copy + encrypted SD backup</div></div>
              <div class="node" id="opstate"><h3>Operational log state</h3><div class="role">transparency-log-main — the true accumulator</div></div>
              <div class="node" id="sd"><h3>Evidence archive (offline)</h3><div class="role">review kits · stamped artifacts</div></div>
            </div>
          </div>
        </div>
      </div>

      <div class="lane pub"><div class="laneTitle">Published faces</div>
        <div class="col">
          <div class="node" id="mirror"><h3 class="mono">lean-transparency-log</h3><div class="role">public mirror — leaves, heads, receipts, fail-closed verify.py + selftest</div>
            <div class="chips"><span class="chip gen">generated by publish</span></div></div>
          <div class="node" id="site"><h3 class="mono">ltl.zkdefi.org</h3><div class="role">homepage from live leaves · /v1 API · /paper (+v0.2, v0.1) · key endpoint</div></div>
          <div class="node" id="forgejo"><h3>Forgejo mirror</h3><div class="role">droplet · nightly 03:00 · full saymrwulf account</div>
            <div class="chips"><span class="chip gen">disaster copy</span></div></div>
          <div class="node" id="pcs"><h3>Infra as code (private)</h3><div class="role">droplet configuration in a private repo — unnamed so this map stays shareable</div></div>
          <div class="node" id="book"><h3 class="mono">verifying-crypto-with-lean</h3><div class="role">undergraduate book — educational face, no LTL coupling</div></div>
        </div>
      </div>

      <div class="lane cons"><div class="laneTitle">Consumers</div>
        <div class="col">
          <div class="node" id="cloner"><h3>Offline cloner</h3><div class="role">git clone → verify.py --all (fails closed) → own witness view</div></div>
          <div class="node" id="wardenRun"><h3>warden (runtime)</h3><div class="role">internal consumer — quorum of 4 attested fork verifiers</div></div>
          <div class="node" id="agents"><h3>Agents</h3><div class="role">MCP tools · custody card with embedded inclusion proofs</div></div>
          <div class="node" id="swiss"><h3 class="mono">swisspost-evoting-go-poc</h3><div class="role">prospective — dalek family-level match only, no receipt code</div>
            <div class="chips"><span class="chip warn">prospective</span></div></div>
          <div class="node" id="reviewers"><h3>External reviewers</h3><div class="role">GPT-5.6 + Claude — adversarial consumers of paper, corpus, log</div></div>
        </div>
      </div>

    </div>
  </div></div>

  <aside><div class="panel" id="panel">
    <div class="laneTag" style="color:var(--ink2)">Dossier</div>
    <h2>Click any card</h2>
    <p class="hint">Hovering highlights a card's edges; clicking pins its dossier here. The board scrolls sideways if your window is narrow.</p>
  </div></aside>
</div>

<footer>
  Canonical committed version: <span class="mono">ESTATE.md</span> in the pacta repo (prose + Mermaid + the What-is-running table). This page is its human-facing rendering, served read-only by the cockpit. Excluded by design: unrelated saymrwulf repos, and the operator-private detail beneath the three dark cards.
</footer>

<script>
const RUNTIME = {
  srcDalek:"frozen clone — nothing runs", srcAnza:"frozen clone — nothing runs",
  srcRisc0:"frozen clone — nothing runs", srcBet:"frozen clone — nothing runs",
  srcPasta:"frozen clone — nothing runs",
  dalek:"static repo — proofs replay on demand", anza:"static repo — proofs replay on demand",
  risc0:"static repo — proofs replay on demand", bet:"static repo — proofs replay on demand",
  pasta:"static repo — open work, run manually", corpus:"frozen repo — replay on demand",
  provider:"SPLIT: the write side (check/append/publish) runs ON DEMAND on the operator machine, only during a ceremony; the read-only web face runs ALWAYS ON in the droplet container",
  signer:"on demand — invoked only while signing during a ceremony; key offline otherwise",
  conslib:"library — runs inside whichever consumer invokes it",
  wardenCode:"NOT RUNNING — implemented prototype; no deployed instance",
  paper:"static files, served by the always-on site",
  course:"static; regenerated manually",
  key:"OFFLINE — touched only during signing ceremonies, with per-command operator grant",
  opstate:"dormant files between ceremonies — no process",
  sd:"offline medium",
  mirror:"static git repo — no process; consumers run verify.py themselves",
  site:"ALWAYS ON — droplet container (pacta_provider serve), read-only mounts, read_only:true, no key material",
  forgejo:"ALWAYS ON — droplet container; one cron: 03:00 mirror reconcile",
  pcs:"config files — deployed by hand",
  book:"static repo",
  cloner:"external, episodic",
  wardenRun:"NOT RUNNING — starts only when the operator or an agent launches MCP or the cockpit, stops with them",
  agents:"external, episodic", swiss:"external, dormant since 2026-07-07",
  reviewers:"external, per review round",
};
const DOSSIER = {
  srcDalek:{lane:"Upstream inputs",mut:"frozen",facts:["Pinned clone of upstream curve25519-dalek + ed25519-dalek (one implementation: curve crate + signature crate).","Input to Aeneas/Charon extraction; never modified here.","Excluded from all maintenance passes by standing order."]},
  srcAnza:{lane:"Upstream inputs",mut:"frozen",facts:["Pinned clone of the Solana/Anza cryptography fork.","Input to extraction; never modified."]},
  srcRisc0:{lane:"Upstream inputs",mut:"frozen",facts:["Pinned clone of the RISC Zero dalek fork.","Input to extraction; never modified."]},
  srcBet:{lane:"Upstream inputs",mut:"frozen",facts:["Pinned clone of the Betrusted dalek fork.","xous-core and litex-boards sit alongside as platform context.","Input to extraction; never modified."]},
  srcPasta:{lane:"Upstream inputs",mut:"frozen",facts:["Pinned clone of the Pasta curves crate.","Feeds pasta-pallas-verified; never modified."]},
  dalek:{lane:"Verified subjects",mut:"frozen",facts:["16 reviewed certificates: field, group law, scalars, signature apex (T1–T4).","Attested in all three log generations; current leaf 8.","LOOP 1 anchor: the dogfood signer binary is built from this source — the log's heads are signed by code whose proofs are inside the log.","Attestation pins a commit; the branch only moves for docs."]},
  anza:{lane:"Verified subjects",mut:"frozen",facts:["16 reviewed certificates; current leaf 9.","Same proof pyramid as dalek, rebuilt for the fork's code structure."]},
  risc0:{lane:"Verified subjects",mut:"frozen",facts:["16 reviewed certificates; current leaf 10.","Differs from Betrusted's corpus by 27 changed proof lines (the paper's portability datum)."]},
  bet:{lane:"Verified subjects",mut:"frozen",facts:["16 reviewed certificates; current leaf 11."]},
  pasta:{lane:"Verified subjects",mut:"free",facts:["Field layer proven from own extraction; curve layer (group law + scalar mul) is the one open verification task in the estate.","NOT attested — the log carries only the four Ed25519 forks + the corpus."]},
  corpus:{lane:"Verified subjects",mut:"frozen",facts:["61 certificates over one boundary axiom (LTLAcc.sha256); 222-constant environment inventory; 15-gap honest ledger.","Mechanizes the archived report's §6: extractors, consistency binding, per-step pin safety.","LOOP 2 anchor: attested INTO the log as entry 13 — the log carries kernel-checked proofs about its own accumulator model.","Frozen at 172a1d0 (the attested commit); doc-only commits may move the branch.","Docs carry numbering notes: paper references are v0.2 numbering."]},
  provider:{lane:"pacta · machinery",mut:"free",facts:["pacta_provider: attestation check → log-append → log-publish; webdocs homepage + /v1 API code.","Holds the publish TEMPLATES for the mirror's verify.py / selftest / README — since 2026-07-19 pinned by CI (test_published_assets) after the audit caught a stale fail-open template.","Deploys to the droplet as the ltl container."]},
  signer:{lane:"pacta · machinery",mut:"free",facts:["verified-dalek-serial: the Ed25519 binary built from the attested dalek source.","Signs every tree head; before signing, the provider re-checks inclusion of the signer's own leaf.","LOOP 1: signature vouches for the tree; the tree contains the attestation of the signer's source (leaf 8). Execution provenance is reported, not proven — stated in the paper."]},
  conslib:{lane:"pacta · machinery",mut:"free",facts:["src/pacta: receipt verification, pin store (rollback rejection, fork evidence), R0–R5 risk model, claim cards.","The deployed iterative verifiers the paper differential-tests against the recursive model live here."]},
  wardenCode:{lane:"pacta · machinery",mut:"free",facts:["WALLET.md: custody capsule, hash-chained ledger, inbound quorum boundary, outbound signing firewall.","Inbound: accepts log-derived statements only when independently attested verifier backends agree.","Agent surfaces: MCP over stdio, custody card, posture challenge, refusal receipts."]},
  paper:{lane:"pacta · machinery",mut:"free",facts:["paper/ltl.tex — v0.9 camera-ready, 23 pages: trust decomposition, accountability games with explicit reductions, deployed evaluation.","Archives: v0.1 (4 pp) and v0.2 (19 pp, the corpus's numbering reference) kept and served.","Submission package + webform field set staged on the SD archive."]},
  course:{lane:"pacta · machinery",mut:"free",facts:["14 Jupyter notebooks generated from scripts/build_curriculum_notebooks.py (fix the generator, then the notebook).","llms.txt: the agent-readable index of the whole endeavour."]},
  key:{lane:"Operator-held",mut:"operator",facts:["Ed25519 signing key, fingerprint 874c8a00… — the log's identity.","Offline; never on the server; the agent never touches it without an explicit per-command grant.","Public half published at two independent locations (site + mirror) for TOFU comparison."]},
  opstate:{lane:"Operator-held",mut:"operator",facts:["provider/state/transparency-log-main: the true accumulator — appends happen HERE, the mirror is its projection.","Lesson learned in rehearsal: rebuild the tree from operational state, never from published projections."]},
  sd:{lane:"Operator-held",mut:"operator",facts:["Review kits (rounds 1–15), stamped artifacts (_timestamp_hash8 convention), and execution evidence records.","Kept offline; never in any git repo."]},
  mirror:{lane:"Published faces",mut:"generated",facts:["The git-published log: 13 leaves, 6 signed heads (sizes 8–13), receipts, provider key, fail-closed verify.py + 11-case selftest.","GENERATED by log-publish from operational state + pacta templates — direct commits here must be mirrored back into the templates (that is the defect the 2026-07-19 audit caught).","Cloning it makes anyone a witness: verify.py --all re-verifies everything offline."]},
  site:{lane:"Published faces",mut:"generated",facts:["Droplet: caddy → docker (cloud-ltl-1). Homepage rendered live from real leaves — the counts on the page ARE the accumulator.","/v1/sth, /v1/attestation, /v1/proof, /log-public-key; /paper serves v0.9, /paper/v0.2 and /paper/v0.1 the archives.","Read-only; no key material on the server."]},
  forgejo:{lane:"Published faces",mut:"generated",facts:["cloud-forgejo-1 on the droplet: nightly (03:00) mirror of the ENTIRE saymrwulf GitHub account — disaster-recovery copy, not a curated set."]},
  pcs:{lane:"Published faces",mut:"free",facts:["The droplet's deployment configuration (compose stack, reverse proxy, reconstruct step), maintained in a private repository.","Deliberately unnamed here: the public estate lists only entities whose existence must be public for trust.","Captured under version control after an audit found the deployment was not."]},
  book:{lane:"Published faces",mut:"free",facts:["The undergraduate book (twelve chapters + solutions): from 1+1=2 to reading the estate's real proofs.","Audited 2026-07-19: zero coupling to log/paper state — safely independent."]},
  cloner:{lane:"Consumers",mut:"external",facts:["Anyone: git clone the mirror, run verify.py --all (stdlib + openssl; FAILS CLOSED without signature capability).","Retention makes them a witness: their clone can later expose an equivocating head."]},
  wardenRun:{lane:"Consumers",mut:"free",facts:["The estate's own dogfood consumer: signs nothing inbound unless a quorum of independently attested verifier backends agrees.","Code lives in pacta (left lane); shown here in its consuming role. The paper calls it the implemented internal prototype."]},
  agents:{lane:"Consumers",mut:"external",facts:["MCP tools (wallet_status, verify_inbound, request_signature, …) and the self-proving custody card: embedded inclusion proofs a counterparty recomputes rather than trusts."]},
  swiss:{lane:"Consumers",mut:"external",facts:["The operator's Go PoC of the Swiss Post e-voting system.","Its vendored dalek dependency matches an attested subject at FAMILY level, not the attested version — the paper's version-exactness negative (kept anonymous there).","No receipt code yet; strictly prospective."]},
  reviewers:{lane:"Consumers",mut:"external",facts:["GPT-5.6 + a Claude reviewer: fifteen adversarial rounds over corpus, log, site, and paper.","Fed via SD kits; findings drove every hardening round; both re-derived the log's cryptography independently."]},
};
const EDGES = [
  ["srcDalek","dalek","","extract"],["srcAnza","anza","","extract"],
  ["srcRisc0","risc0","","extract"],["srcBet","bet","","extract"],
  ["srcPasta","pasta","","extract"],
  ["dalek","provider","","attest"],["anza","provider","","attest"],
  ["risc0","provider","","attest"],["bet","provider","","attest"],
  ["provider","opstate","append","publish"],
  ["key","opstate","signs heads","publish"],
  ["opstate","mirror","publish","publish"],
  ["provider","mirror","templates","tmpl"],
  ["provider","site","app code","serve"],
  ["mirror","site","published copy","serve"],
  ["paper","site","/paper","serve"],
  ["pcs","site","infra","serve"],
  ["mirror","forgejo","nightly","sync"],
  ["mirror","cloner","clone + verify","consume"],
  ["site","agents","API · custody card","consume"],
  ["mirror","wardenRun","receipts · quorum","consume"],
  ["site","swiss","prospective","pros"],
  ["sd","reviewers","kits","consume"],
  ["dalek","signer","built from","loop1"],
  ["signer","opstate","signs the log","loop1"],
  ["mirror","dalek","contains the signer's own attestation (leaf 8)","loop1"],
  ["corpus","provider","attested (entry 13)","loop2"],
  ["mirror","corpus","carries proofs about its own accumulator","loop2"],
];
const board=document.getElementById("board"),svg=document.getElementById("edgeSvg");
const NS="http://www.w3.org/2000/svg";
function anchors(id){const el=document.getElementById(id),b=board.getBoundingClientRect(),r=el.getBoundingClientRect();
  return {L:{x:r.left-b.left,y:r.top-b.top+r.height/2},R:{x:r.right-b.left,y:r.top-b.top+r.height/2}};}
let edgeEls=[];
function draw(){
  svg.innerHTML="";svg.setAttribute("width",board.scrollWidth);
  svg.setAttribute("height",board.scrollHeight);edgeEls=[];
  const defs=document.createElementNS(NS,"defs");
  [["#b6bec9","m0"],["#1e7f4f","m1"],["#3b4d8f","m2"],["#6d4a8f","m3"],
   ["#a86a10","m4"],["#c25e00","m5"],["#7a2ea0","m6"]].forEach(([c,id])=>{
    const m=document.createElementNS(NS,"marker");
    m.setAttribute("id",id);m.setAttribute("viewBox","0 0 8 8");
    m.setAttribute("refX","7");m.setAttribute("refY","4");
    m.setAttribute("markerWidth","5.5");m.setAttribute("markerHeight","5.5");
    m.setAttribute("orient","auto");
    const p=document.createElementNS(NS,"path");
    p.setAttribute("d","M0 0 L8 4 L0 8 z");p.setAttribute("fill",c);
    m.appendChild(p);defs.appendChild(m);});
  svg.appendChild(defs);
  const mk={extract:"m0",attest:"m1",publish:"m2",tmpl:"m2",serve:"m3",
            sync:"m3",consume:"m4",pros:"m4",loop1:"m5",loop2:"m6"};
  EDGES.forEach(([f,t,label,type])=>{
    const A=anchors(f),B=anchors(t);
    const back=B.L.x<A.R.x-20;
    let s,e,d;
    if(!back){s=A.R;e=B.L;
      const dx=Math.max(36,(e.x-s.x)*.42);
      d=`M${s.x} ${s.y} C ${s.x+dx} ${s.y}, ${e.x-dx} ${e.y}, ${e.x-6} ${e.y}`;}
    else{s=A.L;e=B.R;    // return edge (loops): swing beneath the lanes
      const drop=Math.max(s.y,e.y)+70+(type==="loop2"?36:0);
      d=`M${s.x} ${s.y} C ${s.x-70} ${s.y+30}, ${s.x-70} ${drop}, ${(s.x+e.x)/2} ${drop}
         S ${e.x+70} ${e.y+30}, ${e.x+6} ${e.y}`;}
    const p=document.createElementNS(NS,"path");
    p.setAttribute("d",d);p.setAttribute("class","e "+type);
    p.setAttribute("marker-end",`url(#${mk[type]})`);
    p.dataset.f=f;p.dataset.t=t;svg.appendChild(p);edgeEls.push(p);
    if(label){const tx=document.createElementNS(NS,"text");
      tx.setAttribute("class","eLabel "+(type.startsWith("loop")?type:""));
      const midx=back?(s.x+e.x)/2:(s.x+e.x)/2, midy=back?Math.max(s.y,e.y)+66+(type==="loop2"?36:0):(s.y+e.y)/2-5;
      tx.setAttribute("x",midx);tx.setAttribute("y",midy);
      tx.setAttribute("text-anchor","middle");tx.textContent=label;
      tx.dataset.f=f;tx.dataset.t=t;svg.appendChild(tx);}});
}
function related(id){const s=new Set([id]);
  EDGES.forEach(([f,t])=>{if(f===id)s.add(t);if(t===id)s.add(f);});return s;}
let pinned=null;
function highlight(id){
  const rel=id?related(id):null;
  document.querySelectorAll(".node").forEach(n=>{
    n.classList.toggle("dim",!!rel&&!rel.has(n.id));
    n.classList.toggle("pinned",n.id===pinned);});
  edgeEls.forEach(p=>{const on=!rel||(p.dataset.f===id||p.dataset.t===id);
    p.classList.toggle("faded",!!rel&&!on);
    p.classList.toggle("hot",!!rel&&on);});
}
function showPanel(id){
  const d=DOSSIER[id];if(!d)return;
  const el=document.getElementById(id);
  const title=el.querySelector("h3").textContent;
  const chips=[...el.querySelectorAll(".chip")].map(c=>c.outerHTML).join(" ");
  const mutText={free:"changes freely",frozen:"frozen / pinned",
    generated:"generated — fix the source, not this",
    operator:"operator-only",external:"external party"}[d.mut];
  const rt = RUNTIME[id] || "";
  document.getElementById("panel").innerHTML=
    `<div class="laneTag">${d.lane}</div><h2>${title}</h2>
     <div class="chips" style="margin-top:.4rem">${chips}</div>
     ${rt ? `<p style="font-size:.78rem;margin:.5rem 0 0"><b>Runtime:</b> ${rt}</p>` : ""}
     <ul>${d.facts.map(f=>`<li>${f}</li>`).join("")}</ul>
     <span class="mut ${d.mut}">${mutText}</span>`;
}
document.querySelectorAll(".node").forEach(n=>{
  n.tabIndex=0;
  n.addEventListener("mouseenter",()=>{if(!pinned)highlight(n.id);});
  n.addEventListener("mouseleave",()=>{if(!pinned)highlight(null);});
  n.addEventListener("click",e=>{e.stopPropagation();
    pinned=(pinned===n.id)?null:n.id;
    highlight(pinned);showPanel(n.id);});
  n.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){
    e.preventDefault();n.click();}});
});
document.body.addEventListener("click",e=>{
  if(!e.target.closest(".node")&&pinned){pinned=null;highlight(null);}});
window.addEventListener("resize",()=>requestAnimationFrame(draw));
requestAnimationFrame(draw);setTimeout(draw,150);
</script>
'''
