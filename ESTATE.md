# The estate map

One page holding the entire mental model of the Lean Transparency Log
endeavour: every repository, service, mirror, and operator-held entity,
and — most importantly — the *typed* relationships between them,
including the two self-referential loops that make the estate hard to
keep in one head. Maintained here in pacta because pacta is the
machinery hub and the only repo that changes freely.

State snapshot (2026-07-19): log **13 leaves**, root `3488a2d0…`, key
fingerprint `874c8a00…`, paper **v0.9 camera-ready (23 pp)**, five
attested components, pacta suite 118 green.

```mermaid
flowchart LR
  subgraph S["UPSTREAM INPUTS (frozen clones)"]
    s1["curve25519-dalek-source"]
    s2["anza-cryptography-source"]
    s3["risc0-…-dalek-source"]
    s4["betrusted-…-dalek-source"]
    s5["pasta_curves-source"]
  end
  subgraph V["VERIFIED SUBJECTS"]
    d["dalek-ed25519-verified<br/>16 certs · leaf 8 · signer source"]
    a["anza-ed25519-verified<br/>16 certs · leaf 9"]
    r["risc0-ed25519-verified<br/>16 certs · leaf 10"]
    b["betrusted-ed25519-verified<br/>16 certs · leaf 11"]
    p["pasta-pallas-verified<br/>field layer only · NOT attested"]
    c["ltl-accumulator-verified<br/>61 certs · entry-13 subject · frozen 172a1d0"]
  end
  subgraph M["MACHINERY — pacta + operator-held"]
    prov["provider service<br/>check · append · publish · site code · templates (CI-pinned)"]
    sig["dogfood signer<br/>verified-dalek binary"]
    lib["consumer library<br/>receipts · pin store · R0–R5"]
    wal["warden (code)<br/>quorum wallet · MCP · cockpit (local, read-only)"]
    pap["paper<br/>v0.9 + v0.1/v0.2 archives"]
    crs["course + llms.txt<br/>14 notebooks"]
    key["SIGNING KEY (offline)"]
    ops["operational log state<br/>the true accumulator"]
    sd["evidence archive (offline)<br/>kits · stamps"]
  end
  subgraph P["PUBLISHED FACES"]
    mir["lean-transparency-log<br/>GENERATED mirror · fail-closed verify.py + selftest"]
    site["ltl.zkdefi.org<br/>homepage · /v1 API · /paper"]
    fj["Forgejo (droplet)<br/>nightly full-account mirror"]
    book["verifying-crypto-with-lean<br/>undergrad book (independent)"]
  end
  subgraph C2["CONSUMERS"]
    cl["offline cloner<br/>verify.py --all"]
    wr["warden (runtime)"]
    ag["agents<br/>MCP · custody card"]
    sw["swisspost-evoting-go-poc<br/>prospective, family-level only"]
    rev["external reviewers<br/>GPT-5.6 + Claude"]
  end
  s1 --> d
  s2 --> a
  s3 --> r
  s4 --> b
  s5 --> p
  d -->|attest| prov
  a -->|attest| prov
  r -->|attest| prov
  b -->|attest| prov
  prov -->|append| ops
  key -->|signs heads| ops
  ops -->|publish| mir
  prov -.->|"templates (CI-pinned)"| mir
  prov -->|app code| site
  mir -->|published copy| site
  pap -->|/paper| site
  mir -.->|nightly| fj
  mir -->|clone + verify| cl
  site -->|API · custody card| ag
  mir -->|receipts · quorum| wr
  site -.->|prospective| sw
  sd -->|review kits| rev
  d ==>|"LOOP 1: built from"| sig
  sig ==>|"LOOP 1: signs the log"| ops
  mir ==>|"LOOP 1: contains the signer's own attestation (leaf 8)"| d
  c ==>|"LOOP 2: attested as entry 13"| prov
  mir ==>|"LOOP 2: carries proofs about its own accumulator"| c
  classDef src fill:#f1f3f5,stroke:#8a93a0,color:#1c2430
  classDef sub fill:#e2f2e9,stroke:#1e7f4f,color:#1c2430
  classDef mach fill:#eef0f7,stroke:#3b4d8f,color:#1c2430
  classDef held fill:#2b3442,stroke:#2b3442,color:#e8ecf2
  classDef pub fill:#efe9f5,stroke:#6d4a8f,color:#1c2430
  classDef cons fill:#fdf0da,stroke:#a86a10,color:#1c2430
  class s1,s2,s3,s4,s5 src
  class d,a,r,b,p,c sub
  class prov,sig,lib,wal,pap,crs mach
  class key,ops,sd held
  class mir,site,fj,book pub
  class cl,wr,ag,sw,rev cons
```

## The two loops (read these first)

**Loop 1 — the dogfood signer.** The log's tree heads are signed by
`verified-dalek-serial`, a binary built from `dalek-ed25519-verified` —
whose own attestation is leaf 8 *inside the log it signs*. Before
signing, the provider re-checks inclusion of the signer's leaf. The
signature vouches for the tree; the tree contains the proofs of the
signer's source. (Execution provenance is reported, not proven — the
paper says so explicitly.)

**Loop 2 — the self-attestation.** `ltl-accumulator-verified` is a Lean
corpus proving soundness of the log's own accumulator *model*
(extractors, consistency binding, per-step pin safety). It was attested
into the log as **entry 13** — the log carries kernel-checked proofs
about its own machinery, scoped honestly (recursive model, not the
deployed verifier; see the corpus KNOWN-GAPS ledger).

## Repository inventory

| Repository | Lane | Role | Mutability |
|---|---|---|---|
| `curve25519-dalek-source`, `anza-cryptography-source`, `risc0-…-source`, `betrusted-…-source`, `pasta_curves-source` (+ `xous-core`, `litex-boards` context) | upstream | pinned inputs to extraction | **frozen — never modified** |
| `dalek-` / `anza-` / `risc0-` / `betrusted-ed25519-verified` | subject | Rust source + Lean proofs; 16 certs each; attested (leaves 8–11, generations at 0–7) | frozen at attested commits; branch moves only for docs |
| `pasta-pallas-verified` | subject | field layer proven; curve layer pending; **not attested** | changes freely |
| `ltl-accumulator-verified` | subject | 61-cert corpus about the log's accumulator model; **entry-13 subject**, frozen `172a1d0` | frozen; doc-only commits allowed |
| `proof-aware-crypto-tooling-agent` (this repo) | machinery | provider service, consumer library, warden (+ local read-only cockpit), dogfood signer, paper, course, tests | **changes freely — the hub** |
| `lean-transparency-log` | published | the public mirror: leaves, heads, receipts, fail-closed `verify.py` + selftest | **generated by publish** — canonical files here, templates in pacta, CI-pinned |
| `verifying-crypto-with-lean` | published | undergraduate book; zero coupling to log state | changes freely |
| `swisspost-evoting-go-poc` | consumer | operator's PoC; prospective consumer (family-level dalek match only) | independent |

## Services, infra, operator-held

| Entity | What it is |
|---|---|
| **ltl.zkdefi.org** | droplet (caddy → docker `cloud-ltl-1`): homepage rendered from live leaves, `/v1` API, `/paper` (+`/v0.2`, `/v0.1`), key endpoint. Read-only; no key material on the server. Deployment configuration is maintained privately. |
| **Forgejo** (`cloud-forgejo-1`) | nightly (03:00) mirror of the entire saymrwulf GitHub account — disaster-recovery copy. |
| **Signing key** | offline, operator-only; fingerprint `874c8a00…`; never on the server; public half published in two independent locations. |
| **Operational log state** | `provider/state/transparency-log-main` — the true accumulator. Appends happen here; the mirror is its projection. |
| **Evidence archive (offline)** | review kits and stamped artifacts (`_timestamp_hash8` convention); never in git. |

## Edge glossary

| Edge | Meaning |
|---|---|
| extract | pinned source → Lean model (Aeneas/Charon) |
| attest | subject at pinned commit → provider check → signed leaf |
| append / publish | leaf → operational state → generated mirror |
| templates (CI-pinned) | pacta `published_assets` → mirror's `verify.py`/selftest/README; guarded by `tests/test_published_assets.py` since 2026-07-19 |
| serve | pacta app + mirror copy + paper → droplet → site |
| consume | mirror/site → cloners, warden, agents (receipts recomputed, never trusted) |

## Maintenance

Update this file when: a leaf is appended or a head signed (snapshot
line), the paper version changes, a repo/service/consumer is added or
retired, or a loop-relevant mechanism changes. Rules that keep the map
honest: **generated artifacts are fixed at their source** (mirror files
→ pacta templates); subject repos move only for docs; the three
operator-held entities are never expanded into detail here, and the
private infrastructure layer is deliberately unnamed — this map lists
only entities whose existence is already public or must be public for
trust.
