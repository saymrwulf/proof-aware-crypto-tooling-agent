# Deploying the online log at ltl.zkdefi.org

STATUS: DEPLOYED (2026-07-06) and serving. This file is now the as-built
record plus the update runbook. Deliberately generic about the host: it
names only what customers must know anyway (the service URL) and standard
software layouts - no provider inventory, no credentials.

## As built (docker compose variant)

The target host runs a compose stack; the LTL joined it as a read-only
container instead of the host-systemd variant below:

- app (git clone of the now-public pacta repo) + published-log clone + reconstructed log dir under the compose
  project directory (`ltl/app`, `ltl/published`, `ltl/log`);
- compose service: `python:3.12-alpine`, `read_only: true`, both volumes
  mounted `:ro`, NO published ports (reachable only on the compose
  network), `restart: unless-stopped`;
- Caddy site block for the domain gained a path `handle` that takes
  precedence over the existing catch-all:

```caddy
redir /lean-transparency-log /lean-transparency-log/docs
handle /lean-transparency-log/* {
    reverse_proxy ltl:8461
}
handle {
    reverse_proxy <existing upstream>
}
```

- config validated in a throwaway caddy container before `caddy reload`;
  Caddyfile and compose file backed up with timestamps first.

Update runbook (after each new proof-check run on the provider machine):

```bash
# on the provider machine
pacta_provider log-append ...        # sign new head (offline, dogfood)
pacta_provider log-publish --log-dir ... --git-dir <mirror clone> --public-key <pub>
cd <mirror clone> && git add -A && git commit -m "log update" && git push
# both app/ and published/ on the server are git clones of the now-public repos,
# so the server-side update is pure git pull (no code shipping):
ssh zkdefi-ltl 'cd <compose-dir>/ltl && (cd app && git pull -q) && (cd published && git pull -q) && \
  python3 reconstruct.py && cd .. && sudo docker compose restart ltl'
```

(`reconstruct.py` = the entries.jsonl/sth-history rebuild from step 1
below; it lives in the server's ltl dir.)

---

The remainder of this file is the original host-systemd variant, kept for
deployments without docker.

## What gets deployed

One **read-only** Python process (standard library only, no pip installs)
serving the CT-style API + customer docs. It never touches private keys:
tree heads are signed offline by the provider CLI and only *stored,
already-signed* material is served. A compromised web process can withhold
or replay (agents detect both via pinning + freshness) but cannot forge.

## 1. Get the code and the log data onto the server

```bash
sudo useradd --system --home /srv/pacta --create-home pacta
sudo -u pacta git clone https://github.com/saymrwulf/proof-aware-crypto-tooling-agent /srv/pacta/app
# the log STATE (entries + signed heads, no keys) comes from the published mirror:
sudo -u pacta git clone https://github.com/saymrwulf/lean-transparency-log /srv/pacta/published
# reconstruct a servable log dir from the published mirror:
sudo -u pacta mkdir -p /srv/pacta/log
sudo -u pacta python3 - <<'EOF'
import json, pathlib
pub = pathlib.Path("/srv/pacta/published"); log = pathlib.Path("/srv/pacta/log")
(log / "metadata.json").write_text((pub / "log-metadata.json").read_text())
with (log / "entries.jsonl").open("w") as out:
    for p in sorted((pub / "entries").glob("[0-9]*.json")):
        r = json.loads(p.read_text())
        out.write(json.dumps({"index": r["index"], "leaf_hash": r["leaf_hash"], "leaf": r["leaf"]},
                             sort_keys=True, separators=(",", ":")) + "\n")
(log / "sth-history.jsonl").write_text((pub / "sth-history.jsonl").read_text())
import shutil; shutil.copy(pub / "latest-sth.json", log / "sth.yaml")
print("log dir reconstructed")
EOF
```

(Alternative: rsync `provider/state/transparency-log-main/` from the
provider machine. The published mirror is preferred — it keeps the server
in the same trust position as any other witness.)

## 2. Systemd unit

`/etc/systemd/system/pacta-log.service`:

```ini
[Unit]
Description=Lean Transparency Log (read-only)
After=network.target

[Service]
User=pacta
WorkingDirectory=/srv/pacta/app
Environment=PYTHONPATH=/srv/pacta/app/src:/srv/pacta/app/provider/src
ExecStart=/usr/bin/python3 -m pacta_provider serve --log-dir /srv/pacta/log --host 127.0.0.1 --port 8461
Restart=on-failure
# hardening: read-only service, no key material anywhere near it
ProtectSystem=strict
ReadOnlyPaths=/srv/pacta
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now pacta-log
curl -s http://127.0.0.1:8461/healthz
```

The service serves from the root path by default (it lives on its own
subdomain); pass `--base-path <prefix>` only if you must mount it under
a path instead.

## 3. Reverse proxy: ltl.zkdefi.org

DNS: an `A` record for `ltl` pointing at the same host (or a `CNAME` to
the apex). Caddy then gets its own site block and handles the
certificate automatically:

```caddy
ltl.zkdefi.org {
    reverse_proxy 127.0.0.1:8461 {
        transport http {
            response_header_timeout 15s
        }
    }
}
```

If the log was ever served under a path (the original deployment used
`zkdefi.org/lean-transparency-log`), keep a permanent redirect in the
old site block so published links stay alive:

```caddy
redir /lean-transparency-log https://ltl.zkdefi.org/ permanent
handle_path /lean-transparency-log/* {
    redir https://ltl.zkdefi.org{uri} permanent
}
```

nginx equivalent, with basic rate limiting (the backend is a stdlib
threading server - let the proxy absorb abuse):

```nginx
limit_req_zone $binary_remote_addr zone=pactalog:1m rate=20r/s;
server {
    server_name ltl.zkdefi.org;
    location / {
        limit_req zone=pactalog burst=40 nodelay;
        proxy_read_timeout 15s;
        proxy_pass http://127.0.0.1:8461/;
        proxy_set_header Host $host;
    }
}
```

Check: `https://ltl.zkdefi.org/docs` renders the customer
documentation; `/v1/sth` returns the dogfood-signed head.

## 4. Second mirror (an independently-operated host — not yours)

Create a periodic pull-mirror of
`https://github.com/saymrwulf/lean-transparency-log` on a second git
host **operated by someone else** (e.g. Codeberg). The published repo is
the witness channel; two independent mirrors mean split-view lies must
fool two infrastructures at once — exactly the point. A mirror on
infrastructure the log operator also controls adds convenience, not
witness value: the operator could equivocate consistently on both.

## 4b. Key hygiene (non-negotiable)

The provider SIGNING key never touches this server. The service is
read-only by construction and the systemd unit mounts the tree read-only;
keep it that way. If the box is ever compromised, rotate nothing —
there is nothing to rotate here; verify the published mirror with
`verify.py --all` and redeploy.

## 5. Update cycle (provider machine → world)

After each new proof-check run on the provider machine:

```bash
pacta_provider log-append ...                      # signs new head (offline, dogfood)
pacta_provider log-publish --log-dir ... --git-dir <clone of lean-transparency-log> \
    --public-key provider/state/local-provider/provider.ed25519.pub
cd <clone> && git add -A && git commit -m "log update" && git push   # mirrors sync from here
# on the server: cd /srv/pacta/published && git pull && re-run step 1's reconstruction
sudo systemctl restart pacta-log
```

## 6. Smoke tests from anywhere

```bash
pacta log-fetch  --url https://ltl.zkdefi.org --component dalek-ed25519-verified --out-dir /tmp/e
pacta receipt-verify --attestation /tmp/e/dalek-ed25519-verified.attestation.json \
    --receipt /tmp/e/dalek-ed25519-verified.receipt.json \
    --log-public-key <provider.ed25519.pub from the published repo> \
    --sth-store ~/.pacta-pins.json
pacta sth-refresh --url https://ltl.zkdefi.org \
    --sth-store ~/.pacta-pins.json --log-public-key <pubkey>
git clone https://github.com/saymrwulf/lean-transparency-log && cd lean-transparency-log && python3 verify.py --all
```
