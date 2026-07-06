# Deploying the online log at zkdefi.org/lean-transparency-log

Checklist for the server session. Deliberately generic about the host:
this file is public, so it names only what customers must know anyway
(the service URL) and standard software layouts - no provider inventory,
no credentials, nothing an attacker couldn't already get from public DNS.

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
ExecStart=/usr/bin/python3 -m pacta_provider serve --log-dir /srv/pacta/log --base-path lean-transparency-log --host 127.0.0.1 --port 8461
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
curl -s http://127.0.0.1:8461/lean-transparency-log/healthz
```

## 3. Reverse proxy on zkdefi.org

Caddy (inside the existing `zkdefi.org` site block):

```caddy
redir /lean-transparency-log /lean-transparency-log/docs
route /lean-transparency-log/* {
    reverse_proxy 127.0.0.1:8461 {
        transport http {
            response_header_timeout 15s
        }
    }
}
```

nginx equivalent, with basic rate limiting (the backend is a stdlib
threading server - let the proxy absorb abuse):

```nginx
limit_req_zone $binary_remote_addr zone=pactalog:1m rate=20r/s;
location /lean-transparency-log/ {
    limit_req zone=pactalog burst=40 nodelay;
    proxy_read_timeout 15s;
    proxy_pass http://127.0.0.1:8461/lean-transparency-log/;
    proxy_set_header Host $host;
}
location = /lean-transparency-log { return 301 /lean-transparency-log/docs; }
```

Check: `https://zkdefi.org/lean-transparency-log/docs` renders the customer
documentation; `/v1/sth` returns the dogfood-signed head.

## 4. Second mirror (any Forgejo/Gitea/GitLab you operate)

Create a periodic pull-mirror of
`https://github.com/saymrwulf/lean-transparency-log` on a second,
independently-operated git host. The published repo is the witness
channel; two independent mirrors mean split-view lies must fool two
infrastructures at once — exactly the point.

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
pacta log-fetch  --url https://zkdefi.org/lean-transparency-log --component dalek-ed25519-verified --out-dir /tmp/e
pacta receipt-verify --attestation /tmp/e/dalek-ed25519-verified.attestation.json \
    --receipt /tmp/e/dalek-ed25519-verified.receipt.json \
    --log-public-key <provider.ed25519.pub from the published repo> \
    --sth-store ~/.pacta-pins.json
pacta sth-refresh --url https://zkdefi.org/lean-transparency-log \
    --sth-store ~/.pacta-pins.json --log-public-key <pubkey>
git clone https://github.com/saymrwulf/lean-transparency-log && cd lean-transparency-log && python3 verify.py --all
```
