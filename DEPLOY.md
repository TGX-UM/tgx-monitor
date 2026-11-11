# Deploying tgx-monitor

The first deploy on the Strato swarm, step by step, then routine updates and rollback.
It follows the cluster's standing rules in `/mnt/gluster/documentation/AGENTS.md`
(Gluster storage, `core` network, Traefik labels, GHCR images, no node pins, Docker
secrets, update the docs after every change). Read that file and
`services/tgx-monitor.md` before touching the live service; when they disagree with this
file, trust the live service and fix the docs.

Who does what:

| Step | Who | Needs root? |
|---|---|---|
| GitHub App, healthchecks.io, PAT, most secrets | Marvin, from his own shell | no |
| A records, Slack webhook secret, the root status cron, ESP between the nodes if needed, SMTP mailbox | Egon (LO-TGX in cc) | yes |
| Everything else in this file | Marvin (docker group) | no |

The batched request to Egon is at the end ("Steps that need Egon").

## 0. Preconditions

- The image exists: a push to `main` runs `.github/workflows/docker.yml`, which publishes
  `ghcr.io/tgx-um/tgx-monitor:sha-<7>` and `:latest`. **Make the package public** once
  (GitHub, TGX-UM, Packages, tgx-monitor, Package settings, Change visibility), so both
  nodes pull it without `--with-registry-auth`. Check from each node:

  ```bash
  ssh tgx1 'docker pull -q ghcr.io/tgx-um/tgx-monitor:latest'
  ssh tgx2 'docker pull -q ghcr.io/tgx-um/tgx-monitor:latest'
  ```

- Never build it on a node (a local-only image breaks failover; AGENTS.md).

## 1. Directories on GlusterFS

```bash
ssh tgx1
mkdir -p /mnt/gluster/docker/tgx-monitor/{data/backups,public,agent-hb}
chgrp -R docker /mnt/gluster/docker/tgx-monitor
chmod 2775 /mnt/gluster/docker/tgx-monitor /mnt/gluster/docker/tgx-monitor/*
chmod 2775 /mnt/gluster/docker/tgx-monitor/data/backups
```

The containers run as uid 10001 with the hosts' docker group (gid 1000 on both nodes),
so group-writable is enough. Swarm refuses to start a task whose bind source does not
exist, so every path in `stack.yml` must exist on **both** nodes before the deploy. The
Gluster and HiDrive paths do already; the three tgx-monitor directories (data, public,
agent-hb, root-status) are created in step 1.

## 2. GitHub App, tokens, healthchecks.io (Marvin, web UI)

1. **GitHub App** `tgx-monitor` on TGX-UM: permissions Issues read/write, Metadata
   read; no webhook. Install it on `TGX-UM/tgx-monitor` only. Download a private key.
   Note the App id and the installation id (`https://github.com/organizations/TGX-UM/settings/installations/<id>`);
   they go into `stack.yml` (`TGXMON_GH_APP_ID`, `TGXMON_GH_INSTALLATION_ID`), they are
   not secret. Issues come from the App because GitHub does not notify you about an
   issue you opened yourself.
2. **`tgxmon_gh_token`**: a fine-grained PAT with read-only *Actions* and *Metadata* on
   the repositories whose workflows the catalogue watches, plus *Actions: write* on
   `TGX-UM/tgx-monitor` (the daily keepalive re-enables `probe.yml` and `browser.yml`).
   Expiry: one year; the `self` check warns 30 days ahead.
3. **`tgxmon_ghcr_read_pat`**: a *classic* PAT with only `read:packages` (GHCR rejects
   App tokens), for the manifest checks of private packages such as `oppbk`.
4. **healthchecks.io**: one project, ten checks, each e-mailing Marvin and Egon:

   | Check | Period / grace |
   |---|---|
   | `core-cycle`, `delivery-watchdog` | 5 min / 10 min |
   | `agent-tgx1`, `agent-tgx2` | 1 min / 5 min |
   | `gha-probe` | 20 min / 6 h |
   | `root-status-tgx1`, `root-status-tgx2` | 5 min / 15 min |
   | `hidrive-copy`, `restore-verify`, `monitor-backup` | 1 day (restore-verify 7 days) / 6 h |

5. **Repository settings** of `TGX-UM/tgx-monitor`: Actions secret `HC_PROBE_URL` (the
   `gha-probe` ping URL), Actions secret `GITLEAKS_LICENSE` (free key from gitleaks.io,
   required for organisation repositories). The variable `OUTSIDE_PROBE_ENABLED` comes
   in step 9.

## 3. Docker secrets

Create each from your own shell, never from a file in the repo or a chat. The value
goes in through stdin or a file you delete afterwards; nothing here is echoed.
`stack.yml` lists all eleven as `external`, so **every one must exist before the first
deploy**; a channel whose secret is still a placeholder reports `unknown` and sends
nothing.

```bash
ssh tgx1
umask 077; d=$(mktemp -d)

# GitHub App private key (PEM), PATs
docker secret create tgxmon_gh_app_key  ~/Downloads/tgx-monitor.<date>.private-key.pem
read -rs T; printf '%s' "$T" | docker secret create tgxmon_gh_token -;      unset T
read -rs T; printf '%s' "$T" | docker secret create tgxmon_ghcr_read_pat -; unset T

# SMTP: JSON. Strato mailbox (587 STARTTLS); see "Enabling alerts" for the fallback.
cat > "$d/smtp.json" <<'EOF'
{"host": "smtp.strato.de", "port": 587, "starttls": true,
 "user": "<MAILBOX>", "password": "<PASSWORD>", "from": "tgx-monitor <MAILBOX>"}
EOF
"${EDITOR:-nano}" "$d/smtp.json"; docker secret create tgxmon_smtp "$d/smtp.json"

# Contacts: handle -> e-mail, for every handle in catalogue/owners.yaml that may get mail
cat > "$d/contacts.json" <<'EOF'
{"marvinm2": "<ADDRESS>", "egonw": "<ADDRESS>"}
EOF
"${EDITOR:-nano}" "$d/contacts.json"; docker secret create tgxmon_contacts "$d/contacts.json"

# UI users: GitHub handle -> argon2 hash (roles come from owners.yaml)
docker run --rm -it ghcr.io/tgx-um/tgx-monitor:latest python -c \
  "import getpass, argon2; print(argon2.PasswordHasher().hash(getpass.getpass()))"
cat > "$d/users.json" <<'EOF'
{"marvinm2": "<ARGON2 HASH>", "egonw": "<ARGON2 HASH>"}
EOF
"${EDITOR:-nano}" "$d/users.json"; docker secret create tgxmon_users "$d/users.json"

# Session signing key, push tokens for the cron jobs (job name -> random token)
openssl rand -hex 32 | tr -d '\n' | docker secret create tgxmon_session_key -
printf '{"wikipathways-reload": "%s", "wikipathways-switch": "%s", "aopwiki-snorql-reload": "%s"}' \
  "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" \
  > "$d/push.json"; docker secret create tgxmon_push_tokens "$d/push.json"

# healthchecks.io: check name -> ping URL (the URL is the credential)
cat > "$d/hc.json" <<'EOF'
{"core-cycle": "<URL>", "delivery-watchdog": "<URL>", "agent-tgx1": "<URL>",
 "agent-tgx2": "<URL>", "monitor-backup": "<URL>"}
EOF
"${EDITOR:-nano}" "$d/hc.json"; docker secret create tgxmon_hc_urls "$d/hc.json"

# Security canaries that name a live hole (private; e-mail and Slack only). YAML list of
# targets in the catalogue format; empty until there is one.
printf '[]\n' | docker secret create tgxmon_private_checks -

# Slack: Egon creates the real one. Until then a placeholder, so the stack deploys.
# A placeholder is a single newline: read as "not configured", never as a value.
# The same works for any secret you do not have yet (e.g. tgxmon_smtp before the mailbox).
printf '\n' | docker secret create tgxmon_slack_webhook -

shred -u "$d"/*; rmdir "$d"
docker secret ls --filter name=tgxmon_
```

Placeholders that exist only so the stack can deploy: `tgxmon_slack_webhook` (`unset`)
and, until the mailbox exists, `tgxmon_smtp`. Replace them with the rotation recipe:

```bash
# rotate or replace: create _v2, point the service at it under the old name, drop the old
docker secret create tgxmon_smtp_v2 "$d/smtp.json"
docker service update --secret-rm tgxmon_smtp \
  --secret-add source=tgxmon_smtp_v2,target=tgxmon_smtp tgx-monitor_core
docker secret rm tgxmon_smtp
```

(`stack.yml` still names `tgxmon_smtp`; on the next `docker stack deploy` either rename
the secret in `stack.yml` in a commit, or recreate `tgxmon_smtp` from the new value.)

## 4. Clone and pin the image

```bash
ssh tgx1
git clone https://github.com/TGX-UM/tgx-monitor.git ~/tgx-monitor   # later: git pull
cd ~/tgx-monitor
SHA=<7-char sha of the commit to deploy>   # git rev-parse --short=7 origin/main
sed -i "s|ghcr.io/tgx-um/tgx-monitor:latest|ghcr.io/tgx-um/tgx-monitor:sha-${SHA}|" stack.yml
```

Deploying a sha tag rather than `:latest` means `docker service inspect` always says
which commit runs. The clone is needed only for `stack.yml`; nothing is built here.

## 5. First deploy: shadow mode, no Traefik routers

```bash
docker stack deploy -c stack.yml tgx-monitor
```

What this gives you:

- `TGXMON_DRY_RUN=1` on core and the agents: every check runs and is recorded, every
  notification is rendered into the outbox and marked dry-run, **nothing is sent**.
- `traefik.enable=false` on core and public: Traefik ignores both until the A records
  exist. Adding a Host rule before DNS points here makes the HTTP-01 challenge loop,
  and the `*.vhp4safety.nl` GitHub Pages wildcard would answer it instead.

## 6. Verify

```bash
docker service ls --filter name=tgx-monitor_
#   tgx-monitor_core          1/1
#   tgx-monitor_public        1/1
#   tgx-monitor_agent         global 2/2
#   tgx-monitor_docker-proxy  global 2/2
docker service ps tgx-monitor_core --no-trunc        # ERROR column if not running
docker service logs --tail 50 tgx-monitor_core

# the scheduler ticks (run on the node that holds the core task)
docker exec "$(docker ps -q -f name=tgx-monitor_core)" \
  python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/livez').read())"

# the catalogue in the running image is clean
docker exec "$(docker ps -q -f name=tgx-monitor_core)" tgx-monitor doctor
```

**Cross-node traffic on the encrypted overlays.** `tgxmon_int` and `tgxmon_dockerapi`
are encrypted (IPsec ESP between the nodes). The host firewall
(`architecture/firewall-design.md`) opens UDP 4789 between the nodes but does not list
ESP (IP protocol 50); no other network on this cluster is encrypted, so this is the
first test of it. Check that core reaches the agent and the proxy **on the other node**:

```bash
docker exec "$(docker ps -q -f name=tgx-monitor_core)" python - <<'EOF'
import socket, urllib.request
for name, port, path in (("tasks.agent", 8001, "/livez"), ("tasks.docker-proxy", 2375, "/v1.47/info")):
    for ip in sorted({a[4][0] for a in socket.getaddrinfo(name, port)}):
        try:
            r = urllib.request.urlopen(f"http://{ip}:{port}{path}", timeout=5)
            print(name, ip, r.status)
        except Exception as e:
            print(name, ip, "FAILED", type(e).__name__, e)
EOF
```

Two answers per name means both nodes work. If only the local node answers, ESP is
blocked: ask Egon to allow it between the two node addresses
(`iptables -A INPUT -p esp -s <peer-ip> -j ACCEPT` on each node, persisted in the
firewall script). Do not drop `encrypted`: these overlays cross the public internet.

**The private UI before DNS** goes through an SSH tunnel and a throwaway relay on the
attachable `core` network:

```bash
ssh -L 18000:127.0.0.1:18000 tgx1 \
  'docker run --rm --network core -p 127.0.0.1:18000:18000 alpine/socat:1.8.0.3 \
     tcp-listen:18000,fork,reuseaddr tcp:tgx-monitor_core:8000'
# then http://127.0.0.1:18000/ ; Ctrl-C removes the relay
```

## 7. Shadow period (two weeks)

Leave it sending nothing for two weeks and tune: the M3 exit criterion is fewer than
five would-be notifications a day. Each day, in the private UI: the outbox (dry-run rows
are what *would* have gone out), the noisiest checks, and `unknown` results (missing
secrets, rate limits). Fix checks by pull request; failures that are real but owned
elsewhere go to `catalogue/known_issues.yaml` with an owner and an expiry.

## 8. DNS, then the Traefik routers

Once Egon's A records resolve:

```bash
dig +short status.cloud.vhp4safety.nl  @1.1.1.1    # 81.169.246.233
dig +short monitor.cloud.vhp4safety.nl @1.1.1.1    # 81.169.246.233
```

change `traefik.enable=false` to `true` for **both** `core` and `public` in `stack.yml`,
in a commit on `main` (so the next deploy does not undo it), then on tgx1:

```bash
cd ~/tgx-monitor && git pull && sed -i "s|tgx-monitor:latest|tgx-monitor:sha-${SHA}|" stack.yml
docker stack deploy -c stack.yml tgx-monitor
curl -sI https://status.cloud.vhp4safety.nl/ | head -1           # 200 (after the first snapshot)
curl -s  https://status.cloud.vhp4safety.nl/status.json | head -c 300
curl -sI https://monitor.cloud.vhp4safety.nl/login | head -1     # 200
curl -s -o /dev/null -w '%{http_code}\n' https://monitor.cloud.vhp4safety.nl/api/push/x  # 404: not routed
```

`/api/push` is deliberately not routed: cron jobs reach `http://tgx-monitor_core:8000`
over `core`, and the app rejects any push that carries forwarding headers.

## 9. The outside probe and the browser checks

In the repository settings, add the variable `OUTSIDE_PROBE_ENABLED` = `true`, then run
"Outside probe" once by hand (Actions tab, Run workflow) and check its summary is green.
Run "Browser checks" by hand once; it creates the `history` branch with
`browser/latest.json`.

## 10. Enabling alerts

Order matters, because every channel must be proven before anyone relies on it:

1. **GitHub issues** first (they need nothing from Egon):

   ```bash
   docker service update --env-add TGXMON_DRY_RUN=0 tgx-monitor_core
   docker exec "$(docker ps -q -f name=tgx-monitor_core)" \
     tgx-monitor test-alert --channel github --to marvinm2,egonw --who marvinm2
   ```

   Expect an issue labelled `test` from `tgx-monitor[bot]` mentioning both, closed by
   itself after 5 minutes; the outbox shows reply `201`.
2. **E-mail**, once `tgxmon_smtp` holds the real mailbox: `test-alert --channel smtp --who marvinm2`;
   reply `250`. Fallback if the Strato mailbox is not possible: a dedicated Gmail
   account with an app password (`smtp.gmail.com`, 587, `starttls: true`).
3. **Slack**, only after Icinga's Slack output is muted (otherwise the channel stays
   unreadable) and Egon has created the real `tgxmon_slack_webhook`:
   `test-alert --channel slack --who marvinm2`; reply `200`.
4. **Agents and healthchecks**: `docker service update --env-add TGXMON_DRY_RUN=0 tgx-monitor_agent`.
5. Commit `TGXMON_DRY_RUN: "0"` in `stack.yml` (core and agent), so a redeploy keeps it.
6. Run the live broken-check drill (RUNBOOK.md, "Drills").

## Update

```bash
# 1. merge to main, wait for "Docker image" to go green
gh run watch "$(gh run list --workflow=docker.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
# 2. roll each service onto the commit's tag
SHA=$(git rev-parse --short=7 origin/main)
for s in core public agent; do
  ssh tgx1 "docker service update --image ghcr.io/tgx-um/tgx-monitor:sha-${SHA} tgx-monitor_${s}"
done
# 3. verify: livez as in step 6; the private UI header shows the catalogue sha
```

Core updates `stop-first` (never two writers on the SQLite file), so expect about a
minute without checks; the agents and the outside probe cover that minute.

## Rollback

The same command with the previous sha:

```bash
ssh tgx1 "docker service update --image ghcr.io/tgx-um/tgx-monitor:sha-<previous> tgx-monitor_core"
```

The monthly `docker system prune` removes unused images, so a rollback may pull again;
GHCR keeps every sha tag. A failed core update rolls itself back
(`update_config.failure_action: rollback`). The database schema only grows, so an older
image reads a newer database. To stop alerting at once without a rollback:
`docker service update --env-add TGXMON_DRY_RUN=1 tgx-monitor_core`.

## Backups of the monitor itself

- Nightly, core writes `data/backups/monitor-<date>.db` and its manifest (14 kept).
  By hand: `docker exec <core> tgx-monitor backup /data/backups`.
- A root job in `TGX-UM/cronjobs` (private image, `--with-registry-auth`) copies the
  newest one to `/mnt/hidrive/docker/tgx-monitor/` daily (14 daily, 8 weekly) and pings
  `hidrive-copy`; a weekly one runs `tgx-monitor restore-verify <copy>` with the HiDrive
  directory mounted read-write and pings `restore-verify`. Add both to
  `operations/cronjobs.md` and `operations/backup-strategy.md`.

## After the deploy: documentation

- `services/tgx-monitor.md` on the cluster (from this file and RUNBOOK.md) and its row
  in `services/service-registry.md`;
- `operations/cronjobs.md` (HiDrive copy, restore-verify) and `operations/backup-strategy.md`;
- `AGENTS.md`: cluster admin is Egon, not Sean;
- the restore drill and the watchdog drill, with dates, in `services/tgx-monitor.md`.

## Steps that need Egon

One batched request, LO-TGX in cc:

1. **A records** `status.cloud.vhp4safety.nl` and `monitor.cloud.vhp4safety.nl` →
   81.169.246.233, before the Traefik rules go in (step 8).
2. **`tgxmon_slack_webhook`**: an incoming webhook for `#monitoring_alerts`, created with
   `docker secret create` (replacing the placeholder, see the rotation recipe).
3. **Review and install `host/tgx-monitor-status.sh`** as a 5-minute root cron on both nodes:
   Gluster heal and split-brain, `mdadm --detail`, `smartctl -H`, `df -i`, NTP and
   reboot-required, written world-readable to `/mnt/gluster/docker/tgx-monitor/root-status/<host>.json`.
   The agents start without it and report the root signals as missing until it runs.
4. **ESP between the nodes** if step 6 shows the encrypted overlays cannot cross nodes.
5. **Mute Icinga's Slack output now**; retire the Icinga stack (behind on security
   releases) once tgx-monitor covers its checks.
6. **The `monitor@vhp4safety.nl` mailbox** in the Strato panel, so SPF and DMARC align.
7. Independent of this project, and urgent: re-add the degraded `md1` on TGX1
   (`mdadm --re-add`, then `smartctl`).
