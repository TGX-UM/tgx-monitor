# When an alert arrives

Every alert names a **target** (a service, endpoint, job, backup or node) and links to
the private page `https://monitor.cloud.vhp4safety.nl/check/<check-id>`. Start there: it
shows the exact request, each assertion with what was expected and what was found, how
long it has been failing, the dependency path, and the delivery log. Nothing in this
runbook needs root unless it says "Egon".

Commands below run inside core (`docker exec -it "$(docker ps -q -f name=tgx-monitor_core)" <cmd>`
on the node that holds the core task; `docker service ps tgx-monitor_core` says which).

## First: is it real?

1. **Is the monitor itself healthy?** The private UI header shows the last scheduler
   tick and the outbox age. If many unrelated targets went red at once, look for the
   single `monitor-vantage-degraded` alert: core lost its own network view (DNS,
   GitHub, 1.1.1.1 unreachable), and the per-target alerts are held back on purpose.
2. **Reproduce it** from the per-check page's copyable `curl`, or run the check once:
   `tgx-monitor check --once --only <check-id> -v`.
3. **Inside a maintenance window?** Results during a window are recorded, not sent. A
   check still failing when the window closes alerts at once: that usually means the
   reload or switch it covers did not finish.

## What each alert means

### GitHub issue `[<target>] <check> failing`

One issue per failing **root** target, opened by `tgx-monitor[bot]`, mentioning the
target's owners (and `@egonw` for infra, backup and security, or after 2 h of an
unacknowledged critical). It lists every failing check of that target; children of a
failing dependency are listed as BLOCKED and send nothing themselves. It closes itself
after two passing runs, with the outage duration; a relapse within 24 h reopens it.

What to do depends on the kind of the failing check:

| Kind | Usually means | First move |
|---|---|---|
| `http` | wrong status, missing content marker, a new redirect (parking page, moved service) | the redirect chain and final URL on the check page; `docker service ps <svc>` |
| `tls` | certificate near expiry, or the Traefik default (self-signed) certificate on one node | `ssh tgx1 'docker service logs traefik_traefik --since 1h \| grep -i acme'`; a default cert on one node only means that node lacks the router |
| `dns` | an A record no longer points at tgx1, or a dangling record | compare with `architecture/dns-inventory.md`; DNS changes are Egon's |
| `sparql` | endpoint down, or the data shrank or vanished (empty store, a failed reload) | row counts on the check page against the baseline; the endpoint's reload job in `job_runs` |
| `invariant`, `compare` | two numbers that must agree do not; a reload did not land; a release lacks files | which side moved; for WikiPathways, whether the upstream release is complete before blaming the store |
| `roundtrip` | a multi-step API answer changed (BridgeDb wire format, a known answer drifted) | the step that failed and its captured values; check for a new image of the service |
| `shiny` | the app serves 200 but sessions do not start | the service's logs; memory (OOM kills) |
| `browser_artifact` | a JS-heavy page renders empty, or the Playwright run stopped (artifact old) | the page entry in `browser/latest.json` on the `history` branch; the "Browser checks" workflow |
| `job_run` | a cron job did not run, failed, or ran out of order (switch without reload) | `docker service ps cronjobs_<job>`; its log markers on the check page |
| `file_age`, `sqlite_backup`, `restore_marker` | a backup is stale, too small, does not open, or `missing` (none exists) | the job that writes it; for `missing`, a backup has to be built, which is a task, not a fix |
| `swarm` | replicas short, crash loop, a node-pinned or local-only image that cannot fail over | `docker service ps --no-trunc <svc>`, the ERROR column |
| `host` | RAID degraded, disk or inodes full, memory, a node or peer port unreachable | Egon for RAID, SMART and Gluster heal; `df -h` and `docker system df` for disk |
| `gha` | a pipeline that feeds a service failed or was disabled for inactivity | the workflow run; re-enable in the Actions tab |
| `registry` | an image manifest or the read PAT stopped working, or an image is missing on a node | `docker manifest inspect`; PAT expiry in the `self` check |
| `digest_drift` | a `:latest` service runs different code than a week ago (information) | nothing, unless it coincides with another failure |
| `security` | an admin page or debug server is reachable that must not be | fix the exposure first; see "Security alerts" |
| `docs_drift` | the cluster docs disagree with the live services (weekly, never pages) | fix the docs in `/mnt/gluster/documentation/` |
| `self` | the monitor's own health: tick, outbox, vantage, token or App-key expiry | see "Alerts about the monitor" |

### E-mail and Slack

Critical (high) targets e-mail the owners and Marvin at once and post one Slack line;
warnings (medium) go into the 08:00 Europe/Amsterdam digest mail and post on open and
recovery; info (low) is a weekly digest and a daily Slack one-liner. Muted targets are
recorded only. More than 8 sends per channel per minute collapse into one summary;
Slack is capped at 20 messages an hour, so a storm shows as one "N more" line.

### Security alerts

Checks that name a live hole come from the private `tgxmon_private_checks` secret and
alert by **e-mail and Slack only**, never in a public issue. Do not describe the hole in
any public place (issues, commits, PR text) until it is closed. Once fixed, move the
canary into the public catalogue as a regression check (`class: security`) and delete it
from the private secret.

### Alerts about the monitor

| Alert (healthchecks.io e-mail unless noted) | Means | Do |
|---|---|---|
| `core-cycle` down | no complete scheduler cycle for 10 min: core is dead, stuck or restarting | `docker service ps tgx-monitor_core`; logs; `/livez` |
| `delivery-watchdog` down | the outbox stopped delivering (the synthetic notification did not arrive) | `tgx-monitor outbox --dead`; channel secrets; the dispatcher in the logs |
| `agent-tgx1` / `agent-tgx2` down or `/fail` | that node's agent is gone, or it sees core's or the peer's heartbeat older than 5 min | the reason is in the ping body; a stale *peer* heartbeat with core fine points at Gluster |
| `gha-probe` down | the outside probe has not run for 6 h (schedule disabled, Actions outage) | Actions tab: enable "Outside probe", run it by hand |
| `root-status-tgx*` down | Egon's root cron stopped writing `status.json` | Egon |
| `monitor-backup`, `hidrive-copy`, `restore-verify` down | the monitor's own backup chain broke | see "Backups" in DEPLOY.md; run the step by hand |
| issue **Outside probe: cluster unreachable or stale** (label `outside-probe`) | from GitHub's runners, `status.json` is older than 15 min or unreachable through a node, the status hostname left tgx1, or several sentinels fail on one node | see below |
| `self` check, "channel X failing" | one channel keeps failing (e.g. SMTP 535, Slack 404); the alert goes out on the other two | fix the secret (rotation recipe in DEPLOY.md), then `outbox --dead` to see what was lost |

**Outside probe issue.** Its body lists what failed, per node. Stale `status.json` on
both nodes with the sentinels fine: core or public is down (check `core-cycle` too).
Everything failing through one node: that node's Traefik or Docker is down; with two
managers, one node's Docker going down freezes the swarm, and if it is tgx1 every
domain is down (`ssh tgx1 'systemctl is-active docker; timeout 15 systemctl is-system-running'`;
Egon for a reboot). The issue closes itself on the first green run.

## Silence, acknowledge, known issue

- **Acknowledge** an incident when someone is on it: stops the 2 h escalation to Egon,
  nothing else. UI button on the incident, or `tgx-monitor ack <incident-id> --who <handle>`.
- **Silence** when you know it will fail and why (a planned migration, a redeploy):
  `tgx-monitor silence add <target> [--check <id>] --reason "<why>" --until 4h --who <handle>`.
  Every silence has a reason, an expiry and a name; owners can silence only their own
  targets, admins any. `silence list`, `silence rm <id> --who <handle>`.
- **Known issue** when it is broken, owned and will stay broken for a while: a pull
  request adding it to `catalogue/known_issues.yaml` with `owner`, `reason`, `until` (a
  date) and ideally a `ticket`. It shows on the page and alerts again after `until`, so
  nothing is forgotten.
- **Maintenance window** for recurring work: `catalogue/maintenance.yaml` (RRULE, UTC).

Never "fix" a noisy check by deleting it or loosening it until it cannot fail. Change
the threshold with a reason in the pull request, or mark it a known issue.

## Drills

Record the date and the result of each in `services/tgx-monitor.md` on the cluster.

### Live broken check (after enabling alerts, then monthly; automated later)

```bash
tgx-monitor test-incident --break      # monitor-selftest goes red
# within 3 cycles + the 2 min hold: an issue from tgx-monitor[bot] mentioning the owners,
# a mail, a Slack line; outbox replies 201 / 250 / 200
tgx-monitor test-incident --fix        # two passes later: closed with duration, recovery mail and line
```

Repeat once with the selftest target's class set to `infra` to prove the Egon cc.

### Watchdog drill (quarterly)

```bash
ssh tgx1 'docker service scale tgx-monitor_core=0'
# wait 20 min. Expect: core-cycle and delivery-watchdog alert by e-mail, both agents
# send /fail ("core heartbeat stale"), the next outside-probe run opens its issue.
ssh tgx1 'docker service scale tgx-monitor_core=1'
# expect: all of it recovers, the outside-probe issue closes itself.
```

Then disable "Outside probe" in the Actions tab: `gha-probe` must alert within its 6 h
grace. Enable it again.

### Restore drill (twice a year)

Losing the database loses history only: checks, owners and windows live in git and
baselines rebuild from the rollups. The drill proves the history comes back.

```bash
ssh tgx1
B=/mnt/gluster/docker/tgx-monitor/data/backups
ls -t $B/monitor-*.db | head -1                          # newest backup
docker service scale tgx-monitor_core=0                 # one writer: stop it first
cp /mnt/gluster/docker/tgx-monitor/data/monitor.db ~/monitor.db.before-restore
cp "$(ls -t $B/monitor-*.db | head -1)" /mnt/gluster/docker/tgx-monitor/data/monitor.db
docker service scale tgx-monitor_core=1
docker exec "$(docker ps -q -f name=tgx-monitor_core)" \
  tgx-monitor restore-verify "/data/backups/$(ls -t $B/monitor-*.db | head -1 | xargs basename)"
# ok: true, counts equal to the manifest
```

After start-up the reconcile loop adopts open GitHub issues through their
`<!-- tgxmon:incident=... -->` markers, so no issue is orphaned or duplicated; check
the incident list against the open `alert` issues. The weekly `restore-verify` job does
the integrity half of this on the HiDrive copy every week; this drill adds the actual
swap.

## Owners

### Adding an owner

1. Pull request to `catalogue/owners.yaml`: their GitHub handle under `people` with
   `name` and `notify: false`. Someone without a GitHub account gets the next opaque
   alias (`ext-04`, ...) with `github: false`; they will get e-mail only.
2. Put the handle in the `owners` of their targets.
3. Open an onboarding issue mentioning them: what tgx-monitor checks on their targets
   (link the per-target page), what an alert looks like, and the question "may we
   notify you? Reply here, or react with a thumbs-up". Nothing is sent to them before
   they say yes. Until then alerts for their targets go to the fallback (`marvinm2`).

### Onboarding an owner who opted in

1. Their e-mail address into `tgxmon_contacts` (never into git). A Docker secret
   cannot be read back, so keep its source JSON in a private place (a password
   manager), add the address there, and rotate the secret (DEPLOY.md, rotation recipe).
2. Pull request: `notify: true` for them in `catalogue/owners.yaml`.
3. If they want the private UI: an argon2 hash into `tgxmon_users` (DEPLOY.md step 3);
   their role follows from `owners.yaml` (their own targets; admins everything).
4. `tgx-monitor test-alert --channel all --to <handle> --who marvinm2` and ask them to
   confirm on the onboarding issue that the issue mention and the mail arrived; close it.

### Removing an owner

The reverse, in one pull request; remove their address from `tgxmon_contacts` and their
hash from `tgxmon_users` (rotation). A target must keep at least one owner (`doctor`
refuses otherwise); use the fallback explicitly.
