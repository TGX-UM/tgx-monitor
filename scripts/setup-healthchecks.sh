#!/usr/bin/env bash
# Create (or update) the monitor's healthchecks.io checks and hand their ping URLs to the
# places that ping them, without printing a URL or the API key.
#
# Run on your own machine (needs curl, jq, ssh access to tgx1 and gh logged in):
#   scripts/setup-healthchecks.sh
# It asks for a read-write API key of the healthchecks.io project (Settings -> API Access).
# Checks are matched by name, so running it again updates them instead of duplicating.
# Every check notifies all of the project's integrations (add the e-mail addresses there).
#
# Results:
#   - Docker secret tgxmon_hc_urls_v<n> on the swarm ({name: ping URL}), swapped into
#     tgx-monitor_core, tgx-monitor_agent and cronjobs_tgx-monitor-offsite (restarts them;
#     update the secret name in both stack files afterwards);
#   - GitHub Actions secret HC_PROBE_URL and variable OUTSIDE_PROBE_ENABLED=true on
#     TGX-UM/tgx-monitor, which starts the outside probe.
set -euo pipefail

API=https://healthchecks.io/api/v3/checks/
REPO=TGX-UM/tgx-monitor
# name | period (s) | grace (s) | what pings it
CHECKS=$(cat <<'EOF'
core-cycle|300|600|core, every 2 min while its scheduler completes cycles; /fail when stalled
delivery-watchdog|300|600|core, every 5 min through the real alert outbox
agent-tgx1|60|300|agent on tgx1, every minute; /fail when core's or the peer's heartbeat is stale
agent-tgx2|60|300|agent on tgx2, every minute; /fail when core's or the peer's heartbeat is stale
gha-probe|1200|21600|GitHub Actions probe.yml (outside the cluster), every 20 min
monitor-backup|86400|21600|core, nightly after its database backup
hidrive-copy|86400|21600|cronjobs_tgx-monitor-offsite, nightly copy to HiDrive, checked on arrival
EOF
)

for tool in curl jq ssh gh; do
  command -v "$tool" >/dev/null || { echo "needs $tool" >&2; exit 1; }
done
read -rsp "healthchecks.io API key (read-write, project TGX monitor): " key; echo
[ -n "$key" ] || { echo "no key" >&2; exit 2; }

urls='{}'
while IFS='|' read -r name timeout grace desc; do
  body=$(jq -n --arg n "$name" --arg d "$desc" --argjson t "$timeout" --argjson g "$grace" \
    '{name: $n, desc: $d, timeout: $t, grace: $g, channels: "*",
      tags: "tgx-monitor", unique: ["name"]}')
  resp=$(curl -sS -w '\n%{http_code}' -X POST "$API" -H "X-Api-Key: $key" \
    -H 'Content-Type: application/json' --data "$body")
  code=${resp##*$'\n'}; json=${resp%$'\n'*}
  case "$code" in
    200|201) ;;
    *) unset key; echo "$name: healthchecks.io answered HTTP $code" >&2; exit 1 ;;
  esac
  url=$(jq -r '.ping_url // empty' <<<"$json")
  [ -n "$url" ] || { unset key; echo "$name: no ping_url in the answer" >&2; exit 1; }
  urls=$(jq --arg n "$name" --arg u "$url" '. + {($n): $u}' <<<"$urls")
  echo "  $name: $([ "$code" = 201 ] && echo created || echo updated) (period ${timeout}s, grace ${grace}s)"
done <<<"$CHECKS"
unset key

# The outside probe's URL goes to GitHub only; the rest to the swarm.
jq -r '."gha-probe"' <<<"$urls" | gh secret set HC_PROBE_URL -R "$REPO" >/dev/null
echo "  GitHub secret HC_PROBE_URL set on $REPO"

new=$(jq 'del(."gha-probe")' <<<"$urls")
unset urls
# Create the next secret version and swap it into every service that pings, all on tgx1.
printf '%s' "$new" | ssh tgx1 'set -euo pipefail
  current=$(docker service inspect tgx-monitor_core --format \
    "{{range .Spec.TaskTemplate.ContainerSpec.Secrets}}{{if eq .File.Name \"tgxmon_hc_urls\"}}{{.SecretName}}{{end}}{{end}}")
  n=$(sed -n "s/^tgxmon_hc_urls_v\([0-9]*\)$/\1/p" <<<"$current")
  next="tgxmon_hc_urls_v$(( ${n:-1} + 1 ))"
  docker secret create "$next" - >/dev/null
  for svc in tgx-monitor_core tgx-monitor_agent cronjobs_tgx-monitor-offsite; do
    docker service update --quiet --detach --secret-rm "$current" \
      --secret-add "source=$next,target=tgxmon_hc_urls" "$svc" >/dev/null
    echo "  $svc now reads $next"
  done
  echo "  (was ${current:-none}; stack files still say the old name until updated)"'
unset new

# The outside probe: its schedule starts once this variable is true.
gh variable set OUTSIDE_PROBE_ENABLED --body true -R "$REPO" >/dev/null
echo "  GitHub variable OUTSIDE_PROBE_ENABLED=true on $REPO"
echo "Done. Checks turn green on healthchecks.io within a few minutes (gha-probe within 20,"
echo "monitor-backup and hidrive-copy after their next nightly run)."
