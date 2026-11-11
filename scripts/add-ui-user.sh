#!/usr/bin/env bash
# Add (or reset) a login for the private monitor UI.
#
# Run it on the swarm node where tgx-monitor_core runs, as the person whose login it is:
#   /mnt/gluster/docker/tgx-monitor/deploy/scripts/add-ui-user.sh <github-handle>
# The password is typed here, hashed with argon2 inside the monitor image and never shown
# or written to disk. The existing users are carried over from the running core into a new
# secret version tgxmon_users_v<n+1>, and core is pointed at it (a stop-first restart of
# about 30 seconds). Afterwards set that name in stack.yml so the next deploy keeps it.
# Roles come from catalogue/owners.yaml, not from here.
set -euo pipefail

handle="${1:?usage: add-ui-user.sh <github-handle>}"
[[ "$handle" =~ ^[A-Za-z0-9-]{1,39}$ ]] || { echo "not a GitHub handle: $handle" >&2; exit 2; }

svc=tgx-monitor_core
cid=$(docker ps -q -f "name=${svc}." | head -1)
if [ -z "$cid" ]; then
  echo "core does not run on this node; run the script on:" >&2
  docker service ps "$svc" --filter desired-state=running --format '  {{.Node}}' >&2
  exit 1
fi
image=$(docker service inspect "$svc" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')
current=$(docker service inspect "$svc" --format \
  '{{range .Spec.TaskTemplate.ContainerSpec.Secrets}}{{if eq .File.Name "tgxmon_users"}}{{.SecretName}}{{end}}{{end}}')
n=$(sed -n 's/^tgxmon_users_v\([0-9]*\)$/\1/p' <<<"$current")
next="tgxmon_users_v$(( ${n:-1} + 1 ))"
if docker secret inspect "$next" >/dev/null 2>&1; then
  echo "$next already exists; remove it or finish the earlier run first" >&2
  exit 1
fi

read -rsp "New password for $handle (12+ characters): " p1; echo
read -rsp "Again: " p2; echo
if [ "$p1" != "$p2" ] || [ "${#p1}" -lt 12 ]; then
  unset p1 p2
  echo "the passwords differ or are shorter than 12 characters" >&2
  exit 2
fi
hash=$(printf %s "$p1" | docker run --rm -i "$image" \
  python -c 'import sys, argon2; print(argon2.PasswordHasher().hash(sys.stdin.read()))')
unset p1 p2

# First line: the new hash; the rest: the users JSON core reads now (empty if a placeholder).
{ printf '%s\n' "$hash"; docker exec "$cid" cat /run/secrets/tgxmon_users; } |
  docker run --rm -i -e HANDLE="$handle" "$image" python -c '
import json, os, sys
new, _, rest = sys.stdin.read().partition("\n")
users = json.loads(rest) if rest.strip() else {}
if not isinstance(users, dict):
    sys.exit("current tgxmon_users is not a JSON object; not touching it")
users[os.environ["HANDLE"]] = new.strip()
print(json.dumps(users, indent=1, sort_keys=True))
' | docker secret create "$next" - >/dev/null
unset hash

docker service update --quiet --detach=false \
  --secret-rm "$current" --secret-add "source=$next,target=tgxmon_users" "$svc" >/dev/null
echo "Login for $handle saved; core now reads $next (was $current)."
echo "Next: in stack.yml set  tgxmon_users: {external: true, name: $next}  and commit,"
echo "then remove the old secret: docker secret rm $current"
