# docker-proxy: the GET-only Docker API for tgx-monitor

Core needs to read swarm state (services, tasks, nodes, task logs, events) and, per node,
images and containers. Whoever can talk to `/var/run/docker.sock` is root on that node, so
core never mounts it. Instead each node runs
[wollomatic/socket-proxy](https://github.com/wollomatic/socket-proxy) in global mode, and
core talks to it over a private, encrypted, internal overlay.

## What the proxy allows

Only `GET`, and only these paths (the proxy adds `^` and `$` itself and matches the
path, not the query string):

```
-allowGET=/v1\.(4[4-9]|5[0-3])/(info|nodes|services|tasks|events|images/json|containers/json|tasks/[a-z0-9]+/logs)
```

This is `tgx_monitor.docker.ALLOWED_PATHS`, character for character.
`tests/test_proxy_contract.py` fails if the two differ, if `DockerAPI` requests anything
outside the pattern, or if the pattern lets through any of the refused paths below.

Refused on purpose, and why:

| Path | Why it stays closed |
|---|---|
| `/containers/<id>/json`, `/services/<id>`, `/tasks/<id>` | full inspect output: environment, mounts, secrets references |
| `/containers/<id>/archive`, `/containers/<id>/export` | read any file in a container |
| `/secrets`, `/configs` | swarm secrets and configs metadata |
| `/images/<x>/get` | image export (layers can hold build secrets) |
| `/exec`, `/containers/<id>/exec` | command execution |
| `/services/<id>/logs` | not needed: task logs cover the cron jobs |
| any `POST`, `PUT`, `DELETE`, `HEAD` | read-only; no other `-allow<METHOD>` flag is set |

`/services` and `/tasks` list responses still carry `ContainerSpec.Env` in plain text.
`tgx_monitor.docker` passes every answer through `redact.redact_spec` before anything
else sees it.

## Stack fragment

Part of `stack.yml` (stack `tgx-monitor`). Pin the digest at deploy time.

```yaml
services:
  docker-proxy:
    image: wollomatic/socket-proxy:1.13.2@sha256:<digest>
    command:
      - '-loglevel=info'
      - '-listenip=0.0.0.0'
      - '-proxyport=2375'
      - '-allowfrom=tasks.tgx-monitor_core'
      - '-allowGET=/v1\.(4[4-9]|5[0-3])/(info|nodes|services|tasks|events|images/json|containers/json|tasks/[a-z0-9]+/logs)'
      - '-watchdoginterval=600'
      - '-stoponwatchdog'
      - '-shutdowngracetime=5'
      - '-allowhealthcheck'
    user: "65534:1000"            # nobody, group docker (gid 1000 on tgx1 and tgx2)
    read_only: true
    cap_drop: [ALL]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [dockerapi]
    healthcheck:
      test: ["CMD", "./healthcheck"]
      interval: 60s
      timeout: 5s
      retries: 3
    deploy:
      mode: global
      resources:
        limits: {memory: 64M}
      restart_policy: {condition: any}

  core:
    networks: [core, int, dockerapi]
    environment:
      TGXMON_DOCKER_PROXY: tasks.docker-proxy   # one A record per node
      TGXMON_DOCKER_API: v1.47

networks:
  dockerapi:
    name: tgxmon_dockerapi
    driver: overlay
    internal: true
    driver_opts: {encrypted: "true"}
```

Notes:

- No host port, no Traefik labels, no node pin. `internal: true` means the overlay has no
  route out, and only `core` and `docker-proxy` join it. The agent never does.
- `-allowfrom` names `tasks.tgx-monitor_core`, not `tgx-monitor_core`: the plain service
  name resolves to the service VIP, but connections arrive from the task IP.
- The socket is mounted read-only. That does not make the API read-only (a socket is
  a socket), which is why the allowlist is the boundary.
- `security_opt: no-new-privileges` is ignored by `docker stack deploy`, so it is left out.

## How core finds the proxies

`DockerAPI` resolves `TGXMON_DOCKER_PROXY` (default `tasks.docker-proxy`) to one IP per
proxy task, calls `GET /info` on each and maps the answering engine's hostname to a node
alias (`h3068544` is tgx1, `h2973005` is tgx2). Swarm-wide calls go to tgx1 first and fall
over to tgx2. Images, containers and events are asked of the node they concern.

## Checks at M4 (live, from inside core)

```sh
docker exec $(docker ps -q -f name=tgx-monitor_core) getent hosts tasks.docker-proxy   # two IPs
# expected 200
GET http://<proxy-ip>:2375/v1.47/info
GET http://<proxy-ip>:2375/v1.47/tasks
# expected 403
GET  /v1.47/containers/<id>/json   /v1.47/containers/<id>/archive?path=/etc
GET  /v1.47/containers/<id>/export /v1.47/secrets  /v1.47/configs  /v1.47/images/<x>/get
POST /v1.47/containers/create
```

Then restart core (`docker service update --force tgx-monitor_core`) and repeat the first
`GET`: it must still answer 200 with core's new task IP. If it answers 403, the proxy
resolved `-allowfrom` only at start; switch `-allowfrom` to the subnet of
`tgxmon_dockerapi` (give the network a fixed `ipam` subnet) and repeat.

If `tasks.docker-proxy` does not resolve inside core, set
`TGXMON_DOCKER_PROXY=tasks.tgx-monitor_docker-proxy`.
