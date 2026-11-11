"""Swarm and cron-job checks: ``swarm``, ``job_run``, ``digest_drift``, ``docs_drift``.

All of them read the Docker API through :class:`~tgx_monitor.docker.DockerAPI` (the
GET-only proxy), so they run from core only: ``via: [core]``.

Why these exist, each from a real incident:

* ``swarm`` -- a service at 0/1 after a clean exit under ``restart_policy: on-failure``
  (aopdb for 12 days in September, nanolinks on 2026-10-22); a crash loop that Traefik
  hides behind a 502; node pins and images that exist on one node only, so failover
  ends in "No such image" (xploreaop, robot, biodatafuse).
* ``job_run`` -- swarm-cronjob notifies no one. A missed or failed run, or a WikiPathways
  switch without a successful reload before it, is only visible if someone records each
  run before the five-task history rotates it away. :func:`record_job_runs` does that;
  the kind then judges the latest scheduled slot from the ``job_runs`` table.
* ``digest_drift`` -- ``:latest`` and ``:master`` pull new code on any reschedule while
  the spec looks unchanged. Informational.
* ``docs_drift`` -- ``service-registry.md`` going stale (arrayanalysis 0.1.4 vs 0.1.5).

Request keys
------------

``swarm``: ``check`` (replicas | crash_loops | placement | local_images | nodes |
restart_policy), ``services`` (glob list, default all), ``ignore`` (glob list);
crash_loops also ``window`` (1h), ``threshold`` (3).

``job_run``: ``service`` (required), ``grace`` (20m), ``marker_re`` (regex, group 1 is
exposed), ``after_success_of`` (another job), ``schedule`` (override the label; lets a
push-only job be checked without Docker).

``digest_drift``: ``services``, ``ignore``.  ``docs_drift``: ``mount`` (required),
``path`` (services/service-registry.md), ``aliases`` {doc name: live prefix}, ``ignore``.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import re
from collections import Counter, defaultdict
from typing import Any

from ..assertions import parse_duration
from ..catalogue import Check
from ..docker import TERMINAL_STATES, DockerAPI, DockerError, node_alias, parse_ts
from ..model import Call, Observation, iso
from ..redact import redact_text
from .base import Context, Kind, register

CRON_LABEL = "swarm.cronjob.enable"
SCHEDULE_LABEL = "swarm.cronjob.schedule"
OWNER_LABEL = "tgx.service.owner"
MARKER = re.compile(r"^TGXMON-MARKER\s+([A-Za-z0-9_.-]+)=(.*)$")
JOB_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
LOG_TAIL = 200
KILLED = {137, 139}  # OOM / SIGKILL, segfault


# ---------------------------------------------------------------------- small helpers
def _name(s: dict[str, Any]) -> str:
    return (s.get("Spec") or {}).get("Name", "")


def _labels(s: dict[str, Any]) -> dict[str, str]:
    return (s.get("Spec") or {}).get("Labels") or {}


def _is_cron(s: dict[str, Any]) -> bool:
    return _labels(s).get(CRON_LABEL) == "true"


def _image(s: dict[str, Any]) -> str:
    tt = (s.get("Spec") or {}).get("TaskTemplate") or {}
    return (tt.get("ContainerSpec") or {}).get("Image", "")


def _mode(s: dict[str, Any]) -> str:
    return next(iter((s.get("Spec") or {}).get("Mode") or {"Replicated": {}}), "Replicated")


def _selected(name: str, req: dict[str, Any]) -> bool:
    globs = req.get("services") or ["*"]
    return (any(fnmatch.fnmatchcase(name, g) for g in globs)
            and not any(fnmatch.fnmatchcase(name, g) for g in req.get("ignore") or []))


def split_image(ref: str) -> tuple[str, str, str]:
    """'ghcr.io/a/b:1.0@sha256:x' -> ('ghcr.io/a/b', '1.0', 'sha256:x'); Hub names short."""
    ref, _, digest = ref.partition("@")
    slash = ref.rfind("/")
    repo, tag = ref, ""
    if ref.rfind(":") > slash:
        repo, tag = ref.rsplit(":", 1)
    for prefix in ("docker.io/", "index.docker.io/"):
        repo = repo.removeprefix(prefix)
    return repo.removeprefix("library/"), tag, digest


# ---------------------------------------------------------------------- cron
_MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
_DAYS = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
_NAMES = {**{m: i for i, m in enumerate(_MONTHS, 1)}, **{d: i for i, d in enumerate(_DAYS)}}
_MACROS = {"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
           "@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
           "@hourly": "0 * * * *"}
_BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


def _field(text: str, lo: int, hi: int) -> set[int]:
    out: set[int] = set()
    for part in text.upper().split(","):
        rng, _, step = part.partition("/")
        if rng == "*":
            a, b = lo, hi
        elif "-" in rng:
            x, y = rng.split("-", 1)
            a, b = int(_NAMES.get(x, x)), int(_NAMES.get(y, y))
        else:
            a = b = int(_NAMES.get(rng, rng))
            if step:
                b = hi
        if not (lo <= a <= hi and lo <= b <= hi) or a > b:
            raise ValueError(f"cron field {text!r} out of range {lo}-{hi}")
        out.update(range(a, b + 1, int(step) if step else 1))
    return out


def parse_cron(expr: str) -> tuple[set[int], set[int], set[int], set[int], set[int], bool, bool]:
    """Five fields (a leading seconds field is dropped), UTC. Raises ValueError."""
    expr = _MACROS.get(expr.strip(), expr.strip())
    parts = expr.split()
    if len(parts) == 6:
        parts = parts[1:]
    if len(parts) != 5:
        raise ValueError(f"cron schedule {expr!r} needs 5 fields")
    sets = [_field(p, lo, hi) for p, (lo, hi) in zip(parts, _BOUNDS, strict=True)]
    dow = {d % 7 for d in sets[4]}
    return sets[0], sets[1], sets[2], sets[3], dow, parts[2] == "*", parts[4] == "*"


def cron_prev(expr: str, at: dt.datetime) -> dt.datetime:
    """The latest fire time <= ``at`` (minute resolution), searching back 400 days."""
    mins, hours, doms, months, dows, dom_any, dow_any = parse_cron(expr)
    at = at.astimezone(dt.UTC).replace(second=0, microsecond=0)
    day = at.replace(hour=0, minute=0)
    for _ in range(401):
        dom_ok, dow_ok = day.day in doms, (day.weekday() + 1) % 7 in dows
        # Vixie/robfig rule: both restricted -> either may match.
        day_ok = (dom_ok and dow_ok) if (dom_any or dow_any) else (dom_ok or dow_ok)
        if day.month in months and day_ok:
            for h in sorted(hours, reverse=True):
                for m in sorted(mins, reverse=True):
                    t = day.replace(hour=h, minute=m)
                    if t <= at:
                        return t
        day -= dt.timedelta(days=1)
    raise ValueError(f"cron schedule {expr!r} never fired in the last 400 days")


# ---------------------------------------------------------------------- swarm checks
async def _replicas(api: DockerAPI, req: dict[str, Any], calls: list[Call],
                    now: dt.datetime) -> dict[str, Any]:
    by, bad, cron_skipped = {}, [], []
    for s in await api.services(calls=calls):
        name = _name(s)
        if not _selected(name, req) or _mode(s) in ("ReplicatedJob", "GlobalJob"):
            continue
        st = s.get("ServiceStatus") or {}
        run, want = int(st.get("RunningTasks") or 0), int(st.get("DesiredTasks") or 0)
        if _is_cron(s) and run == 0 and want <= 1:
            cron_skipped.append(name)  # swarm-cronjob jobs rest at 0/0 or 0/1
            continue
        by[name] = {"running": run, "desired": want, "mode": _mode(s)}
        if run < want:
            bad.append(f"{name} {run}/{want}")
    return {"checked": len(by), "by": by, "not_converged": sorted(bad),
            "not_converged_count": len(bad), "cron_resting": sorted(cron_skipped)}


async def _crash_loops(api: DockerAPI, req: dict[str, Any], calls: list[Call],
                       now: dt.datetime) -> dict[str, Any]:
    window = parse_duration(req.get("window", "1h"))
    threshold = int(req.get("threshold", 3))
    names = {s["ID"]: _name(s) for s in await api.services(calls=calls)}
    fails: Counter[str] = Counter()
    codes: dict[str, list[int]] = defaultdict(list)
    killed = []
    for t in await api.tasks(calls=calls):
        st = t.get("Status") or {}
        name = names.get(t.get("ServiceID", ""), "")
        ts = parse_ts(st.get("Timestamp"))
        if (not name or not _selected(name, req) or st.get("State") not in ("failed", "rejected")
                or ts is None or (now - ts).total_seconds() > window):
            continue
        fails[name] += 1
        code = (st.get("ContainerStatus") or {}).get("ExitCode")
        if code is not None:
            codes[name].append(int(code))
            if int(code) in KILLED:
                killed.append(f"{name} exit {code} at {iso(ts)}")
    looping = sorted(f"{n}: {c} failures (exit {sorted(set(codes[n]))})"
                     for n, c in fails.items() if c >= threshold)
    return {"window": req.get("window", "1h"), "threshold": threshold,
            "failures": dict(fails), "failed_task_count": sum(fails.values()),
            "crash_looping": looping, "crash_looping_count": len(looping),
            "killed": sorted(killed), "killed_count": len(killed)}


def _pin_of(s: dict[str, Any]) -> str | None:
    cons = (((s.get("Spec") or {}).get("TaskTemplate") or {}).get("Placement") or {}).get(
        "Constraints") or []
    for c in cons:
        m = re.match(r"^\s*node\.(hostname|id)\s*==\s*(\S+)\s*$", c)
        if m:
            return node_alias(m.group(2)) if m.group(1) == "hostname" else m.group(2)
    return None


def _node_rows(nodes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rows = {}
    for n in nodes:
        ms = n.get("ManagerStatus") or {}
        rows[n.get("Alias") or n.get("ID", "?")] = {
            "id": n.get("ID", ""), "state": (n.get("Status") or {}).get("State", ""),
            "availability": (n.get("Spec") or {}).get("Availability", ""),
            "role": (n.get("Spec") or {}).get("Role", ""),
            "reachability": ms.get("Reachability", ""), "leader": bool(ms.get("Leader")),
        }
    return rows


async def _placement(api: DockerAPI, req: dict[str, Any], calls: list[Call],
                     now: dt.datetime) -> dict[str, Any]:
    nodes = _node_rows(await api.nodes(calls=calls))
    usable = {a for a, n in nodes.items()
              if n["state"] == "ready" and n["availability"] == "active"}
    usable |= {n["id"] for a, n in nodes.items() if a in usable}
    pins = {}
    for s in await api.services(calls=calls):
        pin = _pin_of(s)
        if pin and _selected(_name(s), req):
            pins[_name(s)] = pin
    return {"pinned": sorted(f"{s} -> {n}" for s, n in pins.items()),
            "pinned_services": sorted(pins), "pinned_count": len(pins), "pins": pins,
            "pinned_on_unavailable_node": sorted(s for s, n in pins.items() if n not in usable)}


def _image_index(images: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """(repo:tag set, digest and image-id set) for one node."""
    tags: set[str] = set()
    digests: set[str] = set()
    for im in images:
        for t in im.get("RepoTags") or []:
            repo, tag, _ = split_image(t)
            tags.add(f"{repo}:{tag or 'latest'}")
        digests |= {d.partition("@")[2] for d in im.get("RepoDigests") or []}
        if im.get("Id"):
            digests.add(im["Id"])
    return tags, digests


def is_local_build(ref: str) -> bool:
    """No registry digest in the spec and no registry or namespace in the name.

    Swarm pins a digest whenever it could resolve the tag in a registry, and official
    Hub images here all carry one, so an unresolved single-component name (``robot:1.4``,
    ``xploreaop_v1:latest``) is a local build. (RepoDigests cannot tell: with Docker 29's
    containerd store local builds get one too.)
    """
    repo, _, digest = split_image(ref)
    return not digest and "/" not in repo


async def _local_images(api: DockerAPI, req: dict[str, Any], calls: list[Call],
                        now: dt.datetime) -> dict[str, Any]:
    """Single-node images, and among them the ones no registry can supply (local builds):
    those are the services that end in "No such image" when their node goes down."""
    eps = await api.endpoints(calls)
    want = req.get("nodes") or ["tgx1", "tgx2"]
    if any(n not in eps for n in want):
        raise DockerError(f"need the proxy on {want}, answering: {sorted(eps) or 'none'}")
    index = {n: _image_index(await api.images(n, calls=calls)) for n in want}
    by, single, local, missing = {}, [], [], []
    for s in await api.services(calls=calls):
        name, ref = _name(s), _image(s)
        mode = (s.get("Spec") or {}).get("Mode") or {}
        replicas = (mode.get("Replicated") or {}).get("Replicas", 1)
        if not ref or not _selected(name, req) or (replicas == 0 and not _is_cron(s)):
            continue
        repo, tag, digest = split_image(ref)
        key = f"{repo}:{tag or 'latest'}"
        on = [n for n in want if (digest in index[n][1] if digest else key in index[n][0])]
        by[name] = on
        short = ref.split("@")[0]
        if not on:
            missing.append(f"{name} ({short})")
        elif len(on) < len(want):
            single.append(f"{name} ({short}) only on {', '.join(on)}")
            if is_local_build(ref):
                local.append(f"{name} ({short}) built locally on {', '.join(on)}")
    return {"by": by, "single_node_images": sorted(single), "single_node_count": len(single),
            "local_only": sorted(local), "local_only_count": len(local),
            "local_only_services": sorted(x.split(" ")[0] for x in local),
            "missing_everywhere": sorted(missing), "missing_count": len(missing)}


async def _nodes(api: DockerAPI, req: dict[str, Any], calls: list[Call],
                 now: dt.datetime) -> dict[str, Any]:
    rows = _node_rows(await api.nodes(calls=calls))
    leaders = [a for a, n in rows.items() if n["leader"]]
    managers = [a for a, n in rows.items() if n["role"] == "manager"]
    return {
        "nodes": rows, "node_count": len(rows), "manager_count": len(managers),
        "leader": leaders[0] if len(leaders) == 1 else None, "leader_count": len(leaders),
        "not_ready": sorted(a for a, n in rows.items()
                            if n["state"] != "ready" or n["availability"] != "active"),
        "unreachable_managers": sorted(a for a in managers
                                       if rows[a]["reachability"] != "reachable"),
    }


async def _restart_policy(api: DockerAPI, req: dict[str, Any], calls: list[Call],
                          now: dt.datetime) -> dict[str, Any]:
    pol: dict[str, list[str]] = defaultdict(list)
    for s in await api.services(calls=calls):
        name = _name(s)
        if not _selected(name, req) or _is_cron(s) or _mode(s) in ("ReplicatedJob", "GlobalJob"):
            continue
        rp = ((s.get("Spec") or {}).get("TaskTemplate") or {}).get("RestartPolicy") or {}
        pol[rp.get("Condition") or "any"].append(name)
    not_any = sorted(pol.get("on-failure", []) + pol.get("none", []))
    return {"on_failure": sorted(pol.get("on-failure", [])), "none": sorted(pol.get("none", [])),
            "not_any": not_any, "not_any_count": len(not_any)}


SWARM_CHECKS = {"replicas": _replicas, "crash_loops": _crash_loops, "placement": _placement,
                "local_images": _local_images, "nodes": _nodes, "restart_policy": _restart_policy}


def _evidence(values: dict[str, Any], keys: tuple[str, ...]) -> str:
    lines = []
    for k in keys:
        v = values.get(k)
        if v:
            lines.append(f"{k}:")
            lines += [f"  {x}" for x in (v if isinstance(v, list) else [v])][:60]
    return "\n".join(lines)


def _no_docker(ctx: Context) -> Observation | None:
    if ctx.docker is None:
        return Observation(unknown="no Docker API in this process (core only, via the proxy)")
    return None


def _docker_failed(exc: DockerError, calls: list[Call], hard: bool = False) -> Observation:
    msg = str(exc)
    if hard or (exc.status == 503 and "leader" in msg.lower()):
        return Observation(error=msg, calls=calls, evidence=msg)
    return Observation(unknown=msg, calls=calls, evidence=msg)


@register
class SwarmKind(Kind):
    name = "swarm"
    required = ("check",)
    vias = ("core",)

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        if request.get("check") not in SWARM_CHECKS:
            probs.append(f"swarm check must be one of {sorted(SWARM_CHECKS)}")
        return probs

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        if (o := _no_docker(ctx)) is not None:
            return o
        calls: list[Call] = []
        fn = SWARM_CHECKS.get(check.request.get("check", ""))
        if fn is None:
            return Observation(unknown=f"unknown swarm check {check.request.get('check')!r}")
        try:
            values = await fn(ctx.docker, check.request, calls, ctx.now())
        except DockerError as exc:
            return _docker_failed(exc, calls, hard=check.request["check"] == "nodes")
        ev = _evidence(values, ("not_converged", "crash_looping", "killed", "pinned",
                                "pinned_on_unavailable_node", "local_only",
                                "missing_everywhere", "not_ready", "unreachable_managers",
                                "not_any"))
        return Observation(values=values, calls=calls, evidence=ev)


# ---------------------------------------------------------------------- job runs
def extract_markers(lines: list[str]) -> dict[str, str]:
    out = {}
    for line in lines:
        m = MARKER.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip()[:500]
    return out


def _run_row(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {}
    try:
        markers = json.loads(row.get("markers") or "{}")
    except ValueError:
        markers = {}
    return {k: row.get(k) for k in ("task_id", "state", "exit_code", "scheduled_at",
                                     "started_at", "finished_at", "node", "source")} | {
        "markers": markers, "ok": row.get("state") == "complete" and row.get("exit_code") == 0}


def _norm_ts(v: Any) -> str:
    if isinstance(v, dt.datetime):
        ts = v
    else:
        ts = parse_ts(str(v)) if v else None
        if ts is None:
            raise ValueError(f"not a timestamp: {v!r}")
    return iso(ts.astimezone(dt.UTC))


def _scheduled_for(expr: str | None, started: dt.datetime) -> str | None:
    """The fire time a task belongs to, or None for a manual run."""
    if not expr:
        return None
    try:
        fire = cron_prev(expr, started + dt.timedelta(minutes=1))
    except ValueError:
        return None
    return iso(fire) if (started - fire).total_seconds() <= 300 else None


async def record_job_runs(store: Any, docker: DockerAPI) -> int:
    """Copy every finished swarm-cronjob task into ``job_runs`` with its log tail.

    Idempotent (UNIQUE(job, task_id), and known task ids are skipped before their logs
    are fetched). Call it every couple of minutes: logs disappear with the task.
    Returns the number of rows inserted.
    """
    if not store.get_meta("job_recorder_started"):
        store.set_meta("job_recorder_started", iso(dt.datetime.now(dt.UTC)))
    aliases = {n.get("ID"): n.get("Alias", "") for n in await docker.nodes()}
    inserted = 0
    for s in await docker.services():
        if not _is_cron(s):
            continue
        job, expr = _name(s), _labels(s).get(SCHEDULE_LABEL)
        known = {r["task_id"] for r in store.query("SELECT task_id FROM job_runs WHERE job=?",
                                                    (job,))}
        for t in await docker.tasks(service=job):
            st = t.get("Status") or {}
            if t.get("ID") in known or st.get("State") not in TERMINAL_STATES:
                continue
            started = parse_ts(t.get("CreatedAt"))
            if started is None:
                continue
            try:
                lines = await docker.task_logs(t["ID"], tail=LOG_TAIL)
            except DockerError as exc:
                lines = [f"[logs unavailable: {exc}]"]
            code = (st.get("ContainerStatus") or {}).get("ExitCode")
            finished = parse_ts(st.get("Timestamp"))
            cur = store.execute(
                "INSERT OR IGNORE INTO job_runs(job,task_id,scheduled_at,started_at,finished_at,"
                "node,state,exit_code,markers,log_tail,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (job, t["ID"], _scheduled_for(expr, started), iso(started),
                 iso(finished) if finished else None, aliases.get(t.get("NodeID"), ""),
                 st.get("State"), code, json.dumps(extract_markers(lines)),
                 "\n".join(lines), "swarm"))
            inserted += cur.rowcount or 0
    return inserted


def ingest_push(store: Any, job: str, payload: dict[str, Any]) -> int:
    """Store a run a cron script POSTed (source=push); returns the row id.

    payload: ``exit_code`` (int), ``started_at``/``finished_at`` (ISO, default now),
    ``state`` (default from exit_code), ``node``, ``log`` (text, last 200 lines kept,
    redacted), ``markers`` (mapping), ``run_id`` (dedupe key; default push-<started_at>).
    Raises ValueError on a malformed payload; the web handler answers 400.
    """
    if not JOB_NAME.match(job or ""):
        raise ValueError(f"bad job name {job!r}")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    started = _norm_ts(payload.get("started_at") or dt.datetime.now(dt.UTC))
    finished = _norm_ts(payload["finished_at"]) if payload.get("finished_at") else started
    code = payload.get("exit_code")
    if code is not None and (isinstance(code, bool) or not isinstance(code, int | str)):
        raise ValueError("exit_code must be an integer")
    code = int(code) if code is not None else None
    state = str(payload.get("state") or ("complete" if code == 0 else "failed" if code is not None
                                         else "unknown"))[:20]
    lines = [redact_text(x, cap=4000) for x in str(payload.get("log") or "").splitlines()]
    lines = lines[-LOG_TAIL:]
    markers = extract_markers(lines)
    extra = payload.get("markers") or {}
    if not isinstance(extra, dict):
        raise ValueError("markers must be a mapping")
    markers |= {str(k)[:64]: redact_text(str(v), cap=500) for k, v in extra.items()}
    run_id = str(payload.get("run_id") or f"push-{started}")[:120]
    node = redact_text(str(payload.get("node") or ""), cap=40)
    cur = store.execute(
        "INSERT OR IGNORE INTO job_runs(job,task_id,scheduled_at,started_at,finished_at,node,"
        "state,exit_code,markers,log_tail,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (job, run_id, None, started, finished, node, state, code, json.dumps(markers),
         "\n".join(lines), "push"))
    if cur.rowcount:
        return int(cur.lastrowid)
    row = store.one("SELECT id FROM job_runs WHERE job=? AND task_id=?", (job, run_id))
    return int(row["id"]) if row else 0


@register
class JobRunKind(Kind):
    name = "job_run"
    required = ("service",)
    vias = ("core",)

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r, calls = check.request, []
        if ctx.store is None:
            return Observation(unknown="no store: job runs are read from job_runs")
        now = ctx.now()
        expr, created = r.get("schedule"), None
        if not expr:
            if (o := _no_docker(ctx)) is not None:
                return o
            try:
                svcs = await ctx.docker.services({"name": [r["service"]]}, calls=calls)
            except DockerError as exc:
                return _docker_failed(exc, calls)
            svc = next((s for s in svcs if _name(s) == r["service"]), None)
            if svc is None:
                return Observation(error=f"service {r['service']} is not in the swarm", calls=calls)
            expr = _labels(svc).get(SCHEDULE_LABEL)
            created = parse_ts(svc.get("CreatedAt"))
            if not expr or _labels(svc).get(CRON_LABEL) != "true":
                return Observation(error=f"{r['service']} has no enabled swarm.cronjob schedule",
                                   calls=calls)
        try:
            grace = parse_duration(r.get("grace", "20m"))
            latest = cron_prev(expr, now)
            due = latest if (now - latest).total_seconds() >= grace else \
                cron_prev(expr, latest - dt.timedelta(minutes=1))
            prev_due = cron_prev(expr, due - dt.timedelta(minutes=1))
        except ValueError as exc:
            return Observation(error=str(exc), calls=calls)
        if created is not None and due < created:
            return Observation(unknown=f"not yet due: {r['service']} was created {iso(created)}, "
                                       f"after its last scheduled slot {iso(due)}", calls=calls)
        q = ("SELECT * FROM job_runs WHERE job=? AND started_at>=? AND started_at<=? "
             "ORDER BY started_at DESC LIMIT 1")
        run = _run_row(ctx.store.one(q, (r["service"], iso(due - dt.timedelta(minutes=1)),
                                         iso(due + dt.timedelta(seconds=grace)))))
        last = _run_row(ctx.store.one(
            "SELECT * FROM job_runs WHERE job=? ORDER BY started_at DESC LIMIT 1", (r["service"],)))
        # Swarm keeps only the last few tasks per job, so a slot from before the monitor
        # started recording may simply be invisible: that is "cannot tell", not "missed".
        since = parse_ts(ctx.store.get_meta("job_recorder_started") or "")
        if not run and since is not None and due < since:
            return Observation(unknown=f"slot {iso(due)} predates the monitor's job record "
                                       f"(since {iso(since)}); judged from the next run",
                               calls=calls)
        values: dict[str, Any] = {
            "schedule": expr, "last_scheduled_at": iso(latest), "checked_slot": iso(due),
            "pending": due != latest, "ran": bool(run), "run": run, "last_run": last,
            "last_run_age_h": round((now - parse_ts(last["started_at"])).total_seconds() / 3600, 2)
            if last.get("started_at") else None,
        }
        subject = run or last
        if r.get("marker_re") and subject:
            row = ctx.store.one("SELECT log_tail FROM job_runs WHERE job=? AND task_id=?",
                                (r["service"], subject["task_id"]))
            hits = re.findall(r["marker_re"], (row or {}).get("log_tail") or "", re.M)
            values["marker_found"] = bool(hits)
            last_hit = hits[-1] if hits else None
            values["marker"] = last_hit[0] if isinstance(last_hit, tuple) else last_hit
        if r.get("after_success_of"):
            dep = _run_row(ctx.store.one(
                "SELECT * FROM job_runs WHERE job=? AND started_at<=? ORDER BY started_at DESC "
                "LIMIT 1", (r["after_success_of"], (subject or {}).get("started_at") or iso(now))))
            values["dependency_run"] = dep
            values["ran_after_dependency"] = bool(
                dep and dep["ok"] and dep["started_at"] > iso(prev_due))
        ev = "\n".join(f"{k}: {values[k]}" for k in ("schedule", "checked_slot", "ran"))
        return Observation(values=values, calls=calls, evidence=ev)


# ---------------------------------------------------------------------- digest drift
@register
class DigestDriftKind(Kind):
    name = "digest_drift"
    vias = ("core",)

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        if (o := _no_docker(ctx)) is not None:
            return o
        if ctx.store is None:
            return Observation(unknown="no store to keep the previous observation in")
        calls: list[Call] = []
        api: DockerAPI = ctx.docker
        try:
            spec = {_name(s): _image(s).split("@")[0] for s in await api.services(calls=calls)
                    if _selected(_name(s), check.request)}
            ids: dict[str, dict[str, str]] = defaultdict(dict)
            for node in await api.endpoints(calls):
                found: dict[str, set[str]] = defaultdict(set)
                for c in await api.containers(node, calls=calls):
                    svc = (c.get("Labels") or {}).get("com.docker.swarm.service.name")
                    if svc in spec:
                        found[svc].add(c.get("ImageID", ""))
                for svc, s in found.items():
                    ids[svc][node] = ",".join(sorted(s))
        except DockerError as exc:
            return _docker_failed(exc, calls)
        key = f"digest_drift:{check.id}"
        prev = json.loads(ctx.store.get_meta(key) or "{}")
        p_ids, p_spec = prev.get("ids", {}), prev.get("spec", {})
        changed, redeployed = [], []
        for svc, per in ids.items():
            for node, now_id in per.items():
                old = p_ids.get(svc, {}).get(node)
                if old is None or old == now_id:
                    continue
                if p_spec.get(svc) == spec.get(svc):
                    changed.append(f"{svc}@{node}: {old[7:19]} -> {now_id[7:19]} ({spec[svc]})")
                else:
                    redeployed.append(f"{svc}: {p_spec.get(svc)} -> {spec.get(svc)}")
        ctx.store.set_meta(key, json.dumps({"ids": ids, "spec": spec, "at": iso(ctx.now())}))
        split = sorted(svc for svc, per in ids.items() if len(set(per.values())) > 1)
        values = {"changed": sorted(changed), "changed_count": len(changed),
                  "redeployed": sorted(set(redeployed)), "node_mismatch": split,
                  "services": len(ids), "first_run": not p_ids}
        return Observation(values=values, calls=calls,
                           evidence=_evidence(values, ("changed", "redeployed", "node_mismatch")))


# ---------------------------------------------------------------------- docs drift
_IMAGE_REF = re.compile(r"(?<![\w./-])((?:[a-z0-9][a-z0-9.-]*(?::\d+)?/)?[a-z0-9][a-z0-9._-]*"
                        r"(?:/[a-z0-9][a-z0-9._-]*)*):([A-Za-z0-9][A-Za-z0-9._-]{0,127})(?![<\w.-])")


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse_registry(text: str) -> list[dict[str, Any]]:
    """Rows of the first ``| Service | Image | ...`` table: service, images, domain."""
    header: list[str] | None = None
    rows = []
    for line in text.splitlines():
        if header is None:
            if re.match(r"^\|\s*Service\s*\|\s*Image", line):
                header = [c.lower() for c in _cells(line)]
            continue
        if not line.startswith("|"):
            break
        cells = _cells(line)
        if not cells or set(cells[0]) <= set("-: "):
            continue
        row = dict(zip(header, cells, strict=False))
        raw = row.get("service", "")
        if "~~" in raw or "removed" in row.get("status", "").lower():
            continue
        name = re.sub(r"[*`~]", "", raw).strip()
        rows.append({"service": name, "domain": row.get("domain", ""),
                     "images": [(split_image(f"{m.group(1)}:{m.group(2)}")[0], m.group(2))
                                for m in _IMAGE_REF.finditer(row.get("image", ""))]})
    return rows


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _owner_shown(label: str) -> str:
    """Owner labels on the live services hold e-mail addresses; never let one into values."""
    return _EMAIL.sub("[e-mail, not a handle]", label)[:120]


def _group(row_name: str, prefix: str, services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [s for s in services
            if _name(s) in (row_name, prefix) or _name(s).startswith(prefix + "_")
            or _labels(s).get("com.docker.stack.namespace") == prefix]


@register
class DocsDriftKind(Kind):
    name = "docs_drift"
    required = ("mount",)
    vias = ("core",)

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r, calls = check.request, []
        if (o := _no_docker(ctx)) is not None:
            return o
        root = ctx.mounts.get(r["mount"])
        path = (root / r.get("path", "services/service-registry.md")) if root else None
        if path is None or not path.is_file():
            return Observation(unknown=f"docs mount {r['mount']!r} or its registry is missing")
        rows = parse_registry(path.read_text(errors="replace"))
        try:
            services = await ctx.docker.services(calls=calls)
        except DockerError as exc:
            return _docker_failed(exc, calls)
        aliases = r.get("aliases") or {}
        covered: set[str] = set()
        missing_live, mismatch = [], []
        for row in rows:
            grp = _group(row["service"], aliases.get(row["service"], row["service"]), services)
            if not grp:
                missing_live.append(row["service"])
                continue
            covered |= {_name(s) for s in grp}
            for repo, tag in row["images"]:
                live = {split_image(_image(s))[1] or "latest" for s in grp
                        if split_image(_image(s))[0] == repo}
                if live and tag not in live:
                    mismatch.append(f"{row['service']}: docs {repo}:{tag}, live "
                                    f"{', '.join(sorted(live))}")
        units = {_labels(s).get("com.docker.stack.namespace") or _name(s) for s in services
                 if _name(s) not in covered}
        ignore = r.get("ignore") or []
        missing_docs = sorted(u for u in units
                              if not any(fnmatch.fnmatchcase(u, g) for g in ignore))
        owners = ctx.catalogue.owners if ctx.catalogue else None
        handles = set(owners.people) if owners else set()
        unknown_owner = sorted(f"{_name(s)}: {_owner_shown(_labels(s)[OWNER_LABEL])}"
                               for s in services
                               if _labels(s).get(OWNER_LABEL) and handles
                               and any(h.strip() not in handles
                                       for h in _labels(s)[OWNER_LABEL].split(",")))
        values = {"rows": len(rows), "missing_live": sorted(missing_live),
                  "missing_in_docs": missing_docs, "image_mismatch": sorted(mismatch),
                  "unknown_owner_labels": unknown_owner,
                  "unknown_owner_count": len(unknown_owner),
                  "missing_live_count": len(missing_live),
                  "missing_in_docs_count": len(missing_docs),
                  "image_mismatch_count": len(mismatch)}
        return Observation(values=values, calls=calls, evidence=_evidence(
            values, ("missing_live", "missing_in_docs", "image_mismatch", "unknown_owner_labels")))
