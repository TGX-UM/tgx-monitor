"""swarm, job_run, digest_drift and docs_drift, offline against ``FakeSwarm``.

The scenarios are the incidents these kinds exist for: a clean exit under on-failure
leaving 0/1, cron jobs resting at 0/1 (normal), local builds on one node, a missed weekly
reload, a switch without a reload before it, a moving tag pulling new code.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from test_docker import FakeSwarm, container, frame, image, node, svc, task

from tgx_monitor.catalogue import Catalogue, Check, Target
from tgx_monitor.http import Http
from tgx_monitor.kinds import KINDS
from tgx_monitor.kinds.base import Context, run_probe
from tgx_monitor.kinds.infra import (
    cron_prev,
    ingest_push,
    is_local_build,
    parse_cron,
    parse_registry,
    record_job_runs,
    split_image,
)
from tgx_monitor.store import Store

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)  # a Wednesday
CRON = {"swarm.cronjob.enable": "true", "com.docker.stack.namespace": "cronjobs"}
ROOT = Path(__file__).resolve().parents[1]


def cron(schedule: str) -> dict[str, str]:
    return {**CRON, "swarm.cronjob.schedule": schedule}


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


def ctx_for(swarm: FakeSwarm | None, store: Store | None = None, **kw) -> Context:
    return Context(http=Http(mode="replay"), catalogue=Catalogue(ROOT / "catalogue"),
                   store=store, docker=swarm.api() if swarm else None, now=lambda: NOW, **kw)


def check(kind: str, **request) -> Check:
    return Check(id=f"t-{kind.replace('_', '-')}", kind=kind, via=["core"], request=request)


async def observe(kind: str, ctx: Context, **request):
    return await KINDS[kind]().observe(check(kind, **request), "core", ctx)


# ---------------------------------------------------------------------- cron
@pytest.mark.parametrize(("expr", "at", "want"), [
    ("0 6 * * 0", "2026-11-11T12:00", "2026-11-08T06:00"),     # weekly Sunday reload
    ("0 2 12 * *", "2026-11-11T12:00", "2026-10-12T02:00"),    # monthly WikiPathways
    ("0 2 12 * *", "2026-11-12T02:00", "2026-11-12T02:00"),    # exactly at the fire time
    ("*/15 * * * *", "2026-11-11T12:14", "2026-11-11T12:00"),
    ("30 3 * * 1-5", "2026-11-09T03:00", "2026-11-06T03:30"),  # Monday early -> Friday
    ("0 4 * * MON", "2026-11-11T12:00", "2026-11-09T04:00"),
    ("0 0 1 * 1", "2026-11-11T12:00", "2026-11-09T00:00"),     # dom OR dow (Vixie rule)
    ("0 0 * * 7", "2026-11-11T12:00", "2026-11-08T00:00"),     # 7 is Sunday too
    ("0 30 3 * * *", "2026-11-11T12:00", "2026-11-11T03:30"),  # leading seconds field
    ("@daily", "2026-11-11T12:00", "2026-11-11T00:00"),
    ("5,35 1-2 * * *", "2026-11-11T02:20", "2026-11-11T02:05"),
])
def test_cron_prev(expr: str, at: str, want: str) -> None:
    got = cron_prev(expr, dt.datetime.fromisoformat(at).replace(tzinfo=dt.UTC))
    assert got == dt.datetime.fromisoformat(want).replace(tzinfo=dt.UTC)


@pytest.mark.parametrize("bad", ["", "* * *", "61 * * * *", "5-1 * * * *", "0 0 * * 8",
                                 "a b c d e", "*/0 * * * *"])
def test_cron_rejects_garbage(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_cron(bad)


def test_cron_that_never_fires() -> None:
    with pytest.raises(ValueError, match="never fired"):
        cron_prev("0 0 31 2 *", NOW)


def test_split_image_and_local_builds() -> None:
    assert split_image("ghcr.io/a/b:1.0@sha256:x") == ("ghcr.io/a/b", "1.0", "sha256:x")
    assert split_image("docker.io/library/traefik:v3") == ("traefik", "v3", "")
    assert split_image("localhost:5000/x") == ("localhost:5000/x", "", "")
    assert is_local_build("robot:1.4") and is_local_build("xploreaop_v1:latest")
    assert not is_local_build("traefik:v3@sha256:abc")
    assert not is_local_build("ghcr.io/vhp4safety/aopsuite:latest")


# ---------------------------------------------------------------------- swarm
@pytest.fixture
def swarm() -> FakeSwarm:
    s = FakeSwarm()
    s.services = [
        svc("bridgedb", "bigcatum/bridgedb:3.0.31-2.1.9@sha256:ab66", sid="sb"),
        svc("nanolinks_nanolinks-virtuoso", "openlink/virtuoso:7@sha256:e7", sid="sn",
            running=0, restart="on-failure"),
        svc("toxtempass_minio_init", "ghcr.io/j/minio-init:v3@sha256:d4", sid="sm", running=0,
            restart="none"),
        svc("traefik", "traefik:v3@sha256:11", sid="st", replicas=None),
        svc("cronjobs_aopwiki-snorql-reload", "ghcr.io/tgx-um/cronjobs:latest@sha256:26",
            sid="sc", running=0, labels=cron("0 6 * * 0"), restart="none"),
        svc("cronjobs_wikipathways-switch", "docker:28-cli@sha256:62", sid="sw", replicas=0,
            labels=cron("0 4 12 * *"), restart="none", created="2026-10-13T11:39:32Z"),
        svc("cronjobs_wikipathways-reload", "ghcr.io/tgx-um/cronjobs:latest@sha256:07", sid="sr",
            running=0, labels=cron("0 2 12 * *"), restart="none"),
        svc("robot", "robot:1.4", sid="so", restart="on-failure",
            constraints=["node.hostname==h3068544.stratoserver.net"]),
        svc("aopsuite", "ghcr.io/vhp4safety/aopsuite:latest", sid="sa"),
    ]
    s.images["tgx1"] = [image(["bigcatum/bridgedb:3.0.31-2.1.9"],
                              ["bigcatum/bridgedb@sha256:ab66"]),
                        image(["robot:1.4"], ["robot@sha256:c1"]),
                        image(["ghcr.io/vhp4safety/aopsuite:latest"]),
                        image(["traefik:v3"], ["traefik@sha256:11"]),
                        image(["openlink/virtuoso:7"], ["openlink/virtuoso@sha256:e7"])]
    s.images["tgx2"] = [image(["traefik:v3"], ["traefik@sha256:11"]),
                        image(["ghcr.io/vhp4safety/aopsuite:latest"]),
                        image(["openlink/virtuoso:7"], ["openlink/virtuoso@sha256:e7"])]
    return s


async def test_replicas_flags_clean_exit_but_not_resting_cron(swarm: FakeSwarm) -> None:
    o = await observe("swarm", ctx_for(swarm), check="replicas", ignore=["toxtempass_*"])
    assert o.error is None and o.unknown is None
    assert o.values["not_converged"] == ["nanolinks_nanolinks-virtuoso 0/1"]
    assert o.values["not_converged_count"] == 1
    assert "cronjobs_aopwiki-snorql-reload" in o.values["cron_resting"]
    assert o.values["by"]["traefik"] == {"running": 2, "desired": 2, "mode": "Global"}
    assert "toxtempass_minio_init" not in o.values["by"]
    assert "nanolinks_nanolinks-virtuoso 0/1" in o.evidence


async def test_replicas_service_globs(swarm: FakeSwarm) -> None:
    o = await observe("swarm", ctx_for(swarm), check="replicas", services=["bridgedb"])
    assert o.values["checked"] == 1 and o.values["not_converged_count"] == 0


async def test_crash_loops_window_threshold_and_kills(swarm: FakeSwarm) -> None:
    recent = [f"2026-11-11T11:{m:02d}:00.5Z" for m in (5, 20, 40)]
    swarm.tasks = [task(f"t{i}", "sn", "failed", ts, exit_code=139) for i, ts in enumerate(recent)]
    swarm.tasks += [task("old", "sb", "failed", "2026-11-10T01:00:00Z", exit_code=1),
                    task("r1", "sb", "running", "2026-11-11T11:00:00Z", desired="running"),
                    task("k1", "sa", "failed", "2026-11-11T11:50:00Z", exit_code=137)]
    o = await observe("swarm", ctx_for(swarm), check="crash_loops", window="1h", threshold=3)
    assert o.values["failures"] == {"nanolinks_nanolinks-virtuoso": 3, "aopsuite": 1}
    assert o.values["crash_looping"] == ["nanolinks_nanolinks-virtuoso: 3 failures (exit [139])"]
    assert o.values["killed_count"] == 4
    o = await observe("swarm", ctx_for(swarm), check="crash_loops", window="24h", threshold=5)
    assert o.values["crash_looping_count"] == 0 and o.values["failed_task_count"] == 4


async def test_placement_and_pin_on_dead_node(swarm: FakeSwarm) -> None:
    o = await observe("swarm", ctx_for(swarm), check="placement")
    assert o.values["pinned_services"] == ["robot"] and o.values["pinned"] == ["robot -> tgx1"]
    assert o.values["pinned_on_unavailable_node"] == []
    swarm.nodes = [node("tgx1", state="down", reach="unreachable"), node("tgx2", leader=True)]
    o = await observe("swarm", ctx_for(swarm), check="placement")
    assert o.values["pinned_on_unavailable_node"] == ["robot"]


async def test_local_images(swarm: FakeSwarm) -> None:
    o = await observe("swarm", ctx_for(swarm), check="local_images")
    v = o.values
    assert v["local_only_services"] == ["robot"]
    assert v["local_only"] == ["robot (robot:1.4) built locally on tgx1"]
    assert "bridgedb (bigcatum/bridgedb:3.0.31-2.1.9) only on tgx1" in v["single_node_images"]
    assert v["by"]["aopsuite"] == ["tgx1", "tgx2"] and v["by"]["traefik"] == ["tgx1", "tgx2"]
    # cron jobs count even at 0 replicas: their image must be there when they fire
    missing = v["missing_everywhere"]
    assert "cronjobs_aopwiki-snorql-reload (ghcr.io/tgx-um/cronjobs:latest)" in missing


async def test_local_images_needs_both_proxies(swarm: FakeSwarm) -> None:
    swarm.down.add("tgx2")
    o = await observe("swarm", ctx_for(swarm), check="local_images")
    assert o.unknown and "tgx2" in o.unknown and o.error is None


async def test_nodes_and_leaderless_swarm(swarm: FakeSwarm) -> None:
    o = await observe("swarm", ctx_for(swarm), check="nodes")
    assert o.values["leader"] == "tgx1" and o.values["not_ready"] == []
    assert o.values["nodes"]["tgx2"]["reachability"] == "reachable"
    swarm.status_override["nodes"] = (503, "The swarm does not have a leader.")
    o = await observe("swarm", ctx_for(swarm), check="nodes")
    assert o.error and "leader" in o.error  # a page, not a grey "unknown"


async def test_restart_policy(swarm: FakeSwarm) -> None:
    o = await observe("swarm", ctx_for(swarm), check="restart_policy")
    assert o.values["on_failure"] == ["nanolinks_nanolinks-virtuoso", "robot"]
    assert o.values["none"] == ["toxtempass_minio_init"]  # cron jobs are left out


async def test_without_docker_or_with_bad_check(swarm: FakeSwarm) -> None:
    o = await observe("swarm", ctx_for(None), check="replicas")
    assert o.unknown and "Docker" in o.unknown
    assert KINDS["swarm"].validate_request({"check": "bogus"}, ["core"])
    assert KINDS["swarm"].validate_request({"check": "nodes"}, ["public"])
    assert not KINDS["swarm"].validate_request({"check": "nodes"}, ["core"])


async def test_run_probe_judges_swarm_values(swarm: FakeSwarm) -> None:
    c = Check(id="swarm-replicas", kind="swarm", via=["core"], request={
        "check": "replicas", "ignore": ["toxtempass_minio_init"]},
        **{"assert": [{"that": "not_converged_count", "eq": 0}]})
    t = Target(id="swarm", name="Swarm", **{"class": "infra"}, owners=["marvinm2"], checks=[c])
    r = await run_probe(t, c, c.id, "core", ctx_for(swarm))
    assert r.status == "failed" and "found 1" in r.summary
    assert all(call.via == "docker" for call in r.calls)


# ---------------------------------------------------------------------- job runs
def reload_tasks() -> list[dict]:
    return [
        task("tok1", "sc", "complete", "2026-11-01T06:00:09.6Z", exit_code=0,
             created="2026-11-01T06:00:00.09Z"),
        task("tok2", "sc", "complete", "2026-11-08T06:00:09.0Z", exit_code=0,
             created="2026-11-08T06:00:00.07Z"),
        task("tbad", "sc", "failed", "2026-10-23T06:21:44.8Z", exit_code=2, node="tgx2",
             created="2026-10-23T06:13:25.4Z"),
        task("trun", "sr", "running", "2026-11-11T11:59:00Z", desired="running"),
    ]


async def test_record_job_runs(swarm: FakeSwarm, store: Store) -> None:
    swarm.tasks = reload_tasks()
    swarm.logs["tok2"] = (frame("rapper: 140600 triples\n") + frame("api_key=abc123\n")
                          + frame("TGXMON-MARKER triples=340667\n")
                          + frame("=== AOP-Wiki RDF reload finished ===\n"))
    api = swarm.api()
    assert await record_job_runs(store, api) == 3
    assert await record_job_runs(store, api) == 0  # idempotent
    rows = {r["task_id"]: r for r in store.query("SELECT * FROM job_runs")}
    assert set(rows) == {"tok1", "tok2", "tbad"}  # the running one waits
    ok = rows["tok2"]
    assert ok["state"] == "complete" and ok["exit_code"] == 0 and ok["node"] == "tgx1"
    assert ok["scheduled_at"] == "2026-11-08T06:00:00+00:00"
    assert ok["started_at"] == "2026-11-08T06:00:00+00:00"
    assert ok["finished_at"] == "2026-11-08T06:00:09+00:00"
    assert json.loads(ok["markers"]) == {"triples": "340667"}
    assert "abc123" not in ok["log_tail"] and "reload finished" in ok["log_tail"]
    bad = rows["tbad"]
    assert bad["scheduled_at"] is None  # a Friday 06:13 rerun belongs to no slot
    assert bad["exit_code"] == 2 and bad["node"] == "tgx2"
    assert "logs unavailable" in rows["tok1"]["log_tail"]
    log_reqs = [r for r in swarm.requests if r.url.path.endswith("/logs")]
    assert len(log_reqs) == 3  # known tasks are not fetched again


async def test_job_run_ran(swarm: FakeSwarm, store: Store) -> None:
    swarm.tasks = reload_tasks()
    swarm.logs["tok2"] = frame("340667 triples\n")
    await record_job_runs(store, swarm.api())
    o = await observe("job_run", ctx_for(swarm, store), service="cronjobs_aopwiki-snorql-reload",
                      marker_re=r"(\d+) triples")
    v = o.values
    assert o.error is None and o.unknown is None
    assert v["schedule"] == "0 6 * * 0" and v["checked_slot"] == "2026-11-08T06:00:00+00:00"
    assert v["ran"] is True and v["run"]["exit_code"] == 0 and v["run"]["ok"] is True
    assert v["marker"] == "340667" and v["marker_found"] is True
    assert v["last_run"]["task_id"] == "tok2" and v["last_run_age_h"] == 78.0


async def test_job_run_missed_slot(swarm: FakeSwarm, store: Store) -> None:
    swarm.tasks = [t for t in reload_tasks() if t["ID"] != "tok2"]
    store.set_meta("job_recorder_started", "2026-10-01T00:00:00+00:00")  # recording all along
    await record_job_runs(store, swarm.api())
    o = await observe("job_run", ctx_for(swarm, store), service="cronjobs_aopwiki-snorql-reload")
    assert o.values["ran"] is False and o.values["run"] == {}
    assert o.values["last_run"]["task_id"] == "tok1"


async def test_job_run_inside_grace_judges_previous_slot(swarm: FakeSwarm, store: Store) -> None:
    swarm.tasks = reload_tasks()
    await record_job_runs(store, swarm.api())
    ctx = ctx_for(swarm, store)
    ctx.now = lambda: dt.datetime(2026, 11, 15, 6, 10, tzinfo=dt.UTC)  # 10 min after Sunday's slot
    o = await KINDS["job_run"]().observe(check("job_run", service="cronjobs_aopwiki-snorql-reload"),
                                         "core", ctx)
    assert o.values["pending"] is True and o.values["ran"] is True
    assert o.values["last_scheduled_at"] == "2026-11-15T06:00:00+00:00"
    assert o.values["checked_slot"] == "2026-11-08T06:00:00+00:00"


async def test_job_run_not_yet_due_and_missing(swarm: FakeSwarm, store: Store) -> None:
    o = await observe("job_run", ctx_for(swarm, store), service="cronjobs_wikipathways-switch")
    assert o.unknown and "not yet due" in o.unknown
    o = await observe("job_run", ctx_for(swarm, store), service="cronjobs_gone")
    assert o.error and "not in the swarm" in o.error
    o = await observe("job_run", ctx_for(swarm, None), service="cronjobs_gone")
    assert o.unknown and "store" in o.unknown


async def test_job_run_after_success_of(swarm: FakeSwarm, store: Store) -> None:
    def push(job: str, at: str, code: int) -> None:
        ingest_push(store, job, {"started_at": at, "exit_code": code, "run_id": f"{job}-{at}"})

    ctx = ctx_for(None, store)
    ctx.now = lambda: dt.datetime(2026, 12, 13, 12, tzinfo=dt.UTC)
    req = {"service": "cronjobs_wikipathways-switch", "schedule": "0 4 12 * *",
           "after_success_of": "cronjobs_wikipathways-reload"}
    push("cronjobs_wikipathways-reload", "2026-12-12T02:00:00Z", 0)
    push("cronjobs_wikipathways-switch", "2026-12-12T04:00:01Z", 0)
    o = await KINDS["job_run"]().observe(check("job_run", **req), "core", ctx)
    assert o.values["ran"] is True and o.values["ran_after_dependency"] is True
    # the reload failed this month: the switch ran without a fresh, successful reload
    store.execute("UPDATE job_runs SET exit_code=1, state='failed' WHERE job=?",
                  ("cronjobs_wikipathways-reload",))
    push("cronjobs_wikipathways-reload", "2026-11-12T02:00:00Z", 0)  # last month's success
    o = await KINDS["job_run"]().observe(check("job_run", **req), "core", ctx)
    assert o.values["ran_after_dependency"] is False
    assert o.values["dependency_run"]["exit_code"] == 1


def test_ingest_push(store: Store) -> None:
    payload = {"started_at": "2026-11-10T01:30:00Z", "finished_at": "2026-11-10T01:30:18Z",
               "exit_code": 0, "node": "tgx2", "run_id": "r1",
               "log": "line\nTGXMON-MARKER graphs=38\ntoken=ghp_abcdefghijklmnopqrstuvwxyz",
               "markers": {"triples": 5892342}}
    rid = ingest_push(store, "cronjobs_aopwiki-dashboard-backup", payload)
    assert rid > 0
    assert ingest_push(store, "cronjobs_aopwiki-dashboard-backup", payload) == rid  # dedupe
    row = store.one("SELECT * FROM job_runs WHERE id=?", (rid,))
    assert row["source"] == "push" and row["state"] == "complete"
    assert row["started_at"] == "2026-11-10T01:30:00+00:00"
    assert json.loads(row["markers"]) == {"graphs": "38", "triples": "5892342"}
    assert "ghp_" not in row["log_tail"]
    failed = ingest_push(store, "job", {"exit_code": 3})
    assert store.one("SELECT state FROM job_runs WHERE id=?", (failed,))["state"] == "failed"
    for bad_job, bad in [("../x", {}), ("job", {"exit_code": [1]}), ("job", {"started_at": "x"}),
                         ("job", {"markers": [1]})]:
        with pytest.raises(ValueError):
            ingest_push(store, bad_job, bad)


# ---------------------------------------------------------------------- digest drift
async def test_digest_drift(swarm: FakeSwarm, store: Store) -> None:
    swarm.containers["tgx1"] = [container("aopsuite", "sha256:" + "a" * 64),
                                container("bridgedb", "sha256:" + "b" * 64)]
    swarm.containers["tgx2"] = [container("traefik", "sha256:" + "c" * 64, "tgx2")]
    ctx = ctx_for(swarm, store)
    o = await observe("digest_drift", ctx)
    assert o.values["first_run"] is True and o.values["changed"] == []
    swarm.containers["tgx1"][0] = container("aopsuite", "sha256:" + "d" * 64)  # :latest moved
    swarm.services[0] = svc("bridgedb", "bigcatum/bridgedb:3.0.32@sha256:ff", sid="sb")
    swarm.containers["tgx1"][1] = container("bridgedb", "sha256:" + "e" * 64)
    o = await observe("digest_drift", ctx)
    assert o.values["changed"] == [
        "aopsuite@tgx1: aaaaaaaaaaaa -> dddddddddddd (ghcr.io/vhp4safety/aopsuite:latest)"]
    assert o.values["redeployed"] == [
        "bridgedb: bigcatum/bridgedb:3.0.31-2.1.9 -> bigcatum/bridgedb:3.0.32"]
    assert o.values["first_run"] is False
    o = await observe("digest_drift", ctx_for(swarm, None))
    assert o.unknown


# ---------------------------------------------------------------------- docs drift
REGISTRY = """# Service Registry

## Deployed Services

| Service | Image | Port | Storage | Domain | Status | Deployed |
|---------|-------|------|---------|--------|--------|----------|
| traefik | traefik:v3 | 80, 443 | `/x` | — (infrastructure) | Running | - |
| bridgedb | bigcatum/bridgedb:3.0.31-2.1.9 | (→8183) | - | bridgedb.org | Running | - |
| arrayanalysis | arrayanalysis/arrayanalysis_shiny:0.1.4 | (→3838) | - | a.org | Running | - |
| aopwiki-dashboard | ghcr.io/m/dash:sha-<short> + openlink/v7 (digest) | x | y | z | Running | - |
| aopwiki-grlc | clariah/grlc | x | y | z | **Removed 2026-10-04** | 2026-07-16 |
| ~~old~~ | — | — | — | — | — | — |
| ghost | ghost/image:1.0 | x | y | z | Running | — |
| toxtempassistant | ghcr.io/j/toxtempassistant:v3.31.0 (stack: toxtemp) | x | y | z | Running | — |

> the table is partial

| Service | Other |
|---|---|
| later | not parsed |
"""


def test_parse_registry() -> None:
    rows = {r["service"]: r for r in parse_registry(REGISTRY)}
    assert list(rows) == ["traefik", "bridgedb", "arrayanalysis", "aopwiki-dashboard", "ghost",
                          "toxtempassistant"]
    assert rows["bridgedb"]["images"] == [("bigcatum/bridgedb", "3.0.31-2.1.9")]
    assert rows["aopwiki-dashboard"]["images"] == []  # no placeholder tag "sha-"
    assert rows["bridgedb"]["domain"] == "bridgedb.org"


async def test_docs_drift(swarm: FakeSwarm, tmp_path: Path) -> None:
    (tmp_path / "services").mkdir()
    (tmp_path / "services" / "service-registry.md").write_text(REGISTRY)
    swarm.services += [
        svc("arrayanalysis", "arrayanalysis/arrayanalysis_shiny:0.1.5", sid="sx",
            labels={"tgx.service.owner": "someone@example.org"}),
        svc("aopwiki-dashboard_dashboard", "ghcr.io/marvinm2/aopwiki-dashboard:sha-5816b87",
            sid="sd", labels={"com.docker.stack.namespace": "aopwiki-dashboard",
                              "tgx.service.owner": "marvinm2"}),
        svc("toxtempass_djangoapp", "ghcr.io/j/toxtempassistant:v3.64.4", sid="sj",
            labels={"com.docker.stack.namespace": "toxtempass"}),
    ]
    ctx = ctx_for(swarm, mounts={"docs": tmp_path})
    o = await observe("docs_drift", ctx, mount="docs", aliases={"toxtempassistant": "toxtempass"},
                      ignore=["cronjobs", "nanolinks*"])
    v = o.values
    assert v["image_mismatch"] == [
        "arrayanalysis: docs arrayanalysis/arrayanalysis_shiny:0.1.4, live 0.1.5",
        "toxtempassistant: docs ghcr.io/j/toxtempassistant:v3.31.0, live v3.64.4"]
    assert v["missing_live"] == ["ghost"]
    assert v["missing_in_docs"] == ["aopsuite", "robot"]
    assert v["unknown_owner_labels"] == ["arrayanalysis: [e-mail]"]
    assert "@" not in json.dumps(v)
    o = await observe("docs_drift", ctx, mount="nope")
    assert o.unknown



async def test_job_run_slot_before_recording_started_is_unknown(swarm: FakeSwarm,
                                                               store: Store) -> None:
    """Swarm keeps only a few tasks per job: a slot before the monitor began recording
    cannot be judged, so it is unknown rather than a missed run."""
    swarm.tasks = [t for t in reload_tasks() if t["ID"] != "tok2"]
    store.set_meta("job_recorder_started", "2099-01-01T00:00:00+00:00")
    await record_job_runs(store, swarm.api())
    o = await observe("job_run", ctx_for(swarm, store), service="cronjobs_aopwiki-snorql-reload")
    assert o.unknown and "predates" in o.unknown
