"""DockerAPI against a fake two-node swarm, offline.

``FakeSwarm`` answers like the real engines did on 2026-11-11 (shapes taken from live
GETs on tgx1 and tgx2, Env stripped): two proxies, ``p1`` (tgx1) and ``p2`` (tgx2), each
with its own images, containers and events; swarm-wide objects are the same on both.
The infra-kind and proxy-contract tests reuse it.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import httpx
import pytest

from tgx_monitor.docker import DockerAPI, DockerError, demux, node_alias, parse_ts

NODE_IDS = {"tgx1": "7rndtzofc52aedxyxv38airpi", "tgx2": "ipniz5ps89mrcoe8wzxl8p9cm"}
HOSTS = {"p1": "tgx1", "p2": "tgx2"}
HOSTNAMES = {"tgx1": "h3068544.stratoserver.net", "tgx2": "h2973005.stratoserver.net"}


def svc(name: str, image: str, *, sid: str | None = None, replicas: int | None = 1,
        running: int | None = None, labels: dict[str, str] | None = None,
        constraints: list[str] | None = None, restart: str | None = "any",
        created: str = "2026-10-01T10:00:00.123456789Z") -> dict[str, Any]:
    mode = {"Global": {}} if replicas is None else {"Replicated": {"Replicas": replicas}}
    want = 2 if replicas is None else replicas
    return {
        "ID": sid or f"s{abs(hash(name)) % 10**12:012d}", "CreatedAt": created,
        "UpdatedAt": created,
        "Spec": {
            "Name": name, "Labels": labels or {},
            "TaskTemplate": {
                "ContainerSpec": {"Image": image, "Env": ["POSTGRES_PASSWORD=hunter2"],
                                  "Args": ["--token", "ghp_abcdefghijklmnopqrstuvwx"]},
                "RestartPolicy": {"Condition": restart, "MaxAttempts": 0} if restart else None,
                "Placement": {"Constraints": constraints or []},
            },
            "Mode": mode,
        },
        "ServiceStatus": {"RunningTasks": want if running is None else running,
                          "DesiredTasks": want, "CompletedTasks": 0},
    }


def task(tid: str, service_id: str, state: str, ts: str, *, exit_code: int | None = None,
         node: str = "tgx1", created: str | None = None,
         desired: str = "shutdown") -> dict[str, Any]:
    status: dict[str, Any] = {"Timestamp": ts, "State": state, "Message": "started"}
    if exit_code is not None:
        status["ContainerStatus"] = {"ContainerID": "c" * 64, "PID": 0, "ExitCode": exit_code}
        if exit_code:
            status["Err"] = f"task: non-zero exit ({exit_code})"
    return {"ID": tid, "ServiceID": service_id, "NodeID": NODE_IDS[node], "Slot": 1,
            "CreatedAt": created or ts, "UpdatedAt": ts, "DesiredState": desired,
            "Status": status, "Spec": {"ContainerSpec": {"Image": "x", "Env": ["A=b"]}}}


def node(alias: str, *, state: str = "ready", leader: bool = False,
         reach: str = "reachable", availability: str = "active") -> dict[str, Any]:
    ms: dict[str, Any] = {"Reachability": reach, "Addr": "10.0.0.1:2377"}
    if leader:
        ms["Leader"] = True
    return {"ID": NODE_IDS[alias], "Spec": {"Labels": {}, "Role": "manager",
                                            "Availability": availability},
            "Description": {"Hostname": HOSTNAMES[alias], "Platform": {"OS": "linux"}},
            "Status": {"State": state, "Addr": "10.0.0.1"}, "ManagerStatus": ms}


def image(tags: list[str], digests: list[str] | None = None, iid: str = "") -> dict[str, Any]:
    return {"Id": iid or f"sha256:{abs(hash(tuple(tags))) % 10**12:064d}", "RepoTags": tags,
            "RepoDigests": digests or [], "Labels": {}}


def container(service: str, image_id: str, node_alias_: str = "tgx1") -> dict[str, Any]:
    return {"Id": "c" * 64, "Names": [f"/{service}.1.x"], "Image": "img", "ImageID": image_id,
            "State": "running",
            "Labels": {"com.docker.swarm.service.name": service,
                       "com.docker.swarm.node.id": NODE_IDS[node_alias_]}}


def frame(text: str, stream: int = 1) -> bytes:
    b = text.encode()
    return bytes([stream, 0, 0, 0]) + len(b).to_bytes(4, "big") + b


class FakeSwarm:
    """An httpx MockTransport handler standing in for the two proxies."""

    def __init__(self) -> None:
        self.services: list[dict[str, Any]] = []
        self.tasks: list[dict[str, Any]] = []
        self.nodes = [node("tgx1", leader=True), node("tgx2")]
        self.images: dict[str, list[dict[str, Any]]] = {"tgx1": [], "tgx2": []}
        self.containers: dict[str, list[dict[str, Any]]] = {"tgx1": [], "tgx2": []}
        self.events: dict[str, list[dict[str, Any]]] = {"tgx1": [], "tgx2": []}
        self.logs: dict[str, bytes] = {}
        self.down: set[str] = set()  # node aliases whose proxy refuses connections
        self.status_override: dict[str, tuple[int, str]] = {}  # path suffix -> (status, msg)
        self.requests: list[httpx.Request] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def api(self, **kw: Any) -> DockerAPI:
        return DockerAPI(["http://p1:2375", "http://p2:2375"], transport=self.transport(), **kw)

    def handle(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        alias = HOSTS[req.url.host]
        if alias in self.down:
            raise httpx.ConnectError("connection refused", request=req)
        path = req.url.path.split("/", 2)[2]  # strip /v1.47
        for suffix, (code, msg) in self.status_override.items():
            if path.endswith(suffix):
                return httpx.Response(code, json={"message": msg})
        q = req.url.params
        filters = json.loads(q["filters"]) if "filters" in q else {}
        if path == "info":
            return httpx.Response(200, json={"Name": HOSTNAMES[alias], "Swarm": {
                "NodeID": NODE_IDS[alias], "ControlAvailable": True}})
        if path == "services":
            names = filters.get("name")
            return httpx.Response(200, json=[
                s for s in self.services if not names or s["Spec"]["Name"].startswith(names[0])])
        if path == "tasks":
            out = self.tasks
            if "service" in filters:
                ids = {s["ID"] for s in self.services if s["Spec"]["Name"] in filters["service"]}
                out = [t for t in out if t["ServiceID"] in ids]
            return httpx.Response(200, json=out)
        if path == "nodes":
            return httpx.Response(200, json=self.nodes)
        if path == "images/json":
            return httpx.Response(200, json=self.images[alias])
        if path == "containers/json":
            return httpx.Response(200, json=self.containers[alias])
        if path == "events":
            body = "\n".join(json.dumps(e) for e in self.events[alias]) + "\n"
            return httpx.Response(200, text=body, headers={"content-type": "application/jsonl"})
        if path.startswith("tasks/") and path.endswith("/logs"):
            tid = path.split("/")[1]
            if tid not in self.logs:
                return httpx.Response(404, json={"message": f"task {tid} not found"})
            return httpx.Response(200, content=self.logs[tid], headers={
                "content-type": "application/vnd.docker.multiplexed-stream"})
        return httpx.Response(403, text="Forbidden")


@pytest.fixture
def swarm() -> FakeSwarm:
    s = FakeSwarm()
    s.services = [svc("bridgedb", "bigcatum/bridgedb:3.0.31-2.1.9@sha256:ab66", sid="sb")]
    return s


# ---------------------------------------------------------------------- tests
def test_node_alias_and_timestamps() -> None:
    assert node_alias("h3068544.stratoserver.net") == "tgx1"
    assert node_alias("h2973005") == "tgx2"
    assert node_alias("other.example") == "other"
    ts = parse_ts("2026-10-23T06:21:44.851099926Z")
    assert ts == dt.datetime(2026, 10, 23, 6, 21, 44, 851099, tzinfo=dt.UTC)
    assert parse_ts("0001-01-01T00:00:00Z") is None
    assert parse_ts("garbage") is None


async def test_endpoints_map_both_nodes(swarm: FakeSwarm) -> None:
    api = swarm.api()
    eps = await api.endpoints()
    assert sorted(eps) == ["tgx1", "tgx2"]
    assert eps["tgx2"].hostname == "h2973005.stratoserver.net"
    assert eps["tgx1"].node_id == NODE_IDS["tgx1"]
    await api.aclose()


async def test_base_urls_may_be_an_async_callable(swarm: FakeSwarm) -> None:
    async def urls() -> list[str]:
        return ["http://p2:2375"]

    api = DockerAPI(urls, transport=swarm.transport())
    assert list(await api.endpoints()) == ["tgx2"]


async def test_services_are_redacted(swarm: FakeSwarm) -> None:
    calls: list = []
    out = await swarm.api().services(calls=calls)
    blob = json.dumps(out)
    assert "hunter2" not in blob and "ghp_" not in blob and '"Env"' not in blob
    assert out[0]["Spec"]["Name"] == "bridgedb"
    assert calls[-1].url == "docker://tgx1/v1.47/services" and calls[-1].ok
    assert swarm.requests[-1].url.params["status"] == "true"


async def test_nodes_keep_hostname_alias(swarm: FakeSwarm) -> None:
    out = await swarm.api().nodes()
    assert [(n["Alias"], n["NodeHostname"]) for n in out] == [
        ("tgx1", "h3068544.stratoserver.net"), ("tgx2", "h2973005.stratoserver.net")]
    # The node's own hostname is kept (only container-spec hostnames are dropped).
    assert out[0]["Description"]["Hostname"] == "h3068544.stratoserver.net"


async def test_swarm_wide_call_falls_over_to_tgx2(swarm: FakeSwarm) -> None:
    api = swarm.api()
    await api.endpoints()
    swarm.down.add("tgx1")
    calls: list = []
    out = await api.services(calls=calls)
    assert out and calls[0].url.startswith("docker://tgx1") and not calls[0].ok
    assert calls[-1].url.startswith("docker://tgx2") and calls[-1].ok


async def test_client_error_is_final_and_server_error_falls_over(swarm: FakeSwarm) -> None:
    api = swarm.api()
    swarm.status_override["nodes"] = (503, "The swarm does not have a leader.")
    with pytest.raises(DockerError) as exc:
        await api.nodes()
    assert exc.value.status == 503 and "leader" in str(exc.value)
    with pytest.raises(DockerError) as exc:
        await api.task_logs("doesnotexist")
    assert exc.value.status == 404
    logs = [r for r in swarm.requests if r.url.path.endswith("/logs")]
    assert len(logs) == 1  # a 404 is not retried on the other node


async def test_no_endpoint_at_all(swarm: FakeSwarm) -> None:
    swarm.down |= {"tgx1", "tgx2"}
    with pytest.raises(DockerError, match="no docker-proxy"):
        await swarm.api().services()


async def test_task_logs_demux_and_redact(swarm: FakeSwarm) -> None:
    swarm.logs["abc123"] = (frame("starting\n") + frame("password=s3cret\n", 2)
                            + frame("TGXMON-MARKER triples=340667\n"))
    lines = await swarm.api().task_logs("abc123", tail=200)
    assert lines == ["starting", "password=[redacted]", "TGXMON-MARKER triples=340667"]
    assert swarm.requests[-1].url.params["tail"] == "200"
    assert demux(b"plain tty output\n") == "plain tty output\n"


async def test_task_logs_reject_odd_ids_without_asking(swarm: FakeSwarm) -> None:
    with pytest.raises(DockerError, match="not a task id"):
        await swarm.api().task_logs("../../secrets")
    assert not swarm.requests


async def test_node_local_calls_hit_that_node(swarm: FakeSwarm) -> None:
    swarm.images["tgx2"] = [image(["robot:1.4"])]
    api = swarm.api()
    assert (await api.images("tgx2"))[0]["RepoTags"] == ["robot:1.4"]
    assert swarm.requests[-1].url.host == "p2"
    await api.containers("tgx1")
    assert swarm.requests[-1].url.host == "p1"
    with pytest.raises(DockerError, match="no docker-proxy answering on tgx9"):
        await api.images("tgx9")


async def test_events_bounded_and_tagged(swarm: FakeSwarm) -> None:
    swarm.events["tgx1"] = [{"Action": "die", "Actor": {"Attributes": {"exitCode": "137"}}}]
    swarm.events["tgx2"] = [{"Action": "die", "Actor": {"Attributes": {"exitCode": "0"}}}]
    now = dt.datetime(2026, 11, 11, 12, tzinfo=dt.UTC)
    out = await swarm.api().events(now - dt.timedelta(hours=1), now,
                                   {"type": ["container"], "event": ["die"]})
    assert sorted(e["_node"] for e in out) == ["tgx1", "tgx2"]
    q = swarm.requests[-1].url.params
    assert int(q["until"]) - int(q["since"]) == 3600
    assert json.loads(q["filters"]) == {"type": ["container"], "event": ["die"]}


async def test_exec_event_command_lines_are_redacted(swarm: FakeSwarm) -> None:
    """exec_create/exec_start events carry the command line, secrets included."""
    cmd = "exec_start: sh -c PGPASSWORD=hunter2 psql"
    swarm.events["tgx1"] = [{"Action": cmd, "status": cmd, "Actor": {"Attributes": {}}}]
    now = dt.datetime(2026, 11, 11, 12, tzinfo=dt.UTC)
    out = await swarm.api().events(now - dt.timedelta(hours=1), now, node="tgx1")
    assert out and "hunter2" not in json.dumps(out)
    assert out[0]["Action"].startswith("exec_start: sh -c PGPASSWORD=")
