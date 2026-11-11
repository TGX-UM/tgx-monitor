"""The socket-proxy allowlist, DockerAPI and the deploy doc agree, and nothing more opens.

Three sources must say the same thing: ``docker.ALLOWED_PATHS`` (the constant), the
``-allowGET`` flag in ``deploy/socket-proxy.md`` (what gets deployed) and the paths
:class:`DockerAPI` actually requests. The proxy anchors the pattern and matches the path
only, so ``re.fullmatch`` on the path is the faithful model of it.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest
from test_docker import FakeSwarm, frame, svc

from tgx_monitor import docker
from tgx_monitor.docker import ALLOWED_PATHS, API_VERSION

DOC = Path(__file__).resolve().parents[1] / "deploy" / "socket-proxy.md"
ALLOW = re.compile(ALLOWED_PATHS)

REFUSED = [
    "/v1.47/containers/0123abcd/json", "/v1.47/containers/0123abcd/archive",
    "/v1.47/containers/0123abcd/export", "/v1.47/containers/0123abcd/exec",
    "/v1.47/containers/0123abcd/logs", "/v1.47/exec/0123abcd/json", "/v1.47/exec",
    "/v1.47/secrets", "/v1.47/secrets/abc", "/v1.47/configs", "/v1.47/configs/abc",
    "/v1.47/images/traefik/get", "/v1.47/images/get", "/v1.47/images/traefik/json",
    "/v1.47/services/abc", "/v1.47/tasks/abc", "/v1.47/nodes/abc",
    "/v1.47/services/abc/logs", "/v1.47/tasks/../secrets/logs", "/v1.47/tasks/ABC/logs",
    "/v1.47/info/", "/v1.47/info/../secrets", "/v1.47/swarm", "/v1.47/swarm/unlockkey",
    "/v1.47/plugins", "/v1.47/volumes", "/v1.47/system/df", "/v1.47/distribution/x/json",
    "/v1.43/info", "/v1.54/info", "/info", "/version", "/v1.47/version", "/v1.47/_ping",
    "//v1.47/info", "/v1.47/infoX", "X/v1.47/info",
]


def _doc_flag(method: str) -> list[str]:
    return re.findall(rf"-allow{method}=([^'\s`]+)", DOC.read_text())


async def _exercise_every_method() -> FakeSwarm:
    s = FakeSwarm()
    s.services = [svc("bridgedb", "bigcatum/bridgedb:1@sha256:ab", sid="sb")]
    s.logs["abc123"] = frame("hello\n")
    api = s.api()
    now = dt.datetime(2026, 11, 11, tzinfo=dt.UTC)
    await api.endpoints()
    await api.services()
    await api.services({"name": ["bridgedb"]})
    await api.tasks()
    await api.tasks(service="bridgedb", desired_state="running")
    await api.nodes()
    await api.info()
    await api.info("tgx2")
    await api.images("tgx1")
    await api.containers("tgx2", all=True)
    await api.task_logs("abc123")
    await api.events(now - dt.timedelta(hours=1), now)
    await api.aclose()
    return s


async def test_dockerapi_requests_only_allowed_gets() -> None:
    s = await _exercise_every_method()
    assert s.requests
    for req in s.requests:
        assert req.method == "GET", req
        assert ALLOW.fullmatch(req.url.path), f"DockerAPI requests {req.url.path}, not allowed"


async def test_every_allowlist_branch_is_used() -> None:
    """The allowlist holds nothing DockerAPI does not need."""
    s = await _exercise_every_method()
    branches = re.search(r"/\((.*)\)$", ALLOWED_PATHS).group(1).split("|")
    paths = {r.url.path.split("/", 2)[2] for r in s.requests}
    for b in branches:
        assert any(re.fullmatch(b, p) for p in paths), f"allowlist branch {b!r} is unused"


@pytest.mark.parametrize("path", REFUSED)
def test_refused_paths(path: str) -> None:
    assert not ALLOW.fullmatch(path)


@pytest.mark.parametrize("minor", range(44, 54))
def test_supported_api_versions(minor: int) -> None:
    assert ALLOW.fullmatch(f"/v1.{minor}/info")


def test_configured_version_is_inside_the_allowlist() -> None:
    assert ALLOW.fullmatch(f"/{API_VERSION.strip('/')}/info")


def test_deploy_doc_carries_the_exact_flag_and_nothing_but_get() -> None:
    flags = _doc_flag("GET")
    assert flags and all(f == ALLOWED_PATHS for f in flags), flags
    for method in ("POST", "PUT", "DELETE", "HEAD", "PATCH", "CONNECT", "OPTIONS", "TRACE"):
        assert not re.search(rf"-allow{method}=", DOC.read_text()), method
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in DOC.read_text()
    assert "internal: true" in DOC.read_text()


def test_client_source_only_issues_get() -> None:
    src = Path(docker.__file__).read_text()
    assert set(re.findall(r'\.stream\("([A-Z]+)"', src)) == {"GET"}
    assert not re.search(r"\.(post|put|delete|patch|request)\(", src)
