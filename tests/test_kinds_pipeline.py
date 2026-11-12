"""host, gha, registry, security and self kinds, fully offline (fake Http, fake agents)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest

from tgx_monitor.catalogue import Check, Target
from tgx_monitor.http import Fetched
from tgx_monitor.kinds import KINDS, Context, run_probe
from tgx_monitor.kinds import pipeline as P
from tgx_monitor.model import Call, iso
from tgx_monitor.store import Store

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)

Route = Callable[[str, str, dict[str, Any]], tuple[int | None, dict[str, str], str] | str]


class FakeHttp:
    """Answers by a routing function; records (method, url, headers, kwargs)."""

    def __init__(self, route: Route) -> None:
        self.route = route
        self.seen: list[tuple[str, str, dict[str, str], dict[str, Any]]] = []

    async def fetch(self, method: str, url: str, **kw: Any) -> Fetched:
        headers = kw.get("headers") or {}
        self.seen.append((method, url, headers, kw))
        res = self.route(method, url, kw)
        call = Call(method=method, url=url, via=kw.get("via", "public"))
        if isinstance(res, str):
            return Fetched(call=call, error=res)
        status, hdrs, text = res
        call.status, call.ok = status, status is not None and status < 400
        return Fetched(call=call, status=status, headers=hdrs, text=text, final_url=url,
                       rate_limited=status == 429)


def ctx(route: Route | None = None, *, secrets: dict[str, str] | None = None,
        **kw: Any) -> Context:
    http = FakeHttp(route or (lambda m, u, k: (200, {}, "")))
    return Context(http=http, catalogue=None, secrets=lambda n: (secrets or {}).get(n),
                   now=lambda: NOW, **kw)  # type: ignore[arg-type]


def check(kind: str, request: dict[str, Any], via: list[str] | None = None,
          asserts: list[dict[str, Any]] | None = None) -> Check:
    return Check.model_validate({"id": "c-x", "kind": kind, "request": request,
                                 "via": via or ["public"],
                                 "assert": asserts or [{"that": "x", "exists": True}]})


TARGET = Target.model_validate({"id": "t-x", "name": "t", "class": "infra",
                                "owners": ["marvinm2"], "public": False})


# ====================================================================== host
class FakeAgents:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    async def signals(self) -> dict[str, Any]:
        return self.data


def snap(**over: Any) -> dict[str, Any]:
    base = {
        "node": "tgx1", "collected_at": iso(NOW - dt.timedelta(seconds=20)), "errors": {},
        "mdstat": {"arrays": {"md1": {"degraded": True, "status": "_U"}},
                   "degraded_arrays": ["md1"], "degraded_count": 1, "array_count": 3},
        "disk": {"rootfs": {"used_pct": 66.0, "free_gb": 6.2}},
        "memory": {"available_pct": 52.6}, "load": {"per_cpu15": 1.41},
        "boot": {"btime": 1793702592},
        "peer": {"node": "tgx2", "all_ok": True, "ports": {"2377": {"ok": True}}},
        "root_status": {"present": True, "mtime": NOW.timestamp() - 1800,
                        "content": {"gluster": {"heal_pending": 0, "split_brain": 0},
                                    "md": {"md1": {"state": "clean, degraded"}}}},
        "hidrive": {"dash": {"newest_mtime": NOW.timestamp() - 3 * 3600, "count": 14,
                             "entries": [{"name": "a"}] * 80}},
        "heartbeats": {"core": {"age_s": 12.0}, "tgx2": {"age_s": 30.0}},
        "hc": {"state": "sent", "kind": "success"},
    }
    base.update(over)
    return base


async def host(signal: str, data: dict[str, Any], via: str = "agent:tgx1",
               **kw: Any) -> Any:
    c = check("host", {"signal": signal}, via=[via])
    return await KINDS["host"]().observe(c, via, ctx(agents=FakeAgents(data), **kw))


async def test_host_mdstat_and_assertions_through_run_probe() -> None:
    c = check("host", {"signal": "mdstat"}, via=["agent:tgx1"],
              asserts=[{"that": "degraded_arrays", "len_eq": 0}])
    r = await run_probe(TARGET, c, "c-x", "agent:tgx1",
                        ctx(agents=FakeAgents({"tgx1": snap()})))
    assert r.status == "failed" and "degraded_arrays" in r.summary


async def test_host_value_shapes() -> None:
    data = {"tgx1": snap()}
    assert (await host("disk", data)).values["disk"]["rootfs"]["used_pct"] == 66.0
    assert (await host("memory", data)).values["mem"]["available_pct"] == 52.6
    assert (await host("peer", data)).values["peer"]["all_ok"] is True
    rs = (await host("root_status", data)).values
    assert rs["present"] and rs["age_h"] == pytest.approx(0.5)
    assert rs["gluster"]["split_brain"] == 0 and rs["md"]["md1"]["state"] == "clean, degraded"
    hd = (await host("hidrive", data)).values["hidrive"]["dash"]
    assert hd["newest_age_h"] == pytest.approx(3.0) and len(hd["entries"]) == 50


async def test_host_unreachable_agent_is_unknown_but_agent_signal_says_so() -> None:
    data = {"tgx2": {"error": "no agent answered for tgx2"}}
    o = await host("mdstat", data, via="agent:tgx2")
    assert o.unknown and "did not answer" in o.unknown and o.error is None
    o = await host("agent", data, via="agent:tgx2")
    assert o.values["reachable"] is False and o.unknown is None
    o = await host("agent", {"tgx1": snap()})
    assert o.values["reachable"] and o.values["heartbeats"]["core"] == 12.0


async def test_host_stale_snapshot_and_signal_error_are_unknown() -> None:
    old = snap(collected_at=iso(NOW - dt.timedelta(minutes=10)))
    assert "no fresh data" in (await host("disk", {"tgx1": old})).unknown
    broken = snap(errors={"mdstat": "FileNotFoundError"})
    del broken["mdstat"]
    assert "could not read mdstat" in (await host("mdstat", {"tgx1": broken})).unknown
    o = await KINDS["host"]().observe(check("host", {"signal": "disk"}, via=["agent:tgx1"]),
                                      "agent:tgx1", ctx())
    assert o.unknown == "no agent client in this process"


async def test_host_boot_change_against_stored_baseline() -> None:
    store = Store(":memory:")
    store.execute("INSERT INTO metrics(probe_id,path,ts,value) VALUES(?,?,?,?)",
                  ("c-x", "boot.btime", iso(NOW - dt.timedelta(hours=1)), 1792000000.0))
    o = await host("boot", {"tgx1": snap()}, store=store)
    assert o.values["boot"]["changed"] is True
    assert o.values["boot"]["previous_btime"] == 1792000000
    assert o.metrics == {"boot.btime": 1793702592.0}


def test_host_validation() -> None:
    assert KINDS["host"].validate_request({"signal": "nope"}, ["agent:tgx1"])
    assert KINDS["host"].validate_request({"signal": "disk"}, ["public"])
    assert not KINDS["host"].validate_request({"signal": "disk"}, ["agent:tgx1", "agent:tgx2"])


# ====================================================================== gha
WF = '{"id": 96239266, "name": "RDF Generation", "state": "active", ' \
     '"path": ".github/workflows/rdfgeneration.yml", "html_url": "https://github.com/x"}'
RUNS = ('{"total_count": 68, "workflow_runs": ['
        '{"status": "in_progress", "conclusion": null, "created_at": "2026-11-11T10:00:00Z",'
        ' "event": "schedule", "head_sha": "abc", "html_url": "https://github.com/r/2"},'
        '{"status": "completed", "conclusion": "success", "created_at": "2026-11-07T12:00:00Z",'
        ' "updated_at": "2026-11-07T12:30:00Z", "event": "schedule"}]}')


@pytest.fixture(autouse=True)
def clear_etags() -> None:
    P._ETAGS.clear()


def gh_route(m: str, u: str, k: dict[str, Any]) -> Any:
    if u.endswith("/runs?per_page=5"):
        return 200, {"etag": 'W/"runs1"'}, RUNS
    if "/actions/workflows/" in u:
        if (k.get("headers") or {}).get("If-None-Match") == 'W/"wf1"':
            return 304, {}, ""
        return 200, {"etag": 'W/"wf1"'}, WF
    return 404, {}, "{}"


async def test_gha_values_and_etag_reuse() -> None:
    c = ctx(gh_route, secrets={"tgxmon_gh_token": "t0ken"})
    chk = check("gha", {"repo": "marvinm2/AOPWikiRDF", "workflow": "rdfgeneration.yml"})
    o = await KINDS["gha"]().observe(chk, "public", c)
    v = o.values
    assert (v["state"], v["last_status"], v["completed_conclusion"]) == (
        "active", "in_progress", "success")
    assert v["last_run_age_h"] == pytest.approx(2.0)
    assert v["completed_age_h"] == pytest.approx(95.5)
    assert v["last_success_at"] == "2026-11-07T12:00:00Z" and v["auth"] == "token"
    assert c.http.seen[0][2]["Authorization"] == "Bearer t0ken"
    o2 = await KINDS["gha"]().observe(chk, "public", c)
    assert o2.values["state"] == "active"
    assert "304" in o2.calls[0].note
    assert c.http.seen[2][2]["If-None-Match"] == 'W/"wf1"'


async def test_gha_rate_limit_is_unknown_and_404_is_error() -> None:
    limited = ctx(lambda m, u, k: (403, {"x-ratelimit-remaining": "0"}, "API rate limit"))
    chk = check("gha", {"repo": "a/b", "workflow": "w.yml"})
    o = await KINDS["gha"]().observe(chk, "public", limited)
    assert o.unknown and "rate limit" in o.unknown and o.error is None
    o = await KINDS["gha"]().observe(chk, "public", ctx(lambda m, u, k: (404, {}, "{}")))
    assert o.error and "404" in o.error


async def test_gha_rejected_token_falls_back_to_anonymous() -> None:
    def route(m: str, u: str, k: dict[str, Any]) -> Any:
        if "Authorization" in (k.get("headers") or {}):
            return 401, {}, "Bad credentials"
        return gh_route(m, u, k)

    c = ctx(route, secrets={"tgxmon_gh_token": "expired"})
    o = await KINDS["gha"]().observe(
        check("gha", {"repo": "a/b", "workflow": "w.yml"}), "public", c)
    assert o.values["auth"] == "anonymous" and o.values["state"] == "active"


async def test_gha_repo_wide_states() -> None:
    body = ('{"workflows": [{"path": ".github/workflows/verify.yml", "state": '
            '"disabled_inactivity"}, {"path": ".github/workflows/build.yml", "state": "active"},'
            ' {"path": ".github/workflows/old.yml", "state": "disabled_manually"}]}')
    c = ctx(lambda m, u, k: (200, {}, body))
    o = await KINDS["gha"]().observe(check("gha", {"repo": "bridgedb/docker"}), "public", c)
    assert o.values["inactive"] == ["verify.yml"]
    assert o.values["disabled"] == ["old.yml", "verify.yml"] and o.values["count"] == 3


# ====================================================================== registry
@pytest.mark.parametrize("ref,expect", [
    ("ghcr.io/vhp4safety/oppbk:latest", ("ghcr.io", "vhp4safety/oppbk", "latest")),
    ("vhp4safety/virtual-human-platform:1.0-6",
     ("docker.io", "vhp4safety/virtual-human-platform", "1.0-6")),
    ("docker.io/library/postgres:17", ("docker.io", "library/postgres", "17")),
    ("postgres", ("docker.io", "library/postgres", "latest")),
    ("localhost:5000/x/y@sha256:ab", ("localhost:5000", "x/y", "sha256:ab")),
])
def test_parse_image(ref: str, expect: tuple[str, str, str]) -> None:
    assert P.parse_image(ref) == expect


CHALLENGE = {"www-authenticate":
             'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
             'scope="repository:vhp4safety/oppbk:pull"'}


def registry_route(private: bool) -> Route:
    def route(m: str, u: str, k: dict[str, Any]) -> Any:
        h = k.get("headers") or {}
        if u == "https://ghcr.io/token":
            if private and not h.get("Authorization", "").startswith("Basic "):
                return 403, {}, '{"errors": [{"code": "DENIED"}]}'
            return 200, {}, '{"token": "tok"}'
        assert m == "HEAD"
        if h.get("Authorization") == "Bearer tok":
            return 200, {"docker-content-digest": "sha256:d1"}, ""
        return 401, CHALLENGE, ""
    return route


class FakeDocker:
    async def images(self, node: str, calls: list[Call] | None = None) -> list[dict[str, Any]]:
        if node == "tgx1":
            return [{"RepoTags": ["ghcr.io/vhp4safety/oppbk:latest"],
                     "RepoDigests": ["ghcr.io/vhp4safety/oppbk@sha256:d1"]}]
        return [{"RepoTags": ["other:1"]}]


class HalfDocker(FakeDocker):
    async def images(self, node: str, calls: list[Call] | None = None) -> list[dict[str, Any]]:
        if node == "tgx2":
            raise RuntimeError("proxy on tgx2 unreachable")
        return await super().images(node, calls)


async def test_registry_public_with_nodes() -> None:
    c = ctx(registry_route(private=False), docker=FakeDocker())
    o = await KINDS["registry"]().observe(
        check("registry", {"image": "ghcr.io/vhp4safety/oppbk:latest"}), "public", c)
    v = o.values
    assert v["reachable"] and v["digest"] == "sha256:d1" and v["auth"] == "anonymous"
    assert v["present_on_nodes"] == ["tgx1"] and v["missing_on_nodes"] == ["tgx2"]
    assert v["node_digest_match"] == {"tgx1": True}
    assert {s[0] for s in c.http.seen} <= {"HEAD", "GET"}
    c = ctx(registry_route(private=False), docker=HalfDocker())
    o = await KINDS["registry"]().observe(
        check("registry", {"image": "ghcr.io/vhp4safety/oppbk:latest"}), "public", c)
    assert o.values["nodes_unknown"] == ["tgx2"] and o.values["missing_on_nodes"] == []


class DigestOnlyDocker(FakeDocker):
    """tgx2 pulled the image by digest only (a tag@digest service pin): no RepoTags."""
    async def images(self, node: str, calls: list[Call] | None = None) -> list[dict[str, Any]]:
        if node == "tgx2":
            return [{"RepoTags": [], "RepoDigests": ["ghcr.io/vhp4safety/oppbk@sha256:d1"]},
                    {"RepoTags": [], "RepoDigests": ["ghcr.io/vhp4safety/oppbk@sha256:old"]}]
        return await super().images(node, calls)


async def test_registry_digest_only_image_counts_as_present() -> None:
    c = ctx(registry_route(private=False), docker=DigestOnlyDocker())
    o = await KINDS["registry"]().observe(
        check("registry", {"image": "ghcr.io/vhp4safety/oppbk:latest"}), "public", c)
    v = o.values
    assert v["present_on_nodes"] == ["tgx1", "tgx2"] and v["missing_on_nodes"] == []
    assert v["node_digest_match"] == {"tgx1": True, "tgx2": True}


async def test_registry_private_needs_pat() -> None:
    chk = check("registry", {"image": "ghcr.io/vhp4safety/oppbk:latest"})
    o = await KINDS["registry"]().observe(chk, "public", ctx(registry_route(private=True)))
    assert o.unknown and "tgxmon_ghcr_read_pat" in o.unknown
    c = ctx(registry_route(private=True), secrets={"tgxmon_ghcr_read_pat": "ghp_x"})
    o = await KINDS["registry"]().observe(chk, "public", c)
    assert o.values["auth"] == "pat" and o.values["reachable"]
    assert "present_on_nodes" not in o.values  # no docker client in this context


# ====================================================================== security
def test_security_validation_refuses_writes() -> None:
    v = KINDS["security"].validate_request
    assert v({"url": "https://x/", "method": "POST", "expect_status": [403]}, ["public"])
    assert v({"url": "http://{node_ip}:8080/", "expect_status": [401]}, ["public"])
    assert v({"url": "https://x/"}, ["public"])
    assert not v({"url": "http://{node_ip}:8080/", "expect_status": [401]}, ["tgx1", "tgx2"])


async def test_security_exposed_by_status_or_marker() -> None:
    page = (200, {"server": "Virtuoso"}, "<title>Virtuoso Conductor</title>")
    chk = check("security", {"url": "https://aopdb.example/conductor/",
                             "expect_status": [401, 403, 404],
                             "absent_markers": ["Virtuoso Conductor"]})
    o = await KINDS["security"]().observe(chk, "public", ctx(lambda m, u, k: page))
    assert o.values["exposed"] and o.values["markers_found"] == ["Virtuoso Conductor"]
    assert "Conductor</title>" not in o.evidence  # the body is never kept
    o = await KINDS["security"]().observe(chk, "public", ctx(lambda m, u, k: (403, {}, "no")))
    assert o.values["exposed"] is False


async def test_security_closed_port_is_fine_and_node_ip_is_substituted() -> None:
    c = ctx(lambda m, u, k: "ConnectError: refused")
    chk = check("security", {"url": "http://{node_ip}:8080/dashboard/",
                             "expect_status": [401]}, via=["tgx1", "tgx2"])
    o = await KINDS["security"]().observe(chk, "tgx2", c)
    assert o.error is None and o.values["exposed"] is False and not o.values["reachable"]
    method, url, _, kw = c.http.seen[0]
    assert (method, url, kw["via"]) == ("GET", "http://85.214.252.63:8080/dashboard/", "public")


# ====================================================================== self
async def test_self_store_signals() -> None:
    store = Store(":memory:")
    c = ctx(store=store)
    run = KINDS["self"]().observe
    assert (await run(check("self", {"signal": "tick"}, via=["core"]), "core", c)).unknown
    store.set_meta("last_tick", iso(NOW - dt.timedelta(seconds=90)))
    o = await run(check("self", {"signal": "tick"}, via=["core"]), "core", c)
    assert o.values["tick_age_s"] == pytest.approx(90)
    for created, dry, dead in ((NOW - dt.timedelta(minutes=30), 0, 0),
                               (NOW - dt.timedelta(minutes=90), 1, 0),
                               (NOW - dt.timedelta(minutes=5), 0, 1)):
        store.execute("INSERT INTO outbox(created_at,channel,event,payload,next_attempt_at,"
                      "dry_run,dead) VALUES(?,?,?,?,?,?,?)",
                      (iso(created), "slack", "open", "{}", iso(created), dry, dead))
    o = await run(check("self", {"signal": "outbox"}, via=["core"]), "core", c)
    assert o.values == {"pending": 1, "oldest_pending_age_min": 30.0, "dead_letters": 1}
    o = await run(check("self", {"signal": "selftest"}, via=["core"]), "core", c)
    assert o.values["broken"] is False
    store.set_meta("selftest_broken", "1")
    o = await run(check("self", {"signal": "selftest"}, via=["core"]), "core", c)
    assert o.values["broken"] is True


async def test_self_token_expiry() -> None:
    hdr = {"github-authentication-token-expiration": "2026-12-01 12:00:00 UTC",
           "x-ratelimit-remaining": "4999"}
    c = ctx(lambda m, u, k: (200, hdr, "{}"), secrets={"tgxmon_gh_token": "t"})
    o = await KINDS["self"]().observe(check("self", {"signal": "token"}, via=["core"]),
                                      "core", c)
    assert o.values["days_left"] == pytest.approx(20.0) and o.values["rate_remaining"] == 4999
    assert c.http.seen[0][1].endswith("/rate_limit")
    o = await KINDS["self"]().observe(check("self", {"signal": "token"}, via=["core"]),
                                      "core", ctx(secrets={}))
    assert o.unknown and "tgxmon_gh_token" in o.unknown
    assert P.parse_expiry("2026-12-01 12:00:00 +0100") == dt.datetime(
        2026, 12, 1, 11, 0, tzinfo=dt.UTC)


async def test_self_vantage(monkeypatch: pytest.MonkeyPatch) -> None:
    from tgx_monitor import agent

    async def fake_tcp(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
        return {"ok": (host, port) == ("1.1.1.1", 53), "ms": 3.0}

    monkeypatch.setattr(agent, "tcp_probe", fake_tcp)
    o = await KINDS["self"]().observe(check("self", {"signal": "vantage"}, via=["core"]),
                                      "core", ctx(lambda m, u, k: (429, {}, "")))
    assert o.values["vantage_ok"] is True and o.values["github_status"] == 429
    o = await KINDS["self"]().observe(check("self", {"signal": "vantage"}, via=["core"]),
                                      "core", ctx(lambda m, u, k: "ConnectError"))
    assert o.values["vantage_ok"] is False


async def test_github_reads_prefer_the_pat_then_the_app_then_anonymous() -> None:
    from tgx_monitor.kinds.base import github_read_token

    async def app() -> str | None:
        return "app-tok"

    async def broken() -> str | None:
        raise RuntimeError("key refused")

    def ctx(secrets: dict[str, str], provider: Any) -> Context:
        return Context(http=None, catalogue=None, secrets=secrets.get,  # type: ignore[arg-type]
                       gh_app_token=provider)

    assert await github_read_token(ctx({"tgxmon_gh_token": "pat"}, app)) == ("pat", "token")
    assert await github_read_token(ctx({}, app)) == ("app-tok", "app")
    assert await github_read_token(ctx({}, broken)) == (None, "anonymous")
    assert await github_read_token(ctx({}, None)) == (None, "anonymous")
