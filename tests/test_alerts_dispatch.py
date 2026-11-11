"""Outbox delivery: retries, dead letters, self alerts, storm brake, dry run, channels."""

from __future__ import annotations

import datetime as dt
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from test_alerts_support import T0, Clock, StubChannel, World

from tgx_monitor.alerts import outbox
from tgx_monitor.alerts.channels.base import Message
from tgx_monitor.alerts.channels.github import GitHubChannel
from tgx_monitor.alerts.channels.hc import HcChannel
from tgx_monitor.alerts.channels.slack import SlackChannel, blocks
from tgx_monitor.alerts.channels.smtp import SmtpChannel
from tgx_monitor.alerts.dispatcher import Dispatcher, build_channels
from tgx_monitor.store import Store


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


async def test_slack_500_retries_dead_letter_and_self_alert(tmp_path) -> None:
    w = World(tmp_path, fail={"slack": 500})
    for _ in range(4):
        w.cycle({"app-a"})
    slack_row = w.rows(channel="slack", event="open")[0]
    gaps = []
    for _ in range(8):
        await w.dispatch()
        row = w.store.one("SELECT * FROM outbox WHERE id=?", (slack_row["id"],))
        if row["dead"]:
            break
        nxt = dt.datetime.fromisoformat(row["next_attempt_at"])
        gaps.append(round((nxt - w.clock()).total_seconds() / 60))
        w.clock.t = nxt
    assert gaps == [1, 2, 4, 8, 16, 32, 60]
    assert row["dead"] == 1 and row["attempts"] == 8 and json.loads(row["reply"])["status"] == 500
    selfs = w.rows(event="self")
    assert [(r["channel"], r["recipients"]) for r in selfs] == [("smtp", ["marvinm2", "egonw"])]
    await w.dispatch()
    assert "delivery via slack failing" in w.channels["smtp"].sent[-1].payload["subject"]
    assert len(w.channels["slack"].sent) == 8
    assert [r["id"] for r in outbox.listing(w.store, "dead")] == [slack_row["id"]]


async def test_github_comment_waits_for_open(world: World) -> None:
    w = world
    w.channels["github"].fail = 502
    for _ in range(4):
        w.cycle({"app-a"})
    w.cycle()
    w.cycle()  # recovered: a close row queued behind the failed open
    await w.dispatch()
    assert w.channels["github"].actions() == ["open"], "close must not overtake the open"
    w.channels["github"].fail = None
    w.clock.advance(minutes=2)
    await w.dispatch()
    assert w.channels["github"].actions() == ["open", "open", "close"]
    assert w.channels["github"].sent[-1].issue_number == 101


async def test_storm_brake_collapses_burst(tmp_path) -> None:
    store = Store(":memory:")
    clock = Clock()
    with store.transaction() as db:
        for i in range(12):
            outbox.enqueue(db, channel="slack", event="open", now=clock(),
                           payload={"text": f"t{i}", "line": f"line {i}"})
    slack = StubChannel("slack")
    stats = await Dispatcher(store, {"slack": slack}, now=clock).run_once()
    assert len(slack.sent) == 1 and "12 alerts" in slack.sent[0].payload["text"]
    assert stats == {"sent": 1}
    assert store.one("SELECT COUNT(*) AS n FROM outbox WHERE sent_at IS NULL")["n"] == 0


async def test_slack_hourly_cap(tmp_path) -> None:
    store = Store(":memory:")
    clock = Clock()
    slack = StubChannel("slack")
    d = Dispatcher(store, {"slack": slack}, now=clock)
    for _ in range(25):
        with store.transaction() as db:
            outbox.enqueue(db, channel="slack", event="open", now=clock(), payload={"text": "x"})
        await d.run_once()
        clock.advance(minutes=2)
    assert len(slack.sent) == 20


async def test_dry_run_logs_only(tmp_path) -> None:
    store = Store(":memory:")
    with store.transaction() as db:
        outbox.enqueue(db, channel="github", event="open", now=T0, dry_run=True,
                       payload={"action": "open", "title": "x", "body": "y"})
        outbox.enqueue(db, channel="nowhere", event="open", now=T0, payload={})
    gh = StubChannel("github")
    stats = await Dispatcher(store, {"github": gh}, now=lambda: T0).run_once()
    assert not gh.sent and stats == {"dry_run": 1, "unconfigured": 1}


def _mock(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


async def test_github_app_auth_open_and_close() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    calls: list[tuple[str, str, str]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, req.headers.get("authorization", "")))
        if req.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_inst", "expires_at":
                                             "2026-11-11T10:00:00Z"})
        if req.method == "POST" and req.url.path.endswith("/issues"):
            assert json.loads(req.content)["labels"] == ["alert"]
            return httpx.Response(201, json={"number": 7, "html_url": "u"})
        if req.method == "GET":
            return httpx.Response(200, json=[{"number": 7, "body": "b", "labels": [
                {"name": "alert"}]}, {"number": 8, "pull_request": {}}])
        return httpx.Response(201 if req.method == "POST" else 200, json={})

    gh = GitHubChannel("org/repo", app_id="1", installation_id="2", app_key=pem,
                       transport=_mock(handler), now=lambda: T0)
    ok, reply = await gh.send(Message(1, "github", "open", [], {
        "action": "open", "title": "t", "body": "b", "labels": ["alert"]}))
    assert ok and reply["number"] == 7
    ok, _ = await gh.send(Message(2, "github", "close", [], {"action": "close",
                                                             "comment": "done"}, 7))
    assert ok
    assert [c[:2] for c in calls] == [("POST", "/app/installations/2/access_tokens"),
                                      ("POST", "/repos/org/repo/issues"),
                                      ("POST", "/repos/org/repo/issues/7/comments"),
                                      ("PATCH", "/repos/org/repo/issues/7")]
    assert calls[1][2] == "Bearer ghs_inst" and calls[0][2].startswith("Bearer ey")
    assert [i["number"] for i in await gh.open_alert_issues()] == [7]


async def test_github_pat_fallback_and_errors() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"] == "Bearer pat"
        return httpx.Response(403, json={})

    gh = GitHubChannel("o/r", token="pat", transport=_mock(handler))
    ok, reply = await gh.send(Message(1, "github", "open", [], {"action": "open", "title": "t",
                                                                "body": "b"}))
    assert not ok and reply["status"] == 403
    ok, reply = await gh.send(Message(1, "github", "comment", [], {"comment": "c"}))
    assert not ok and "no issue number" in reply["error"]
    ok, reply = await GitHubChannel("o/r").send(Message(1, "github", "comment", [],
                                                        {"comment": "c"}, 3))
    assert not ok and "no GitHub credential" in reply["error"]


async def test_smtp_resolves_handles_and_cc() -> None:
    sent = {}

    async def fake_send(message, **kw):
        sent.update(msg=message, **kw)
        return {}, "250 2.0.0 queued"

    ch = SmtpChannel({"host": "smtp.example.org", "port": 465, "tls": True,
                      "from": "monitor@example.org"},
                     {"marvinm2": "m@example.org", "egonw": "e@example.org"}, sender=fake_send)
    ok, reply = await ch.send(Message(1, "smtp", "open", ["marvinm2", "ghost", "cc:egonw"],
                                      {"subject": "S\nInjected: x", "text": "body"}))
    assert ok and reply == {"status": 250, "response": "250 2.0.0 queued", "refused": 0,
                            "no_address": ["ghost"]}
    msg = sent["msg"]
    assert msg["To"] == "m@example.org" and msg["Cc"] == "e@example.org"
    assert msg["Subject"] == "S Injected: x" and sent["use_tls"] is True
    ok, reply = await ch.send(Message(2, "smtp", "open", ["ghost"], {"subject": "s"}))
    assert not ok and "ghost" in reply["error"]


async def test_slack_and_hc_channels() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, text="ok")

    s = SlackChannel("https://hooks.example.org/x", transport=_mock(handler))
    ok, reply = await s.send(Message(1, "slack", "open", [], {
        "text": "a <b> & c", "link": "https://monitor.example.org/incidents/k", "line": "l"}))
    assert ok and reply["status"] == 200
    assert json.loads(seen[0].content)["blocks"][0]["text"]["text"] == (
        "a &lt;b&gt; &amp; c <https://monitor.example.org/incidents/k|details>")
    hc = HcChannel({"delivery-watchdog": "https://hc.example.org/abc"}, transport=_mock(handler))
    assert (await hc.send(Message(2, "hc", "watchdog", [], {"check": "delivery-watchdog",
                                                            "status": "fail"})))[0]
    assert str(seen[-1].url) == "https://hc.example.org/abc/fail"
    assert not (await hc.ping("unknown"))[0]
    assert blocks({"text": "x", "link": "javascript:alert(1)"})["blocks"][0]["text"]["text"] == "x"


def test_build_channels_from_secrets() -> None:
    secrets = {"tgxmon_gh_token": "pat", "tgxmon_smtp": json.dumps({"host": "h", "from": "f"}),
               "tgxmon_contacts": "marvinm2: m@example.org",
               "tgxmon_hc_urls": json.dumps({"delivery-watchdog": "https://hc.example.org/1"})}
    chans = build_channels(secrets.get, {"TGXMON_GH_REPO": "o/r"})
    assert sorted(chans) == ["github", "hc", "smtp"]
    assert chans["smtp"].contacts == {"marvinm2": "m@example.org"}
    assert build_channels(lambda n: None, {}) == {}


async def test_watchdog_ping_is_live_even_in_dry_run(world: World) -> None:
    w = world
    w.engine.dry_run = True
    w.engine.tick()
    w.clock.advance(minutes=1)
    w.engine.tick()
    await w.dispatch()
    assert [m.payload["check"] for m in w.channels["hc"].sent] == ["delivery-watchdog"]
    w.clock.advance(minutes=5)
    w.engine.tick()
    await w.dispatch()
    assert len(w.channels["hc"].sent) == 2
