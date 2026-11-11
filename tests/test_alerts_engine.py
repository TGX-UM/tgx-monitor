"""Alert lifecycle scenarios, fake clock and stub channels (no network)."""

from __future__ import annotations

import datetime as dt
import re

import pytest
from test_alerts_support import Clock, World, make_catalogue

from tgx_monitor.alerts import engine as E
from tgx_monitor.alerts import reconcile
from tgx_monitor.catalogue import Check


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


LEAF = {"app-a"}


def _fail_until_open(w: World, failing: set[str], cycles: int = 3) -> None:
    for _ in range(cycles):
        w.cycle(failing)


async def test_leaf_failure_one_issue_right_people(world: World) -> None:
    w = world
    w.cycle(LEAF)
    w.cycle(LEAF)
    assert not w.incidents()
    w.feed("app-a-home@public", "failed")  # third failure: incident opens, held
    w.feed("app-a-home@tgx1", "failed")
    w.engine.tick()
    assert len(w.incidents()) == 1 and not w.rows()
    w.clock.advance(minutes=1)
    w.engine.tick()
    assert not w.rows(), "the 2-minute hold lets a parent open first"
    w.clock.advance(minutes=1, seconds=1)
    w.engine.tick()
    by = {r["channel"]: r["recipients"] for r in w.rows(event="open")}
    assert by == {"github": ["marvinm2"], "smtp": ["marvinm2"], "slack": []}
    for _ in range(4):  # still failing: no second issue
        w.cycle(LEAF)
    await w.dispatch()
    gh = w.channels["github"]
    assert gh.actions() == ["open"]
    body = gh.sent[0].payload["body"]
    assert "@marvinm2" in body and "@ozancinar" not in body
    assert re.search(r"<!-- tgxmon:incident=app-a-\d{12} -->", body)
    assert "app-a-home works (via public, tgx1)" in body
    assert "@" not in body.replace("@marvinm2", "")  # no e-mail addresses
    assert w.incidents()[0]["issue_number"] == 101
    assert [m.recipients for m in w.channels["smtp"].sent] == [["marvinm2"]]


async def test_recovery_closes_with_duration(world: World) -> None:
    w = world
    _fail_until_open(w, LEAF, 4)
    await w.dispatch()
    w.cycle()
    assert w.incidents(), "one pass is not a recovery"
    w.cycle()
    assert not w.incidents()
    await w.dispatch()
    assert w.channels["github"].actions() == ["open", "close"]
    close = w.channels["github"].sent[-1]
    assert close.issue_number == 101 and "Recovered" in close.payload["comment"]
    assert w.channels["smtp"].sent[-1].payload["subject"].startswith("[tgx-monitor] RESOLVED")
    assert "recovered" in w.channels["slack"].sent[-1].payload["text"]


async def test_parent_failure_blocks_children(world: World) -> None:
    w = world
    # Children are fed before the parent in every cycle (catalogue order), the worst case.
    _fail_until_open(w, {"edge-tgx1", "app-a", "app-b"}, 4)
    incs = w.incidents()
    assert [i["target_id"] for i in incs] == ["edge-tgx1"]
    assert E.json.loads(incs[0]["blocked"]) == ["app-a", "app-b"]
    opens = w.rows(event="open")
    assert {r["channel"] for r in opens} == {"github", "smtp", "slack"}
    assert all(r["incident_id"] == incs[0]["id"] for r in w.rows())
    assert {r["channel"]: r["recipients"] for r in opens}["github"] == ["egonw"]
    view = w.engine.view()
    assert view["app-a-home@public"]["state"] == "BLOCKED"
    assert view["edge-tgx1-http"]["state"] == "FAILING"
    await w.dispatch()
    assert "Also affected" in w.channels["github"].sent[0].payload["body"]


async def test_child_recovering_with_parent_never_pages(world: World) -> None:
    w = world
    _fail_until_open(w, {"edge-tgx1", "app-a"}, 4)
    w.cycle({"app-a"})
    w.cycle({"app-a"})  # parent recovered; child lags one cycle behind
    w.cycle()
    w.cycle()
    assert not w.incidents()
    assert [i["target_id"] for i in w.incidents(False) if i["last_notified_at"]] == ["edge-tgx1"]


async def test_window_silences_then_alerts_on_close(tmp_path) -> None:
    w = World(tmp_path)
    w.clock.t = dt.datetime(2026, 11, 15, 5, 50, tzinfo=dt.UTC)  # Sunday, window opens
    while w.clock() < dt.datetime(2026, 11, 15, 7, 25, tzinfo=dt.UTC):
        w.cycle(LEAF)
    assert not w.incidents() and not w.rows()
    assert w.engine.view()["app-a-home@public"]["state"] == "MAINTENANCE"
    w.clock.t = dt.datetime(2026, 11, 15, 7, 30, 30, tzinfo=dt.UTC)  # window closed
    w.engine.tick()
    opens = w.rows(event="open")
    assert opens and opens[0]["created_at"] == E.iso(w.clock()), "alerts at once"


async def test_restart_creates_no_duplicates(world: World) -> None:
    w = world
    _fail_until_open(w, LEAF, 4)
    await w.dispatch()
    w.engine = w.new_engine()  # restart: same database, new process state
    for _ in range(3):
        w.cycle(LEAF)
    await w.dispatch()
    assert w.channels["github"].actions() == ["open"]
    assert len(w.incidents(open_only=False)) == 1
    issue = {"number": 101, "body": w.channels["github"].sent[0].payload["body"],
             "labels": ["alert", "target:app-a"]}
    assert reconcile.adopt(w.engine, [issue]) == {"adopted": [], "orphans": []}


async def test_restored_db_adopts_open_issue(tmp_path) -> None:
    w = World(tmp_path)
    issues = [{"number": 42, "title": "[app-a] app-a-home failing",
               "body": "x\n<!-- tgxmon:incident=app-a-202611100800 -->",
               "labels": ["alert", "sev:critical", "target:app-a"],
               "created_at": "2026-11-10T08:00:00Z"},
              {"number": 43, "body": "no marker", "labels": ["alert"]}]
    out = reconcile.adopt(w.engine, issues)
    assert out["adopted"] == ["app-a-202611100800"]
    assert out["orphans"] == [{"issue": 43, "why": "no tgxmon marker"}]
    inc = w.incidents()[0]
    assert (inc["issue_number"], inc["severity"], inc["target_id"]) == (42, "critical", "app-a")
    for _ in range(4):
        w.cycle(LEAF)
    assert not w.rows(event="open"), "the adopted issue is reused, not duplicated"
    w.cycle()
    w.cycle()
    await w.dispatch()
    assert w.channels["github"].actions() == ["close"]
    assert w.channels["github"].sent[0].issue_number == 42


async def test_flapping_one_notice_then_quiet(world: World) -> None:
    w = world
    for i in range(16):
        w.cycle(LEAF if i % 2 else set())
    flaps = w.rows(event="flapping")
    assert [r["channel"] for r in flaps] == ["slack", "slack"]  # one per probe (two vias)
    assert not w.incidents()
    assert w.engine.view()["app-a-home@public"]["state"] == "FLAPPING"
    for _ in range(30):  # calm for 2.5 h: flapping clears, nothing else was sent
        w.cycle()
    assert w.engine.view()["app-a-home@public"]["state"] == "OK"
    assert len(w.rows(event="flapping")) == 2


async def test_security_never_reaches_github(world: World) -> None:
    w = world
    _fail_until_open(w, {"canary"}, 4)
    inc = w.incidents()[0]
    assert inc["private"] == 1
    chans = {r["channel"] for r in w.rows()}
    assert chans == {"smtp", "slack"}
    smtp = w.rows(channel="smtp")[0]
    assert smtp["recipients"] == ["marvinm2", "cc:egonw"]
    text = smtp["payload"]["text"]
    assert "canary public summary" in text and "conductor" not in text.lower()
    _fail_until_open(w, {"canary"}, 0)
    w.cycle()
    w.cycle()
    assert "github" not in {r["channel"] for r in w.rows()}


async def test_vantage_degraded_single_incident(world: World) -> None:
    w = world
    bad = {"app-a", "app-b", "filler-1", "filler-2", "filler-3", "filler-4", "monitor-vantage"}
    _fail_until_open(w, bad, 4)
    assert [i["target_id"] for i in w.incidents()] == [E.VANTAGE_TARGET]
    assert {r["incident_id"] for r in w.rows()} == {w.incidents()[0]["id"]}
    w.cycle()
    w.cycle()
    assert not w.incidents(), "vantage incident closes when the monitor can see again"


async def test_silence_and_known_issue(world: World) -> None:
    w = world
    E.add_silence(w.store, "app-a", "deploying", w.clock() + dt.timedelta(hours=1), "marvinm2",
                  now=w.clock())
    _fail_until_open(w, LEAF, 5)
    assert not w.incidents()
    assert w.engine.view()["app-a-home@tgx1"]["state"] == "SILENCED"
    w.clock.advance(hours=1)
    w.cycle(LEAF)
    assert w.rows(event="open"), "silence expired while still failing: alerts at once"


async def test_reminder_and_escalation(world: World) -> None:
    w = world
    _fail_until_open(w, LEAF, 4)
    w.clock.advance(hours=2)
    w.engine.tick()
    esc = w.rows(event="escalate")
    assert {r["channel"]: r["recipients"] for r in esc} == {"github": ["egonw"],
                                                           "smtp": ["egonw"]}
    w.engine.tick()
    assert len(w.rows(event="escalate")) == 2, "escalates once"
    w.clock.advance(hours=22)
    w.engine.tick()
    assert {r["channel"] for r in w.rows(event="reminder")} == {"github", "slack"}


async def test_ack_prevents_escalation(world: World) -> None:
    w = world
    _fail_until_open(w, LEAF, 4)
    assert w.engine.ack(w.incidents()[0]["key"], "marvinm2")
    w.clock.advance(hours=3)
    w.engine.tick()
    assert not w.rows(event="escalate")


def test_thresholds_and_unknown(tmp_path) -> None:
    cat = make_catalogue(tmp_path)
    _, fast = cat.checks["app-a-home"]
    _, slow = cat.checks["backup-age"]
    t = Clock()
    r = E.blank("p")
    for status, want in [("failed", "PENDING"), ("unknown", "PENDING"), ("failed", "PENDING"),
                         ("failed", "FAILING"), ("ok", "FAILING"), ("unknown", "FAILING"),
                         ("ok", "OK")]:
        r = E.step(r, status, t(), fast)
        t.advance(minutes=5)
        assert r["state"] == want, (status, r)
    # Sparse checks retry once after 10 min by default, so the retry must fail too.
    assert slow.retry == "10m"
    once = E.step(E.blank("q"), "failed", t(), slow)
    assert once["state"] == "PENDING"
    assert E.step(once, "failed", t(), slow)["state"] == "FAILING"
    no_retry = slow.model_copy(update={"retry": ""})
    assert E.step(E.blank("q"), "failed", t(), no_retry)["state"] == "FAILING"
    lazy = slow.model_copy(update={"alert_after": "2h"})
    r = E.step(E.blank("q"), "failed", t(), lazy)
    assert r["state"] == "PENDING"
    t.advance(hours=2)
    assert E.step(r, "failed", t(), lazy)["state"] == "FAILING"


def test_unknown_for_too_long_counts_as_failing():
    """A target that only ever answers 429 (or hangs past the timeout) must page
    eventually: after max(6 h, 3 x interval) of unknowns they count as failures."""
    fast = Check.model_validate({"id": "chk", "kind": "http", "every": "5m",
                                 "assert": [{"that": "status", "eq": 200}]})
    start = dt.datetime(2026, 11, 11, 8, 0, tzinfo=dt.UTC)
    r = E.blank("p")
    r = E.step(r, "ok", start, fast)
    assert r["state"] == "OK"
    ts = start
    for _ in range(12 * 6):  # six hours of 5-minute unknowns
        ts += dt.timedelta(minutes=5)
        r = E.step(r, "unknown", ts, fast)
    assert r["state"] == "OK" and r["consecutive_fail"] <= 1
    for _ in range(3):
        ts += dt.timedelta(minutes=5)
        r = E.step(r, "unknown", ts, fast)
    assert r["state"] == "FAILING"
    r = E.step(r, "ok", ts + dt.timedelta(minutes=5), fast)
    assert r["unknown_since"] is None


def test_waiting_never_turns_into_failing():
    """A job slot from before the monitor recorded runs is 'skipped', not 'unknown':
    a day of it must neither page nor start the blind clock."""
    job = Check.model_validate({"id": "chk", "kind": "job_run", "every": "15m",
                                "assert": [{"that": "ran", "eq": True}]})
    ts = dt.datetime(2026, 11, 11, 2, 0, tzinfo=dt.UTC)
    r = E.blank("p")
    for _ in range(4 * 24):
        ts += dt.timedelta(minutes=15)
        r = E.step(r, "skipped", ts, job)
    assert r["state"] == "UNKNOWN" and r["consecutive_fail"] == 0
    assert r["unknown_since"] is None


def test_no_watchdog_rows_without_a_healthchecks_channel(world: World) -> None:
    w = world
    w.engine.watchdog = False
    w.engine.tick()
    assert w.store.one("SELECT COUNT(*) AS n FROM outbox WHERE event='watchdog'")["n"] == 0
