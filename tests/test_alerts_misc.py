"""Digests, the synthetic test alert, the reconcile pass and the CLI commands."""

from __future__ import annotations

import datetime as dt
import json

import pytest
from test_alerts_support import World, make_catalogue

from tgx_monitor import cli
from tgx_monitor.alerts import digests, reconcile, testing
from tgx_monitor.store import Store


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


def _at(*a: int) -> dt.datetime:
    return dt.datetime(*a, tzinfo=dt.UTC)


def test_amsterdam_summer_and_winter_time() -> None:
    assert digests.amsterdam(_at(2026, 7, 1, 6, 0)).hour == 8
    assert digests.amsterdam(_at(2026, 11, 11, 7, 0)).hour == 8
    assert digests.amsterdam(_at(2026, 3, 29, 0, 59)).hour == 1  # just before the switch
    assert digests.amsterdam(_at(2026, 3, 29, 1, 0)).hour == 3


def test_daily_and_weekly_digests(world: World) -> None:
    w = world
    w.clock.t = _at(2026, 11, 15, 12, 0)  # Sunday: no window for app-b
    for _ in range(4):
        w.cycle({"app-b", "info-thing"})
    assert not w.rows(channel="smtp"), "warning and info never mail at once"
    w.clock.t = _at(2026, 11, 16, 6, 59)  # Monday 07:59 Amsterdam
    w.engine.tick()
    assert not w.rows(event="digest")
    w.clock.t = _at(2026, 11, 16, 7, 0)
    w.engine.tick()
    mails = {(r["recipients"][0], r["payload"]["subject"].split(":")[0])
             for r in w.rows(event="digest", channel="smtp")}
    assert mails == {("marvinm2", "[tgx-monitor] Daily digest 2026-11-16"),
                     ("marvinm2", "[tgx-monitor] Weekly digest 2026-W47")}
    slack = w.rows(event="digest", channel="slack")
    assert len(slack) == 1 and "INFO-THING" in slack[0]["payload"]["text"]
    w.clock.advance(hours=1)
    w.engine.tick()
    assert len(w.rows(event="digest")) == 3, "once per day"


async def test_test_alert_opens_and_resolves(world: World) -> None:
    w = world
    key = testing.enqueue_test_alert(w.store, w.cat, ["marvinm2", "egonw"],
                                     ["github", "smtp", "slack"], "marvinm2", now=w.clock())
    await w.dispatch()
    gh = w.channels["github"].sent[0]
    assert gh.payload["labels"] == ["test"] and f"tgxmon:incident={key}" in gh.payload["body"]
    assert "@marvinm2 @egonw" in gh.payload["body"]
    assert w.channels["smtp"].sent[0].payload["subject"].startswith("[TEST]")
    w.clock.advance(minutes=5)
    w.engine.tick()
    await w.dispatch()
    assert w.channels["github"].actions() == ["open", "close"]
    assert w.channels["github"].sent[1].issue_number == 101
    assert not w.incidents()
    try:
        testing.enqueue_test_alert(w.store, w.cat, ["nobody"], ["smtp"], "x")
    except ValueError as exc:
        assert "nobody" in str(exc)
    else:
        raise AssertionError("unknown handle accepted")


def test_selftest_flag() -> None:
    store = Store(":memory:")
    assert not testing.selftest_broken(store)
    testing.set_selftest(store, True)
    assert testing.selftest_broken(store)
    testing.set_selftest(store, False)
    assert store.get_meta("selftest_broken") == "0"


class FakeGitHub:
    def __init__(self, issues=None, error=None):
        self.issues, self.error = issues or [], error

    async def open_alert_issues(self):
        if self.error:
            raise self.error
        return self.issues


async def test_reconcile_run_reports_and_survives_outage(world: World) -> None:
    w = world
    rep = await reconcile.run(w.engine, FakeGitHub(error=RuntimeError("down")))
    assert "down" in rep["error"]
    rep = await reconcile.run(w.engine, FakeGitHub([{"number": 9, "body": "<!-- tgxmon:"
                                                     "incident=ghost-202601010000 -->",
                                                     "labels": ["alert"]}]))
    assert rep["orphans"] == [{"issue": 9, "key": "ghost-202601010000", "why": "unknown target"}]
    assert json.loads(w.store.get_meta("reconcile_orphans"))["orphans"]


def test_reconcile_attaches_issue_to_held_incident(world: World) -> None:
    w = world
    for _ in range(3):
        w.cycle({"app-a"})
    inc = w.incidents()[0]
    assert not inc["last_notified_at"]
    out = reconcile.adopt(w.engine, [{"number": 5, "labels": ["alert", "target:app-a"],
                                      "body": "<!-- tgxmon:incident=app-a-202611100700 -->"}])
    assert out["adopted"] == ["app-a-202611100700"]
    row = w.incidents()[0]
    assert (row["id"], row["issue_number"], row["key"]) == (inc["id"], 5, "app-a-202611100700")
    w.clock.advance(minutes=3)
    w.engine.tick()
    assert not w.rows(channel="github"), "the existing issue was announced already"


def test_cli_silence_ack_outbox_selftest(tmp_path, capsys) -> None:
    db = str(tmp_path / "m.db")
    cat = tmp_path / "cat"
    make_catalogue(cat)
    base = ["--catalogue", str(cat)]
    assert cli.main(base + ["silence", "add", "app-a", "--reason", "deploy", "--until", "2h",
                            "--who", "marvinm2", "--db", db]) == 0
    assert cli.main(base + ["silence", "list", "--db", db]) == 0
    assert "app-a/*" in capsys.readouterr().out
    assert cli.main(base + ["silence", "rm", "1", "--who", "marvinm2", "--db", db]) == 0
    assert cli.main(base + ["ack", "nope", "--who", "marvinm2", "--db", db]) == 1
    assert cli.main(base + ["test-incident", "--break", "--db", db]) == 0
    assert Store(db).get_meta("selftest_broken") == "1"
    assert cli.main(base + ["test-alert", "--channel", "smtp,slack", "--who", "marvinm2",
                            "--dry-run", "--db", db]) == 0
    capsys.readouterr()
    assert cli.main(base + ["outbox", "--db", db]) == 0
    out = capsys.readouterr().out
    assert out.count("DRY") == 2 and "marvinm2,egonw" in out
    audit = [r["action"] for r in Store(db).query("SELECT action FROM audit ORDER BY id")]
    assert audit == ["silence", "unsilence", "test-alert"]
