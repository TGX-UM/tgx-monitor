"""Adversarial scenarios for the alert engine: each test pins down a defect found in review.

Fake clock, stub channels, no network.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from test_alerts_support import OWNERS, T0, TARGETS, WINDOWS, StubChannel, World, _c, _t

from tgx_monitor.alerts import digests, outbox, reconcile, router
from tgx_monitor.alerts import engine as E
from tgx_monitor.alerts.dispatcher import Dispatcher
from tgx_monitor.catalogue import Catalogue, Owners, Target
from tgx_monitor.model import Result, iso
from tgx_monitor.store import Store

LEAF = {"app-a"}
BAD = {"app-a", "app-b", "filler-1", "filler-2", "filler-3", "filler-4", "monitor-vantage"}


def _catalogue(root: Path, targets: list[dict[str, Any]], *, owners: Any = OWNERS,
               windows: Any = WINDOWS, raw_targets: str | None = None) -> Catalogue:
    (root / "targets").mkdir(parents=True, exist_ok=True)
    if owners is not None:
        (root / "owners.yaml").write_text(yaml.safe_dump(owners))
    (root / "maintenance.yaml").write_text(yaml.safe_dump(windows))
    (root / "targets" / "all.yaml").write_text(
        raw_targets if raw_targets is not None else yaml.safe_dump(targets, sort_keys=False))
    return Catalogue(root)


def _world(tmp: Path, targets: list[dict[str, Any]], **kw: Any) -> World:
    w = World(tmp)
    w.cat = _catalogue(tmp / "custom", targets, **kw)
    assert not w.cat.problems, w.cat.problems
    w.engine = w.new_engine()
    return w


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


def _fail(w: World, failing: set[str], cycles: int) -> None:
    for _ in range(cycles):
        w.cycle(failing)


def _ingest(w: World, probe_id: str, status: str, started: dt.datetime) -> None:
    for pid, via, t, c in w.cat.probes():
        if pid == probe_id:
            w.engine.ingest(pid, via, t, c, Result(c.id, t.id, status, started, 1.0), 1)  # type: ignore[arg-type]
            return
    raise KeyError(probe_id)


def _state(w: World, pid: str) -> dict[str, Any]:
    return w.store.one("SELECT * FROM probe_state WHERE probe_id=?", (pid,)) or {}


# ---------------------------------------------------------------------- dependencies
def test_dependency_cycle_still_alerts(tmp_path) -> None:
    """A cycle (or a self-dependency) slipping past validation must not make every
    member 'blocked' by the other, so that nobody is ever told."""
    w = _world(tmp_path, [
        _t("xx", "service", "high", ["marvinm2"], [_c("xx-up")], depends_on=["yy"]),
        _t("yy", "service", "high", ["marvinm2"], [_c("yy-up")], depends_on=["xx"]),
        _t("zz", "service", "high", ["marvinm2"], [_c("zz-up")], depends_on=["zz"])])
    assert not w.cat.problems
    _fail(w, {"xx", "yy", "zz"}, 4)
    announced = {i["target_id"] for i in w.incidents() if i["last_notified_at"]}
    assert announced == {"xx", "yy", "zz"}


def test_child_of_pending_parent_waits_for_parent(world: World) -> None:
    """The parent's third failure lands a few minutes after the child's (jitter): the
    child must not page during that gap only because the 2-minute hold ran out."""
    w = world
    for k in range(5):
        fails = {"app-a"} | ({"edge-tgx1"} if k >= 1 else set())
        for pid, _via, t, c in w.cat.probes():
            if c.interval_s <= 300:
                w.feed(pid, "failed" if (pid in fails or t.id in fails) else "ok")
        for _ in range(5):
            w.engine.tick()
            w.clock.advance(minutes=1)
    app_a = [i["id"] for i in w.incidents(False) if i["target_id"] == "app-a"]
    assert not [r for r in w.rows(event="open") if r["incident_id"] in app_a]
    assert [i["target_id"] for i in w.incidents() if i["last_notified_at"]] == ["edge-tgx1"]


def test_ancestor_window_covers_descendants(tmp_path) -> None:
    """A reload upstream breaks its consumers: they are in the window too."""
    w = _world(tmp_path, [
        _t("upstream", "data", "high", ["marvinm2"], [_c("upstream-up")],
           maintenance=["sunday-reload"]),
        _t("consumer", "service", "high", ["marvinm2"], [_c("consumer-up")],
           depends_on=["upstream"])])
    w.clock.t = dt.datetime(2026, 11, 15, 5, 50, tzinfo=dt.UTC)
    while w.clock() < dt.datetime(2026, 11, 15, 7, 25, tzinfo=dt.UTC):
        w.cycle({"consumer"})
    assert not w.rows(), "nothing is sent during the upstream's window"
    assert w.engine.view()["consumer-up"]["state"] == "MAINTENANCE"
    w.clock.t = dt.datetime(2026, 11, 15, 7, 30, 30, tzinfo=dt.UTC)
    w.engine.tick()
    assert w.rows(event="open"), "still failing when the window closes: alerts at once"


# ---------------------------------------------------------------------- suppression
def test_check_silence_stops_reminders_and_escalation(world: World) -> None:
    w = world
    _fail(w, LEAF, 4)
    assert w.rows(event="open")
    E.add_silence(w.store, "app-a", "known", w.clock() + dt.timedelta(days=2), "marvinm2",
                  check_id="app-a-home", now=w.clock())
    w.clock.advance(hours=25)
    w.engine.tick()
    assert not w.rows(event="escalate") and not w.rows(event="reminder")


def test_flapping_child_of_failing_parent_is_silent(world: World) -> None:
    w = world
    _fail(w, {"edge-tgx1"}, 4)
    for i in range(16):
        w.cycle({"edge-tgx1"} | ({"app-b"} if i % 2 else set()))
    assert _state(w, "app-b-sparql")["state"] == "FLAPPING"
    assert not w.rows(event="flapping"), "children of a failing ancestor are silent"


def test_silence_until_with_offset_is_stored_utc(world: World) -> None:
    w = world
    until = dt.datetime(2026, 11, 11, 10, 30, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    E.add_silence(w.store, "app-a", "r", until, "marvinm2", now=w.clock())
    assert w.store.one("SELECT until FROM silences")["until"] == "2026-11-11T09:30:00+00:00"
    w.clock.t = dt.datetime(2026, 11, 11, 9, 45, tzinfo=dt.UTC)  # expired 15 min ago
    assert not E.list_silences(w.store, w.clock())


# ---------------------------------------------------------------------- vantage
def test_vantage_single_blip_does_not_page(world: World) -> None:
    w = world
    w.cycle(BAD)
    for _ in range(4):
        w.cycle()
    assert not w.rows(event="open")
    assert not w.incidents()


async def test_vantage_flap_reuses_issue_and_no_storm_on_recovery(world: World) -> None:
    w = world
    _fail(w, BAD, 4)
    await w.dispatch()
    assert w.channels["github"].actions() == ["open"]
    # Jittered recovery: most probes pass, filler-4 has not run yet when the tick fires.
    for pid, _via, t, c in w.cat.probes():
        if c.interval_s <= 300 and t.id != "filler-4":
            w.feed(pid, "ok")
    w.engine.tick()
    w.clock.advance(minutes=2)
    w.feed("filler-4-up", "ok")
    w.engine.tick()
    w.clock.advance(minutes=3)
    for _ in range(3):
        w.cycle()
    vid = {i["id"] for i in w.incidents(False) if i["target_id"] == E.VANTAGE_TARGET}
    assert not [r for r in w.rows(event="open") if r["incident_id"] not in vid], \
        "no burst of individual pages right after the vantage recovers"
    assert not w.incidents()
    _fail(w, BAD, 4)
    await w.dispatch()
    assert w.channels["github"].actions() == ["open", "close", "reopen"]


async def test_no_reminders_while_vantage_degraded(world: World) -> None:
    w = world
    _fail(w, LEAF, 4)
    inc = w.incidents()[0]
    while w.clock() < T0 + dt.timedelta(hours=3):
        w.cycle(BAD)
    assert not [r for r in w.rows() if r["incident_id"] == inc["id"]
                and r["event"] in ("escalate", "reminder")]


# ---------------------------------------------------------------------- catalogue changes
async def test_removed_target_closes_without_false_text(world: World) -> None:
    w = world
    _fail(w, LEAF, 4)
    inc = w.incidents()[0]
    cat2 = _catalogue(w.tmp / "cat2", [t for t in TARGETS if t["id"] != "app-a"])
    assert w.engine.reload(cat2)
    w.cat = cat2
    w.engine.tick()
    assert not w.incidents()
    rows = [r for r in w.rows() if r["incident_id"] == inc["id"] and r["channel"] == "smtp"]
    last = rows[-1]["payload"]
    text = last["subject"] + last["text"]
    assert "large share" not in text and "recovered" not in text.lower()
    assert "no longer monitored" in text


def test_reload_rejects_broken_catalogue(world: World) -> None:
    w = world
    _fail(w, LEAF, 4)
    bad = _catalogue(w.tmp / "bad", [], raw_targets="- id: [unclosed\n")
    assert bad.problems
    assert not w.engine.reload(bad)
    w.engine.tick()
    assert w.incidents(), "a catalogue that failed to load must not close every incident"
    assert not w.rows(event="close")


def test_missing_owners_does_not_mark_announced(tmp_path) -> None:
    w = World(tmp_path)
    w.cat = _catalogue(tmp_path / "noowners", TARGETS, owners=None)
    w.engine = w.new_engine()
    _fail(w, LEAF, 4)
    assert w.incidents() and not w.incidents()[0]["last_notified_at"]
    good = _catalogue(tmp_path / "good", TARGETS)
    assert w.engine.reload(good)
    w.cat = good
    w.engine.tick()
    assert w.rows(event="open"), "announced once routing works again"


# ---------------------------------------------------------------------- severity / privacy
def test_severity_upgrade_sends_critical_mail(tmp_path) -> None:
    w = _world(tmp_path, [_t("svc", "service", "medium", ["marvinm2"],
                             [_c("svc-a"), _c("svc-b", severity="high")])])
    _fail(w, {"svc-a"}, 4)
    assert w.rows(event="open", channel="github") and not w.rows(channel="smtp")
    _fail(w, {"svc-a", "svc-b"}, 4)
    assert w.incidents()[0]["severity"] == "critical"
    assert w.rows(channel="smtp"), "a critical check failing must reach e-mail"
    assert len(w.rows(channel="github", event="open")) == 1, "no second issue"


async def test_incident_turning_private_still_closes_issue(tmp_path) -> None:
    w = _world(tmp_path, [_t("svc", "service", "high", ["marvinm2"],
                             [_c("svc-pub"), _c("svc-priv", public=False,
                                                describe="secret hole detail")])])
    _fail(w, {"svc-pub"}, 4)
    await w.dispatch()
    _fail(w, {"svc-pub", "svc-priv"}, 4)
    assert w.incidents()[0]["private"] == 1
    w.cycle()
    w.cycle()
    assert not w.incidents()
    await w.dispatch()
    gh = w.channels["github"]
    assert gh.actions() == ["open", "close"], "the public issue must not be left open"
    assert not any("secret hole" in json.dumps(m.payload) for m in gh.sent)


def test_blocked_private_target_not_named_on_github(tmp_path) -> None:
    w = _world(tmp_path, [
        _t("edge", "infra", "high", ["egonw"], [_c("edge-up")]),
        _t("secret-hole", "security", "high", ["marvinm2"], [_c("secret-hole-up")],
           depends_on=["edge"], public=False),
        _t("app", "service", "high", ["marvinm2"], [_c("app-up")], depends_on=["edge"])])
    _fail(w, {"edge", "secret-hole", "app"}, 4)
    body = w.rows(channel="github", event="open")[0]["payload"]["body"]
    assert "APP" in body and "SECRET-HOLE" not in body


def test_real_target_named_test_is_not_a_test_incident(tmp_path) -> None:
    w = _world(tmp_path, [_t("test-rig", "service", "high", ["marvinm2"], [_c("rig-up")])])
    _fail(w, {"test-rig"}, 4)
    assert w.rows(event="open")
    _fail(w, {"test-rig"}, 3)
    assert w.incidents(), "still failing: must not be auto-resolved as a test"
    assert not w.rows(event="close")
    w.clock.advance(hours=3)
    w.engine.tick()
    assert w.rows(event="escalate")


# ---------------------------------------------------------------------- people
OWNERS_QUIET_EGON = Owners.model_validate({
    "admins": ["marvinm2", "egonw"], "fallback": ["marvinm2"], "infra_cc": ["egonw"],
    "people": {"marvinm2": {"notify": True}, "egonw": {"notify": False},
               "alice": {"notify": True}}})


def test_notify_false_is_never_alerted() -> None:
    t = Target.model_validate({"id": "t-x", "name": "T", "class": "infra",
                               "criticality": "high", "owners": ["alice"]})
    o = OWNERS_QUIET_EGON
    for event in ("open", "close", "reminder", "escalate", "update"):
        for rcpt in router.routes(event, "critical", t, o).values():
            assert not any(h.removeprefix("cc:") == "egonw" for h in rcpt), (event, rcpt)
    assert router.routes("escalate", "critical", t, o) == {"github": ["marvinm2"],
                                                           "smtp": ["marvinm2"]}
    assert "egonw" not in router.digest_recipients(t, o)


# ---------------------------------------------------------------------- results and time
def test_out_of_order_and_skewed_results(world: World) -> None:
    w = world
    now = w.clock()
    _ingest(w, "app-b-sparql", "ok", now)
    for back in (10, 9, 8):  # an agent flushing a backlog after the fresh result
        _ingest(w, "app-b-sparql", "failed", now - dt.timedelta(minutes=back))
    st = _state(w, "app-b-sparql")
    assert st["state"] == "OK" and st["last_run_at"] == iso(now)
    _ingest(w, "app-b-sparql", "ok", now + dt.timedelta(hours=1))  # agent clock ahead
    assert _state(w, "app-b-sparql")["last_run_at"] == iso(now)
    plus1 = dt.timezone(dt.timedelta(hours=1))
    w.clock.advance(minutes=1)
    _ingest(w, "app-b-sparql", "ok", w.clock().astimezone(plus1))
    assert _state(w, "app-b-sparql")["last_run_at"].endswith("+00:00")


def test_sparse_check_with_retry_waits_for_retry(tmp_path) -> None:
    cat = _catalogue(tmp_path / "c", [_t("bk", "backup", "high", ["marvinm2"],
                                          [_c("bk-age", every="1d", retry="10m")])])
    _, c = cat.checks["bk-age"]
    r = E.step(E.blank("p"), "failed", T0, c)
    assert r["state"] == "PENDING", "the scheduler's retry has not run yet"
    r = E.step(r, "failed", T0 + dt.timedelta(minutes=10), c)
    assert r["state"] == "FAILING"


def test_watchdog_survives_clock_jump_back(world: World) -> None:
    w = world
    w.engine.tick()
    w.clock.advance(hours=-1)
    w.engine.tick()
    assert w.store.one("SELECT COUNT(*) AS n FROM outbox WHERE event='watchdog'")["n"] == 2


# ---------------------------------------------------------------------- digests
def _at(*a: int) -> dt.datetime:
    return dt.datetime(*a, tzinfo=dt.UTC)


def test_digest_covers_dst_change(world: World) -> None:
    """Sat 08:00 CEST = 06:00 UTC, Sun 08:00 CET = 07:00 UTC: an incident closed in
    between must appear in Sunday's digest."""
    w = world
    w.clock.t = _at(2026, 10, 23, 12, 0)
    w.engine.tick()
    w.clock.t = _at(2026, 10, 24, 6, 0, 30)
    for _ in range(3):
        w.cycle({"app-b"})
    w.cycle()
    w.cycle()
    assert [r["payload"]["subject"].split(":")[0] for r in w.rows(event="digest",
                                                                  channel="smtp")] == []
    closed = w.incidents(False)[0]["closed_at"]
    assert closed < "2026-10-24T07:00"
    w.clock.t = _at(2026, 10, 25, 7, 0)
    w.engine.tick()
    mails = w.rows(event="digest", channel="smtp")
    assert mails and "APP-B" in mails[0]["payload"]["text"]


def test_digest_after_start_before_eight(world: World) -> None:
    w = world
    w.clock.t = _at(2026, 11, 16, 5, 0)  # Monday 06:00 Amsterdam, first start
    _fail(w, {"app-b"}, 4)
    w.clock.t = _at(2026, 11, 16, 7, 0)
    w.engine.tick()
    assert w.rows(event="digest", channel="smtp"), "today's 08:00 digest is not skipped"


def test_weekly_digest_catches_up_after_missed_monday(world: World) -> None:
    w = world
    w.clock.t = _at(2026, 11, 15, 12, 0)
    _fail(w, {"info-thing"}, 4)
    w.clock.t = _at(2026, 11, 17, 9, 0)  # Tuesday: the core was down all Monday
    w.engine.tick()
    subjects = [r["payload"]["subject"] for r in w.rows(event="digest", channel="smtp")]
    assert any("Weekly digest 2026-W47" in s for s in subjects)


def test_digest_slot_is_eight_amsterdam() -> None:
    assert digests.slot_utc(dt.date(2026, 7, 1)) == _at(2026, 7, 1, 6, 0)
    assert digests.slot_utc(dt.date(2026, 11, 11)) == _at(2026, 11, 11, 7, 0)
    assert digests.slot_utc(dt.date(2026, 3, 29)) == _at(2026, 3, 29, 6, 0)
    assert digests.slot_utc(dt.date(2026, 10, 25)) == _at(2026, 10, 25, 7, 0)


# ---------------------------------------------------------------------- dispatcher
class FlakyGitHub(StubChannel):
    """Fails the first ``fail_close`` close attempts; records successful actions."""

    def __init__(self) -> None:
        super().__init__("github")
        self.fail_close = 0
        self.ok: list[str] = []

    async def send(self, msg):  # type: ignore[no-untyped-def]
        if msg.payload.get("action") == "close" and self.fail_close > 0:
            self.fail_close -= 1
            self.sent.append(msg)
            return False, {"status": 502}
        ok, reply = await super().send(msg)
        self.ok.append(msg.payload.get("action"))
        return ok, reply


async def test_reopen_not_overtaken_by_stale_close(world: World) -> None:
    w = world
    gh = FlakyGitHub()
    w.channels["github"] = gh
    w.dispatcher.channels["github"] = gh
    _fail(w, LEAF, 4)
    await w.dispatch()
    w.cycle()
    w.cycle()
    assert not w.incidents()
    _fail(w, LEAF, 4)  # fails again within 24 h: same key, same issue
    assert w.incidents()[0]["issue_number"] == 101
    gh.fail_close = 1
    await w.dispatch()
    w.clock.advance(minutes=5)
    await w.dispatch()
    assert gh.ok == ["open", "close", "reopen"], "the live incident's issue must end open"


async def test_unconfigured_channel_raises_self_alert() -> None:
    store = Store(":memory:")
    with store.transaction() as db:
        outbox.enqueue(db, channel="smtp", event="open", now=T0, recipients=["marvinm2"],
                       payload={"subject": "s", "text": "t", "line": "l"})
    slack = StubChannel("slack")
    stats = await Dispatcher(store, {"slack": slack}, now=lambda: T0,
                             admins=["marvinm2"]).run_once()
    assert stats.get("unconfigured") == 1
    assert [r["channel"] for r in store.query("SELECT channel FROM outbox WHERE event='self'")
            ] == ["slack"]


def test_reconcile_flags_duplicate_issue_for_one_key(world: World) -> None:
    w = world
    _fail(w, LEAF, 4)
    inc = w.incidents()[0]
    w.store.execute("UPDATE incidents SET issue_number=101 WHERE id=?", (inc["id"],))
    marker = f"<!-- tgxmon:incident={inc['key']} -->"
    issues = [{"number": n, "body": marker, "labels": ["alert", "target:app-a"]}
              for n in (101, 102)]
    out = reconcile.adopt(w.engine, issues)
    assert w.incidents()[0]["issue_number"] == 101
    assert [o["issue"] for o in out["orphans"]] == [102]
    assert reconcile.adopt(w.engine, list(reversed(issues)))["orphans"][0]["issue"] == 102
    assert w.incidents()[0]["issue_number"] == 101


async def test_restore_does_not_resend_open_for_adopted_issue(world: World) -> None:
    """Restored backup: the incident is in the DB with its open row still unsent, but
    GitHub already has its issue. Reconcile adopts it; the stale open must not create
    a second issue."""
    w = world
    _fail(w, LEAF, 4)
    inc = w.incidents()[0]
    assert w.rows(channel="github", event="open") and not inc["issue_number"]
    issue = {"number": 77, "body": f"<!-- tgxmon:incident={inc['key']} -->",
             "labels": ["alert", "target:app-a"]}
    assert reconcile.adopt(w.engine, [issue])["orphans"] == []
    await w.dispatch()
    assert w.channels["github"].actions() == []
    assert w.incidents()[0]["issue_number"] == 77
