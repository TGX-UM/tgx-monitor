"""The public snapshot: what it states, how it swaps, and the server that serves it."""

from __future__ import annotations

import argparse
import datetime as dt
import json

from starlette.testclient import TestClient
from test_web_fixtures import NOW, make_catalogue, make_store

from tgx_monitor import snapshot as S
from tgx_monitor.catalogue import Window
from tgx_monitor.web.public import add_commands, create_public_app


def _build(tmp_path, now=NOW):  # noqa: ANN001, ANN202
    cat = make_catalogue(tmp_path / "catalogue", plant="plain")
    store = make_store(planted=False)
    return S.build_public(store, cat, tmp_path / "public", now), store, cat


def test_build_writes_pages_and_status(tmp_path):
    snap, store, _ = _build(tmp_path)
    cur = tmp_path / "public" / "current"
    assert cur.is_symlink() and cur.resolve() == snap.resolve()
    doc = json.loads((cur / "status.json").read_text())
    assert set(doc) == {"generated_at", "last_cycle_at", "outbox_oldest_age_s", "targets"}
    assert doc["targets"] == [{"id": "svc-a", "name": "Service A", "group": "Group A",
                               "state": "degraded"}]
    assert doc["outbox_oldest_age_s"] == 0.0  # outbox rows created at NOW
    index = (cur / "index.html").read_text()
    assert "Service A" in index and "Degraded" in index and "⚠" in index
    assert "Data as of" in index and "No open incidents" not in index
    assert index.count('class="bar bar--') == 90
    page = (cur / "target" / "svc-a.html").read_text()
    assert "The front page answers 200." in page and "Service A answers." in page
    assert (cur / "static" / "tgx-monitor.css").exists()


def test_rebuild_swaps_and_prunes(tmp_path):
    first, store, cat = _build(tmp_path)
    for i in range(1, 4):
        last = S.build_public(store, cat, tmp_path / "public", NOW + dt.timedelta(minutes=i))
    snaps = sorted(p.name for p in (tmp_path / "public").glob("snap-*"))
    assert len(snaps) == S.KEEP_SNAPSHOTS and last.name in snaps and first.name not in snaps
    assert (tmp_path / "public" / "current").resolve() == last.resolve()


def test_stale_banner_when_the_loop_stops(tmp_path):
    _build(tmp_path, now=NOW + dt.timedelta(hours=1))
    index = (tmp_path / "public" / "current" / "index.html").read_text()
    assert "has not run recently" in index


def test_state_rules():
    assert S.target_state([]) == "unknown"
    assert S.target_state(["ok", "ok"]) == "operational"
    assert S.target_state(["ok", "fail"]) == "degraded"
    assert S.target_state(["fail", "fail", "unknown"]) == "down"
    assert S.target_state(["ok", "warn"]) == "degraded"
    assert S.target_state(["fail"], window_active=True) == "maintenance"
    assert S.classify({"state": "UNKNOWN", "last": {"status": "failed"}}) == "warn"
    assert S.classify({"state": "FAILING", "last": {"status": "failed"}}) == "fail"
    assert S.classify({"state": "BLOCKED", "last": {"status": "ok"}}) == "ok"
    assert S.classify({"state": "OK", "last": {"status": "ok", "warn": 1}}) == "warn"
    assert S.classify({"state": "MAINTENANCE", "last": None}) == "maint"


def test_windows():
    w = Window(id="w", describe="d", rrule="FREQ=WEEKLY;BYDAY=SU", start="05:50",
               duration="100m")
    sunday = dt.datetime(2026, 11, 15, 6, 0, tzinfo=dt.UTC)
    assert S.occurrences(w, sunday, sunday + dt.timedelta(seconds=1))
    occ = S.occurrences(w, NOW, NOW + dt.timedelta(days=14))
    assert [s.date().isoformat() for s, _ in occ] == ["2026-11-15", "2026-11-22"]
    assert S._rule_matches({"FREQ": "MONTHLY", "BYMONTHDAY": "12"}, dt.date(2026, 11, 12))
    assert not S._rule_matches({"FREQ": "WEEKLY", "BYDAY": "SU"}, dt.date(2026, 11, 12))


def test_svgs_carry_text():
    days = [{"day": f"2026-11-{d:02d}", "pct": p, "n": 1} for d, p in
            ((1, None), (2, 100.0), (3, 97.0), (4, 50.0))]
    svg = str(S.uptime_svg(days, "Svc <A>"))
    assert 'role="img"' in svg and "Svc &lt;A&gt;" in svg and "major outage" in svg
    assert 'height="30"' in svg and 'height="14"' in svg  # height differs, not only colour
    line = str(S.sparkline_svg([("a", 1.0), ("b", 3.0)], "count"))
    assert "min 1, max 3, last 3" in line
    assert "Not enough history" in str(S.sparkline_svg([("a", 1.0)], "count"))


def test_public_server(tmp_path):
    _build(tmp_path)
    c = TestClient(create_public_app(tmp_path / "public", limit=4))
    r = c.get("/")
    assert r.status_code == 200 and "Service A" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "public, max-age=30"
    assert c.get("/status.json").json()["targets"][0]["id"] == "svc-a"
    assert c.post("/").status_code == 405
    assert c.get("/target/svc-a.html").status_code == 200
    assert c.get("/x").status_code == 429  # fifth request in the minute


def test_public_command_registered():
    p = argparse.ArgumentParser()
    add_commands(p.add_subparsers(dest="cmd"))
    args = p.parse_args(["serve-public", "--dir", "/srv/x"])
    assert args.port == 8080 and args.dir == "/srv/x" and callable(args.fn)
