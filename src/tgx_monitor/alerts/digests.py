"""Digests: the quiet channel for everything that should not interrupt anyone.

Warning incidents reach e-mail only here, once a day at 08:00 Europe/Amsterdam; info
incidents get a weekly mail (Mondays) and a one-line Slack summary each morning.
Each digest covers the time since the previous one, so a DST change or a late run
leaves no gap. Each
person gets one mail listing the incidents of the targets they own (the fallback sees
all), not one mail per incident, which is the difference between a digest people read
and a filter rule.

Amsterdam time is computed from the EU summer-time rule rather than ``zoneinfo``: the
slim base image ships no tz database, and the rule has been fixed since 1996.
"""

from __future__ import annotations

import calendar
import datetime as dt
import json
import sqlite3
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from ..model import iso
from . import outbox, router
from .testing import TEST_TARGET

if TYPE_CHECKING:
    from .engine import AlertEngine

HOUR = 8


def _last_sunday(year: int, month: int) -> dt.datetime:
    d = dt.date(year, month, calendar.monthrange(year, month)[1])
    d -= dt.timedelta(days=(d.weekday() - 6) % 7)
    return dt.datetime(d.year, d.month, d.day, 1, tzinfo=dt.UTC)


def amsterdam(ts: dt.datetime) -> dt.datetime:
    """Local Europe/Amsterdam wall time (naive) for a UTC instant."""
    summer = _last_sunday(ts.year, 3) <= ts < _last_sunday(ts.year, 10)
    return (ts.astimezone(dt.UTC) + dt.timedelta(hours=2 if summer else 1)).replace(tzinfo=None)


def slot_utc(day: dt.date) -> dt.datetime:
    """08:00 Amsterdam on ``day`` as a UTC instant (06:00 UTC in summer, 07:00 in winter).
    Clocks change at 01:00 UTC, so 08:00 local is never ambiguous."""
    for offset in (2, 1):
        ts = dt.datetime(day.year, day.month, day.day, HOUR - offset, tzinfo=dt.UTC)
        if amsterdam(ts) == dt.datetime(day.year, day.month, day.day, HOUR):
            return ts
    raise AssertionError(f"no 08:00 Amsterdam on {day}")  # pragma: no cover


def daily_slot(now: dt.datetime) -> dt.datetime:
    """The latest 08:00 Amsterdam at or before ``now``."""
    local = amsterdam(now)
    day = local.date() if local.hour >= HOUR else local.date() - dt.timedelta(days=1)
    return slot_utc(day)


def weekly_slot(now: dt.datetime) -> dt.datetime:
    """The latest Monday 08:00 Amsterdam at or before ``now``."""
    local = amsterdam(now).date()
    slot = slot_utc(local - dt.timedelta(days=local.weekday()))
    return slot if slot <= now else slot_utc(local - dt.timedelta(days=local.weekday() + 7))


def _mark(value: str | None) -> dt.datetime | None:
    """The last slot a digest ran for. Older rows stored a date or an ISO week."""
    if not value:
        return None
    try:
        if "-W" in value:
            year, week = value.split("-W")
            return slot_utc(dt.date.fromisocalendar(int(year), int(week), 1))
        if len(value) == 10:
            return slot_utc(dt.date.fromisoformat(value))
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def enqueue_due(db: sqlite3.Connection, engine: AlertEngine, now: dt.datetime) -> list[str]:
    """Queue whichever digests are due; each runs once per slot (08:00 Amsterdam daily,
    Monday 08:00 weekly). A digest covers everything since the previous one ran, not a
    fixed 24 h, so neither a DST change (23 or 25 h between slots) nor a late run (the
    core was down at 08:00) leaves a gap. A missed slot is caught up on the next tick."""
    store, done = engine.store, []
    daily, weekly = daily_slot(now), weekly_slot(now)
    last_d, last_w = _mark(store.get_meta("digest_daily")), _mark(store.get_meta("digest_weekly"))
    if last_d is None:  # first start: do not fire on deploy, but do fire at the next 08:00
        store.set_meta("digest_daily", iso(daily))
        store.set_meta("digest_weekly", iso(weekly))
        return []
    if last_d < daily:
        day = amsterdam(daily).date().isoformat()
        _mail(db, engine, now, "warning", last_d, f"Daily digest {day}")
        _slack_info(db, engine, now, last_d)
        store.set_meta("digest_daily", iso(daily))
        done.append("daily")
    if last_w is None or last_w < weekly:
        year, week, _ = amsterdam(weekly).isocalendar()
        _mail(db, engine, now, "info", last_w or weekly - dt.timedelta(days=7),
              f"Weekly digest {year}-W{week:02d}")
        store.set_meta("digest_weekly", iso(weekly))
        done.append("weekly")
    return done


def incidents(db: sqlite3.Connection, severity: str, since: dt.datetime) -> list[dict[str, Any]]:
    """Open now, or opened or closed since ``since``. Test incidents are left out."""
    return [dict(r) for r in db.execute(
        "SELECT * FROM incidents WHERE severity=? AND target_id<>? AND "
        "(closed_at IS NULL OR closed_at>=? OR opened_at>=?) ORDER BY opened_at",
        (severity, TEST_TARGET, iso(since), iso(since)))]


def line(inc: dict[str, Any], engine: AlertEngine, now: dt.datetime) -> str:
    t = engine.target_for(inc["target_id"])
    opened = dt.datetime.fromisoformat(inc["opened_at"])
    if inc["closed_at"]:
        state = (f"resolved after "
                 f"{router.duration(opened, dt.datetime.fromisoformat(inc['closed_at']))}")
    else:
        state = f"open since {router.stamp(opened)}"
    what = t.public_summary if inc["private"] else ", ".join(
        p.split("@")[0] for p in dict.fromkeys(json.loads(inc["failing"])))
    return f"- {t.name}: {state}" + (f" ({what})" if what else "")


def _mail(db: sqlite3.Connection, engine: AlertEngine, now: dt.datetime, severity: str,
          since: dt.datetime, title: str) -> int:
    owners = engine.catalogue.owners
    if owners is None:
        return 0
    per: dict[str, list[str]] = defaultdict(list)
    for inc in incidents(db, severity, since):
        for handle in router.digest_recipients(engine.target_for(inc["target_id"]), owners):
            per[handle].append(line(inc, engine, now))
    link = f"{engine.private_url.rstrip('/')}/incidents"
    for handle, lines in sorted(per.items()):
        text = (f"{len(lines)} {severity} incident(s) on targets you look after:\n\n"
                + "\n".join(lines) + f"\n\nAll incidents (TGX login): {link}")
        outbox.enqueue(db, channel="smtp", event="digest", now=now, recipients=[handle],
                       dry_run=engine.dry_run,
                       payload={"subject": f"[tgx-monitor] {title}: {len(lines)} {severity}",
                                "text": text, "line": f"{title} for {handle}"})
    return len(per)


def _slack_info(db: sqlite3.Connection, engine: AlertEngine, now: dt.datetime,
                since: dt.datetime) -> None:
    rows = incidents(db, "info", since)
    if not rows:
        return
    names = ", ".join(dict.fromkeys(engine.target_for(r["target_id"]).name for r in rows))
    open_n = sum(1 for r in rows if not r["closed_at"])
    text = f":white_circle: Low-severity: {open_n} open, {len(rows)} in the last day - {names}"
    outbox.enqueue(db, channel="slack", event="digest", now=now, dry_run=engine.dry_run,
                   payload={"text": text, "line": "daily info summary",
                            "link": f"{engine.private_url.rstrip('/')}/incidents"})
