"""Maintenance windows: a small RRULE subset, always in UTC.

The windows in ``maintenance.yaml`` come from cron schedules (weekly reloads, a monthly
switch, a daily store build), so the whole of RFC 5545 is not needed and a library would
be more code to trust than the rule itself. Supported::

    FREQ=DAILY | WEEKLY | MONTHLY
    BYDAY=MO,TU,..,SU          (required for WEEKLY; a filter otherwise)
    BYMONTHDAY=12 | -1         (MONTHLY; negative counts from the month's end)

plus the window's ``start`` (HH:MM UTC) and ``duration`` (e.g. 100m). Anything else is
rejected by :func:`problems` so ``doctor`` catches it, instead of a window silently never
matching and a reload paging someone at six on a Sunday.
"""

from __future__ import annotations

import calendar
import dataclasses
import datetime as dt
from functools import lru_cache

from ..assertions import parse_duration
from ..catalogue import Window

DAYS = ("MO", "TU", "WE", "TH", "FR", "SA", "SU")


@dataclasses.dataclass(frozen=True)
class Rule:
    freq: str
    byday: frozenset[int]
    bymonthday: frozenset[int]


@lru_cache(maxsize=256)
def parse_rrule(text: str) -> Rule:
    parts: dict[str, str] = {}
    for item in text.strip().removeprefix("RRULE:").split(";"):
        if not item:
            continue
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"bad RRULE part {item!r}")
        parts[key.upper()] = value.upper()
    freq = parts.pop("FREQ", "")
    if freq not in ("DAILY", "WEEKLY", "MONTHLY"):
        raise ValueError(f"FREQ must be DAILY, WEEKLY or MONTHLY, not {freq!r}")
    byday = frozenset(DAYS.index(d) for d in _split(parts.pop("BYDAY", ""), DAYS))
    bymonthday = frozenset(int(n) for n in _split(parts.pop("BYMONTHDAY", ""), None))
    if parts:
        raise ValueError(f"unsupported RRULE parts: {', '.join(sorted(parts))}")
    if freq == "WEEKLY" and not byday:
        raise ValueError("FREQ=WEEKLY needs BYDAY")
    if freq == "MONTHLY" and not (bymonthday or byday):
        raise ValueError("FREQ=MONTHLY needs BYMONTHDAY or BYDAY")
    if any(n == 0 or abs(n) > 31 for n in bymonthday):
        raise ValueError("BYMONTHDAY must be 1..31 or -31..-1")
    return Rule(freq, byday, bymonthday)


def _split(value: str, allowed: tuple[str, ...] | None) -> list[str]:
    out = [v for v in value.split(",") if v]
    for v in out:
        if allowed is not None and v not in allowed:
            raise ValueError(f"BYDAY value {v!r} not in {','.join(allowed)}")
        if allowed is None and not v.lstrip("-").isdigit():
            raise ValueError(f"BYMONTHDAY value {v!r} is not a number")
    return out


def matches(rule: Rule, day: dt.date) -> bool:
    """Does an occurrence start on ``day``?"""
    if rule.byday and day.weekday() not in rule.byday:
        return False
    if rule.bymonthday:
        last = calendar.monthrange(day.year, day.month)[1]
        wanted = {n if n > 0 else last + 1 + n for n in rule.bymonthday}
        if day.day not in wanted:
            return False
    return True


def _start_and_length(w: Window) -> tuple[dt.time, dt.timedelta]:
    hh, _, mm = w.start.partition(":")
    return dt.time(int(hh), int(mm or 0), tzinfo=dt.UTC), dt.timedelta(
        seconds=parse_duration(w.duration))


def active(w: Window, now: dt.datetime) -> tuple[dt.datetime, dt.datetime] | None:
    """(start, end) of the occurrence covering ``now``, else None. Crosses midnight."""
    rule = parse_rrule(w.rrule)
    at, length = _start_and_length(w)
    for back in range(length.days + 2):
        day = now.date() - dt.timedelta(days=back)
        if matches(rule, day):
            start = dt.datetime.combine(day, at)
            if start <= now < start + length:
                return start, start + length
    return None


def next_start(w: Window, now: dt.datetime, horizon_days: int = 400) -> dt.datetime | None:
    """The next occurrence starting after ``now``, for the 'upcoming windows' list."""
    rule = parse_rrule(w.rrule)
    at, _ = _start_and_length(w)
    for ahead in range(horizon_days):
        day = now.date() + dt.timedelta(days=ahead)
        if matches(rule, day):
            start = dt.datetime.combine(day, at)
            if start > now:
                return start
    return None


def problems(w: Window) -> list[str]:
    """Everything wrong with one window, for ``doctor``."""
    out = []
    try:
        parse_rrule(w.rrule)
    except ValueError as exc:
        out.append(f"window {w.id}: {exc}")
    try:
        _, length = _start_and_length(w)
        if length <= dt.timedelta(0):
            out.append(f"window {w.id}: duration must be positive")
    except ValueError as exc:
        out.append(f"window {w.id}: start/duration: {exc}")
    return out
