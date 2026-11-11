"""The RRULE subset behind maintenance windows."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from tgx_monitor.alerts import windows as W
from tgx_monitor.catalogue import Catalogue, Window


def _w(rrule: str, start: str = "05:50", duration: str = "100m") -> Window:
    return Window(id="w", describe="d", rrule=rrule, start=start, duration=duration)


def _at(*a: int) -> dt.datetime:
    return dt.datetime(*a, tzinfo=dt.UTC)


def test_weekly_sunday() -> None:
    w = _w("FREQ=WEEKLY;BYDAY=SU")
    assert W.active(w, _at(2026, 11, 15, 5, 49)) is None
    assert W.active(w, _at(2026, 11, 15, 5, 50)) == (_at(2026, 11, 15, 5, 50),
                                                     _at(2026, 11, 15, 7, 30))
    assert W.active(w, _at(2026, 11, 15, 7, 30)) is None
    assert W.active(w, _at(2026, 11, 16, 6, 0)) is None  # Monday
    assert W.next_start(w, _at(2026, 11, 11)) == _at(2026, 11, 15, 5, 50)


def test_monthly_and_last_day() -> None:
    w = _w("FREQ=MONTHLY;BYMONTHDAY=12", "01:50")
    assert W.active(w, _at(2026, 11, 12, 2, 0))
    assert not W.active(w, _at(2026, 11, 13, 2, 0))
    last = _w("FREQ=MONTHLY;BYMONTHDAY=-1", "23:00", "2h")
    assert W.active(last, _at(2027, 2, 28, 23, 30))
    assert W.active(last, _at(2027, 3, 1, 0, 30)), "crosses midnight into the next month"
    assert not W.active(last, _at(2027, 3, 1, 1, 0))


def test_daily_with_byday_filter() -> None:
    w = _w("FREQ=DAILY;BYDAY=MO,TU,WE,TH,FR", "04:25", "45m")
    assert W.active(w, _at(2026, 11, 11, 4, 30))  # Wednesday
    assert not W.active(w, _at(2026, 11, 14, 4, 30))  # Saturday


@pytest.mark.parametrize("bad", ["FREQ=YEARLY", "FREQ=WEEKLY", "FREQ=WEEKLY;BYDAY=XX",
                                 "FREQ=MONTHLY", "FREQ=DAILY;INTERVAL=2",
                                 "FREQ=MONTHLY;BYMONTHDAY=0"])
def test_rejects_unsupported(bad: str) -> None:
    assert W.problems(_w(bad))


def test_real_catalogue_windows_parse() -> None:
    root = Path(__file__).resolve().parents[1] / "catalogue"
    cat = Catalogue(root)
    assert cat.windows
    for w in cat.windows.values():
        assert W.problems(w) == []
        assert W.next_start(w, _at(2026, 11, 11)) is not None
