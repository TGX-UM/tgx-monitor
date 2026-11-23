"""The nightly backup inside core: off the scheduler, and a lost ping is not a lost day.

2026-11-22: the backup (on the event loop) and its healthchecks ping shared one 120 s
timeout. Once the database passed ~0.9 GB the ping was always cancelled, the day never
counted as done, the whole backup ran again every hour, and the next morning core
restart-looped on its health check.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import time

from tgx_monitor import service as S
from tgx_monitor.store import Store

AT = dt.datetime(2026, 11, 23, 2, 0, tzinfo=dt.UTC)


class Hc:
    def __init__(self, fail: Exception | None = None, delay: float = 0.0) -> None:
        self.fail, self.delay, self.pings = fail, delay, []

    async def ping(self, check: str, status: str, body: str) -> None:
        self.pings.append((check, status))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise self.fail


def core(tmp_path, hc: Hc | None) -> S.Service:
    s = S.Service.__new__(S.Service)
    s.store = Store(tmp_path / "data" / "monitor.db")
    s.backup_dir = tmp_path / "data" / "backups"
    s.scratch_dir = tmp_path / "scratch"
    s.channels = {"hc": hc} if hc else {}
    s._nightly_task = None
    s._started_mono = time.monotonic()
    s._last_result_mono = None
    return s


async def test_nightly_backs_up_through_scratch_and_marks_the_day(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "utcnow", lambda: AT)
    hc = Hc()
    s = core(tmp_path, hc)
    await s._nightly()
    assert s.store.get_meta("nightly_done") == "2026-11-23"
    assert (s.backup_dir / "monitor-2026-11-23.db").is_file()
    assert list(s.scratch_dir.iterdir()) == []
    assert hc.pings == [("monitor-backup", "success")]
    await s._nightly()  # done for today: no second backup, no second ping
    assert hc.pings == [("monitor-backup", "success")]


async def test_a_failed_ping_does_not_repeat_the_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "utcnow", lambda: AT)
    s = core(tmp_path, Hc(fail=TimeoutError()))
    await s._nightly()
    assert s.store.get_meta("nightly_done") == "2026-11-23"


async def test_nightly_runs_as_its_own_task(tmp_path, monkeypatch):
    """The hook only starts it; a slow ping must not hold up the hooks (and so the
    scheduler, which awaits them), and a second start while it runs is a no-op."""
    monkeypatch.setattr(S, "utcnow", lambda: AT)
    s = core(tmp_path, Hc(delay=0.5))
    started = time.monotonic()
    assert s._start_nightly() is None
    first = s._nightly_task
    s._start_nightly()
    assert s._nightly_task is first
    assert time.monotonic() - started < 0.4
    await first
    assert s.store.get_meta("nightly_done") == "2026-11-23"


def test_results_quiet(tmp_path):
    s = core(tmp_path, None)
    assert s._results_quiet_s(limit=60) is None  # just started
    s._started_mono = time.monotonic() - 120
    assert s._results_quiet_s(limit=60) >= 120  # nothing yet after two minutes
    s._last_result_mono = time.monotonic() - 5
    assert s._results_quiet_s(limit=60) is None
    s._last_result_mono = time.monotonic() - 1000
    assert s._results_quiet_s(limit=900) >= 1000
