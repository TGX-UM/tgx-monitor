"""The run loop: every probe on its own cadence, bounded concurrency, one writer.

A plain asyncio loop rather than a scheduler library: each probe has a next-due time,
the loop wakes every second, starts what is due (up to ``max_concurrency`` at once,
with a further per-host bound in :class:`~tgx_monitor.http.Http`), and hands each result
to the store and then to the alert engine. Start times are jittered deterministically
by probe id so 600 probes do not all fire at minute zero after a restart.

Liveness is the loop's own business: ``last_tick`` is updated every second and is what
``/livez`` and the healthchecks.io ``core-cycle`` ping report. A target being down must
never make the monitor look unhealthy -- that would restart-loop it exactly when it is
needed.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .catalogue import Catalogue, Check, Target
from .kinds.base import Context, run_probe
from .model import Result, iso, utcnow

log = logging.getLogger("tgx_monitor.scheduler")

OnResult = Callable[[str, str, Target, Check, Result, int], Awaitable[None] | None]


def _jitter(probe_id: str, interval: float) -> float:
    h = int(hashlib.sha256(probe_id.encode()).hexdigest()[:8], 16)
    return (h % 1000) / 1000.0 * min(interval, 300.0)


@dataclass
class ProbeSlot:
    probe_id: str
    via: str
    target: Target
    check: Check
    next_due: float
    running: bool = False
    retry_pending: bool = False
    regular_due: float = 0.0  # where the cadence resumes after a retry


@dataclass
class Scheduler:
    ctx: Context
    catalogue: Catalogue
    on_result: OnResult | None = None
    on_tick: Callable[[], None] | None = None  # persists liveness (store meta last_tick)
    max_concurrency: int = 20
    slots: dict[str, ProbeSlot] = field(default_factory=dict)
    last_tick: dt.datetime | None = None
    last_full_cycle: dt.datetime | None = None
    _sem: asyncio.Semaphore | None = None
    _stop: asyncio.Event | None = None
    _tasks: set[asyncio.Task[Any]] = field(default_factory=set)

    def load(self, catalogue: Catalogue | None = None) -> None:
        """(Re)build the probe table, keeping due times for probes that still exist."""
        if catalogue is not None:
            self.catalogue = catalogue
            self.ctx.catalogue = catalogue
        loop_now = asyncio.get_event_loop().time() if self._running_loop() else 0.0
        fresh: dict[str, ProbeSlot] = {}
        for pid, via, t, c in self.catalogue.probes():
            old = self.slots.get(pid)
            due = old.next_due if old else loop_now + _jitter(pid, c.interval_s)
            fresh[pid] = ProbeSlot(pid, via, t, c, due)
        self.slots = fresh

    @staticmethod
    def _running_loop() -> bool:
        try:
            asyncio.get_running_loop()
            return True
        except RuntimeError:
            return False

    async def run_one(self, slot: ProbeSlot) -> Result:
        result = await run_probe(slot.target, slot.check, slot.probe_id, slot.via, self.ctx)
        rid = 0
        if self.ctx.store is not None:
            rid = await asyncio.to_thread(self.ctx.store.save_result, result, slot.probe_id,
                                          slot.via, self.catalogue.sha)
        if self.on_result is not None:
            maybe = self.on_result(slot.probe_id, slot.via, slot.target, slot.check, result, rid)
            if asyncio.iscoroutine(maybe):
                await maybe
        return result

    async def _guarded(self, slot: ProbeSlot) -> None:
        assert self._sem is not None
        async with self._sem:
            try:
                result = await self.run_one(slot)
                # Sparse checks (daily/weekly) get one quick retry before they count, so
                # a single blip does not wait a day to clear.
                if (result.status == "failed" and slot.check.retry and not slot.retry_pending):
                    from .assertions import parse_duration
                    slot.retry_pending = True
                    slot.next_due = asyncio.get_event_loop().time() + parse_duration(
                        slot.check.retry)
                else:
                    slot.retry_pending = False
            except Exception:  # noqa: BLE001 - never let one probe kill the loop
                log.exception("probe %s crashed outside the kind boundary", slot.probe_id)
            finally:
                slot.running = False

    async def run_forever(self, hooks: list[Callable[[], Awaitable[None]]] | None = None,
                          hook_every: float = 60.0) -> None:
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._stop = asyncio.Event()
        self.load()
        loop = asyncio.get_running_loop()
        last_hook = 0.0
        while not self._stop.is_set():
            now = loop.time()
            self.last_tick = utcnow()
            if self.on_tick is not None:
                try:
                    self.on_tick()
                except Exception:  # noqa: BLE001
                    log.exception("on_tick failed")
            for slot in self.slots.values():
                if slot.running or now < slot.next_due:
                    continue
                slot.running = True
                if slot.retry_pending:
                    slot.next_due = slot.regular_due  # after the retry, back to the cadence
                else:
                    slot.regular_due = slot.next_due = now + slot.check.interval_s
                task = asyncio.create_task(self._guarded(slot))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            if hooks and now - last_hook >= hook_every:
                last_hook = now
                for h in hooks:
                    try:
                        await h()
                    except Exception:  # noqa: BLE001
                        log.exception("periodic hook %s failed", getattr(h, "__name__", h))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=1.0)
        for t in list(self._tasks):
            t.cancel()

    def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()

    def status(self) -> dict[str, Any]:
        running = sum(1 for s in self.slots.values() if s.running)
        return {"probes": len(self.slots), "running": running,
                "last_tick": iso(self.last_tick) if self.last_tick else None}


async def run_all_once(ctx: Context, catalogue: Catalogue, only: list[str] | None = None,
                       concurrency: int = 10,
                       on_result: OnResult | None = None) -> list[tuple[str, str, Result]]:
    """Run every (or selected) probe once; used by ``check --once`` and tests."""
    sched = Scheduler(ctx=ctx, catalogue=catalogue, on_result=on_result,
                      max_concurrency=concurrency)
    sched.load()
    sem = asyncio.Semaphore(concurrency)
    sel = [s for s in sched.slots.values()
           if not only or s.probe_id in only or s.check.id in only or s.target.id in only]

    async def one(s: ProbeSlot) -> tuple[str, str, Result]:
        async with sem:
            return s.probe_id, s.via, await sched.run_one(s)

    return await asyncio.gather(*(one(s) for s in sel))
