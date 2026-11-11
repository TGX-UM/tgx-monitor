"""Shared fixtures for the alert tests: a small catalogue, a fake clock, stub channels.

No tests live here; the module is named ``test_alerts_*`` only so it sits with them.

The catalogue is a DAG: ``edge-tgx1`` -> ``app-a`` (critical, weekly Sunday window) and
``app-b`` (warning); plus a security canary, a daily backup, an info target, a vantage
probe and four fillers so the vantage rule has a population to judge.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import yaml

from tgx_monitor.alerts.channels.base import Message
from tgx_monitor.alerts.dispatcher import Dispatcher
from tgx_monitor.alerts.engine import AlertEngine
from tgx_monitor.catalogue import Catalogue
from tgx_monitor.model import Result
from tgx_monitor.store import Store

T0 = dt.datetime(2026, 11, 11, 9, 0, tzinfo=dt.UTC)  # a Wednesday

OWNERS = {
    "admins": ["marvinm2", "egonw"], "fallback": ["marvinm2"], "infra_cc": ["egonw"],
    "people": {"marvinm2": {"name": "M", "notify": True}, "egonw": {"name": "E", "notify": True},
               "ozancinar": {"name": "O", "notify": False},
               "ext-01": {"name": "X", "notify": True, "github": False}},
}
WINDOWS = [{"id": "sunday-reload", "describe": "weekly reload", "rrule": "FREQ=WEEKLY;BYDAY=SU",
            "start": "05:50", "duration": "100m"}]


def _t(tid: str, cls: str, crit: str, owners: list[str], checks: list[dict[str, Any]],
       **extra: Any) -> dict[str, Any]:
    return {"id": tid, "name": tid.upper(), "class": cls, "criticality": crit, "owners": owners,
            "public_summary": f"{tid} public summary", "checks": checks, **extra}


def _c(cid: str, every: str = "5m", kind: str = "http", **extra: Any) -> dict[str, Any]:
    return {"id": cid, "kind": kind, "every": every, "describe": f"{cid} works",
            "assert": [{"that": "status", "eq": 200}], **extra}


TARGETS = [
    _t("app-a", "service", "high", ["marvinm2", "ozancinar"],
       [_c("app-a-home", via=["public", "tgx1"])], depends_on=["edge-tgx1"],
       maintenance=["sunday-reload"]),
    _t("app-b", "data", "medium", ["ozancinar"], [_c("app-b-sparql")], depends_on=["edge-tgx1"]),
    _t("edge-tgx1", "infra", "high", ["egonw"], [_c("edge-tgx1-http")]),
    _t("canary", "security", "high", ["marvinm2"], [_c("canary-conductor")], public=False),
    _t("daily-backup", "backup", "high", ["marvinm2"], [_c("backup-age", every="1d")]),
    _t("info-thing", "service", "low", ["marvinm2"], [_c("info-thing-up")]),
    _t("monitor-self", "infra", "high", ["marvinm2"], [_c("monitor-vantage", kind="vantage")]),
] + [_t(f"filler-{i}", "service", "medium", ["marvinm2"], [_c(f"filler-{i}-up")])
     for i in range(1, 5)]


def make_catalogue(root: Path) -> Catalogue:
    (root / "targets").mkdir(parents=True, exist_ok=True)
    (root / "owners.yaml").write_text(yaml.safe_dump(OWNERS))
    (root / "maintenance.yaml").write_text(yaml.safe_dump(WINDOWS))
    (root / "targets" / "all.yaml").write_text(yaml.safe_dump(TARGETS, sort_keys=False))
    cat = Catalogue(root)
    assert not cat.problems, cat.problems
    return cat


class Clock:
    def __init__(self, t: dt.datetime = T0) -> None:
        self.t = t

    def __call__(self) -> dt.datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += dt.timedelta(**kw)


class StubChannel:
    """Records every message; ``fail`` makes it answer like a provider error."""

    def __init__(self, name: str, fail: int | None = None) -> None:
        self.name = name
        self.fail = fail
        self.sent: list[Message] = []
        self.next_issue = 100

    async def send(self, msg: Message) -> tuple[bool, dict[str, Any]]:
        self.sent.append(msg)
        if self.fail:
            return False, {"status": self.fail}
        if self.name == "github" and msg.payload.get("action") == "open":
            self.next_issue += 1
            return True, {"status": 201, "number": self.next_issue}
        return True, {"status": {"smtp": 250}.get(self.name, 200), "number": msg.issue_number}

    def actions(self) -> list[str]:
        return [m.payload.get("action", m.event) for m in self.sent]


class World:
    """Engine + dispatcher on one store, driven by a fake clock."""

    def __init__(self, tmp: Path, fail: dict[str, int] | None = None) -> None:
        self.tmp = tmp
        self.clock = Clock()
        self.cat = make_catalogue(tmp / "catalogue")
        self.store = Store(":memory:")
        self.engine = self.new_engine()
        self.channels = {n: StubChannel(n, (fail or {}).get(n))
                         for n in ("github", "smtp", "slack", "hc")}
        self.dispatcher = Dispatcher(self.store, self.channels, now=self.clock,
                                     admins=["marvinm2", "egonw"])

    def new_engine(self) -> AlertEngine:
        return AlertEngine(self.store, self.cat, now=self.clock, dry_run=False,
                           private_base_url="https://monitor.example.org",
                           public_base_url="https://status.example.org")

    def feed(self, probe_id: str, status: str) -> None:
        for pid, via, t, c in self.cat.probes():
            if pid == probe_id:
                r = Result(c.id, t.id, status, self.clock(), 1.0)  # type: ignore[arg-type]
                self.engine.ingest(pid, via, t, c, r, 1)
                return
        raise KeyError(probe_id)

    def cycle(self, failing: set[str] = frozenset(), minutes: float = 5,  # type: ignore[assignment]
              status: str = "failed") -> None:
        """One 5-minute round: every 5m probe reports; ids in ``failing`` (probe, check
        or target ids) report ``status``; then a tick; then the clock moves on."""
        for pid, _via, t, c in self.cat.probes():
            if c.interval_s > 300:
                continue
            bad = pid in failing or c.id in failing or t.id in failing
            self.feed(pid, status if bad else "ok")
        self.engine.tick()
        self.clock.advance(minutes=minutes)

    async def dispatch(self) -> dict[str, int]:
        return await self.dispatcher.run_once()

    def rows(self, **where: Any) -> list[dict[str, Any]]:
        rows = self.store.query("SELECT * FROM outbox WHERE event NOT IN ('watchdog') "
                                "ORDER BY id")
        for r in rows:
            r["recipients"] = json.loads(r["recipients"])
            r["payload"] = json.loads(r["payload"])
        return [r for r in rows if all(r[k] == v for k, v in where.items())]

    def incidents(self, open_only: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM incidents" + (" WHERE closed_at IS NULL" if open_only else "")
        return self.store.query(sql + " ORDER BY id")
