"""Core data types: what a check run produces.

Adapted from tgx-outputs ``model.py``. The difference that matters: in a monitor the
failure *is* the measurement, so nothing here raises. A kind observes, the assertion
engine judges, and the result carries enough provenance (every call, the literal
request, what came back) for the per-check page to show exactly why it is red.

Status vocabulary:

* ``ok``      every assertion held.
* ``failed``  an assertion did not hold, or the target did not answer.
* ``unknown`` we could not tell: a 429, a client-side timeout on a slow-but-alive
              endpoint, a missing credential. Never counted as a failure, never as ok.
* ``skipped`` disabled, or outside its schedule.
* ``blocked`` set by the alert engine, not by a kind: an ancestor is failing.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Any, Literal

Status = Literal["ok", "failed", "unknown", "skipped", "blocked"]

# Severity ladder used when combining assertion outcomes: the worst wins.
_RANK = {"ok": 0, "skipped": 0, "unknown": 1, "failed": 2, "blocked": 1}


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def iso(ts: dt.datetime | None = None) -> str:
    return (ts or utcnow()).isoformat(timespec="seconds")


@dataclasses.dataclass(slots=True)
class Call:
    """One request made by a check, kept so the explainability page can show it."""

    method: str
    url: str
    via: str = "public"  # public | tgx1 | tgx2 | docker | file | agent
    status: int | None = None
    ok: bool = False
    ms: float | None = None
    note: str = ""


@dataclasses.dataclass(slots=True)
class Outcome:
    """The verdict of one assertion."""

    assertion: str  # human-readable form, e.g. "status == 200"
    status: Status
    expected: str = ""
    found: str = ""
    warn_only: bool = False  # a 'warn' threshold breached: shown amber, does not fail


@dataclasses.dataclass(slots=True)
class Observation:
    """What a kind saw. ``values`` is a flat-ish dict the assertions address by path.

    Conventions shared by all kinds so assertions read the same everywhere:
    ``status`` (HTTP status), ``latency_ms``, ``body`` (text, capped), ``json``
    (parsed body), ``rows`` (list of dicts for tabular results), ``count``,
    ``headers`` (lower-case keys), ``final_url``, ``redirects`` (list of urls).
    """

    values: dict[str, Any] = dataclasses.field(default_factory=dict)
    calls: list[Call] = dataclasses.field(default_factory=list)
    error: str | None = None  # the target did not answer at all -> failed
    unknown: str | None = None  # could not tell (429, missing secret) -> unknown
    metrics: dict[str, float] = dataclasses.field(default_factory=dict)  # stored for baselines
    evidence: str = ""  # redacted, capped excerpt kept on failure


@dataclasses.dataclass(slots=True)
class Result:
    check_id: str
    target_id: str
    status: Status
    started_at: dt.datetime
    duration_ms: float
    outcomes: list[Outcome] = dataclasses.field(default_factory=list)
    calls: list[Call] = dataclasses.field(default_factory=list)
    metrics: dict[str, float] = dataclasses.field(default_factory=dict)
    summary: str = ""
    evidence: str = ""
    warn: bool = False  # ok overall but a warn threshold was crossed

    def as_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["started_at"] = iso(self.started_at)
        return d


def worst(statuses: list[Status]) -> Status:
    if not statuses:
        return "ok"
    return max(statuses, key=lambda s: _RANK[s])
