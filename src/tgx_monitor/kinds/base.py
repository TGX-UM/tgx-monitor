"""Check-kind contract and the probe runner.

Same shape as tgx-outputs ``collect/base.py``: a kind is one class with one method, it
never touches the database, and a broken kind cannot take the run down. A kind's job is
to *observe*; :mod:`tgx_monitor.assertions` judges.

To add a kind::

    @register
    class Ping(Kind):
        name = "ping"
        required = ("url",)                 # request keys doctor insists on

        async def observe(self, check, via, ctx):
            f = await ctx.http.get(check.request["url"], via=via)
            return self.from_fetch(f)        # status, latency_ms, body, headers, ...
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import json
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from .. import assertions as A
from ..http import Fetched, Http, classify
from ..model import Observation, Result, utcnow, worst
from ..redact import redact_text

if TYPE_CHECKING:
    from ..catalogue import Catalogue, Check, Target
    from ..store import Store

KINDS: dict[str, type[Kind]] = {}


@dataclasses.dataclass
class Context:
    """Everything a kind may use. Optional members are None where unavailable."""

    http: Http
    catalogue: Catalogue
    store: Store | None = None
    secrets: Callable[[str], str | None] = lambda name: None
    docker: Any = None  # DockerAPI client (via the GET-only socket proxy)
    agents: Any = None  # AgentClient: host signals from the global-mode agents
    mounts: dict[str, Path] = dataclasses.field(default_factory=dict)  # alias -> ro path
    now: Callable[[], dt.datetime] = utcnow
    env: dict[str, str] = dataclasses.field(default_factory=dict)


class Kind:
    name: ClassVar[str] = "abstract"
    required: ClassVar[tuple[str, ...]] = ()
    vias: ClassVar[tuple[str, ...] | None] = None  # None: any; else allowed via values

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        raise NotImplementedError

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = [f"request missing {k!r}" for k in cls.required if k not in request]
        if cls.vias is not None:
            probs += [f"via {v!r} not supported by kind {cls.name}" for v in via
                      if v not in cls.vias]
        return probs

    # Shared helper: the standard observation for one HTTP fetch.
    @staticmethod
    def from_fetch(f: Fetched, *, parse_json: bool = False) -> Observation:
        err, unk = classify(f)
        values: dict[str, Any] = {
            "status": f.status, "latency_ms": f.ms, "body": f.text,
            "headers": f.headers, "final_url": f.final_url, "redirects": f.redirects,
            "redirect_count": len(f.redirects), "size": len(f.text),
        }
        if parse_json and f.text:
            try:
                values["json"] = json.loads(f.text)
            except ValueError:
                values["json_error"] = "body is not JSON"
        return Observation(values=values, calls=[f.call], error=err, unknown=unk,
                           evidence=redact_text(f.text[:4000]) if f.text else (f.error or ""))


def register(cls: type[Kind]) -> type[Kind]:
    if cls.name in KINDS and KINDS[cls.name] is not cls:
        raise RuntimeError(f"kind {cls.name!r} registered twice")
    KINDS[cls.name] = cls
    return cls


async def run_probe(target: Target, check: Check, probe_id: str, via: str,
                    ctx: Context) -> Result:
    """Observe with total failure isolation and a hard timeout, then judge."""
    started = ctx.now()
    t0 = time.perf_counter()
    kind_cls = KINDS.get(check.kind)
    if kind_cls is None:
        return Result(check.id, target.id, "unknown", started, 0.0,
                      summary=f"no kind {check.kind!r} in this build")
    try:
        obs = await asyncio.wait_for(kind_cls().observe(check, via, ctx),
                                     timeout=check.timeout_s + 15)
    except TimeoutError:
        obs = Observation(error=f"check exceeded {check.timeout} (+15s grace)")
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
        obs = Observation(unknown=f"kind {check.kind} crashed: {type(exc).__name__}: {exc}",
                          evidence=traceback.format_exc(limit=4))
    dur = round((time.perf_counter() - t0) * 1000, 1)
    obs.values.setdefault("latency_ms", dur)

    def baseline(path: str, window_s: float) -> list[float]:
        if ctx.store is None:
            return []
        return ctx.store.baseline(probe_id, path, window_s, before=started)

    outcomes = []
    if obs.error is not None:
        status = "failed"
        summary = f"no answer: {obs.error}"
    elif obs.unknown is not None:
        status = "unknown"
        summary = obs.unknown
    else:
        now = ctx.now()
        outcomes = [A.evaluate(a, obs.values, now, baseline) for a in check.assert_]
        status = worst([o.status for o in outcomes])
        bad = [o for o in outcomes if o.status != "ok"]
        summary = ("; ".join(f"{o.assertion}: found {o.found}" for o in bad[:3])
                   if bad else f"{len(outcomes)} assertions held")
    metrics = {**obs.metrics, **A.numeric_paths(check.assert_, obs.values)}
    return Result(
        check_id=check.id, target_id=target.id, status=status, started_at=started,
        duration_ms=dur, outcomes=outcomes, calls=obs.calls, metrics=metrics,
        summary=summary[:1000], evidence=obs.evidence if status != "ok" else "",
        warn=any(o.warn_only for o in outcomes),
    )
