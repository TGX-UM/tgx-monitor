"""The run loop and the probe boundary, driven by a fake kind.

What must hold: a kind that crashes or errors yields a Result (never an exception), the
result is stored and handed on, ``only`` selects probes, and a sparse check that fails
gets exactly one quick retry before it waits for its next regular run.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import textwrap
from pathlib import Path

import pytest

from tgx_monitor import catalogue as catmod
from tgx_monitor.http import Http
from tgx_monitor.kinds.base import KINDS, Context, Kind, register, run_probe
from tgx_monitor.model import Call, Observation
from tgx_monitor.scheduler import ProbeSlot, Scheduler, _jitter, run_all_once
from tgx_monitor.store import Store

SCRIPT: dict[str, list[dict]] = {}  # probe-visible plan: check id -> queued behaviours
CALLS: list[tuple[str, str]] = []
NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)


@register
class FakeKind(Kind):
    """Behaves as the test says: values, error, unknown, or a crash."""

    name = "fake-test"

    async def observe(self, check, via, ctx):
        CALLS.append((check.id, via))
        plan = SCRIPT.get(check.id) or [{}]
        step = plan.pop(0) if len(plan) > 1 else plan[0]
        if step.get("crash"):
            raise RuntimeError("kaboom")
        return Observation(values=dict(step.get("values", {"n": 1})),
                           calls=[Call("GET", f"fake://{check.id}", via=via, status=200)],
                           error=step.get("error"), unknown=step.get("unknown"),
                           evidence=step.get("evidence", "evidence text"))


@pytest.fixture(autouse=True)
def _reset():
    SCRIPT.clear()
    CALLS.clear()
    yield
    assert KINDS["fake-test"] is FakeKind


def write_catalogue(root: Path, checks: str) -> catmod.Catalogue:
    (root / "targets").mkdir(parents=True)
    (root / "owners.yaml").write_text(
        "admins: [alice]\nfallback: [alice]\npeople:\n  alice: {name: Alice}\n")
    (root / "targets" / "svc.yaml").write_text(textwrap.dedent("""\
        id: svc
        name: Svc
        class: service
        owners: [alice]
        public_summary: x
        checks:
        """) + textwrap.indent(textwrap.dedent(checks), "  "))
    return catmod.load(root)


CHECKS = """\
- id: svc-a
  kind: fake-test
  via: [public, tgx1]
  assert: [{that: n, eq: 1}]
- id: svc-b
  kind: fake-test
  assert: [{that: n, gte: 5}]
- id: svc-off
  kind: fake-test
  enabled: false
  assert: [{that: n, eq: 1}]
"""


@pytest.fixture
def setup(tmp_path):
    cat = write_catalogue(tmp_path / "cat", CHECKS)
    store = Store(tmp_path / "m.db")
    http = Http(mode="replay", fixture_dir=tmp_path / "fx")
    ctx = Context(http=http, catalogue=cat, store=store)
    yield ctx, cat, store
    store.close()


# ---------------------------------------------------------------- run_all_once
async def test_run_all_once_runs_every_enabled_probe(setup):
    ctx, cat, store = setup
    seen = []
    res = await run_all_once(ctx, cat, on_result=lambda *a: seen.append(a[0]))
    by = {pid: r for pid, _, r in res}
    assert set(by) == {"svc-a@public", "svc-a@tgx1", "svc-b"}
    assert by["svc-a@tgx1"].status == "ok" and by["svc-b"].status == "failed"
    assert sorted(CALLS) == [("svc-a", "public"), ("svc-a", "tgx1"), ("svc-b", "public")]
    assert sorted(seen) == sorted(by)
    rows = store.query("SELECT probe_id, status, config_sha FROM results ORDER BY probe_id")
    assert [r["probe_id"] for r in rows] == ["svc-a@public", "svc-a@tgx1", "svc-b"]
    assert {r["config_sha"] for r in rows} == {cat.sha}
    # metrics for baselines: the asserted path plus latency
    assert {r["path"] for r in store.query("SELECT DISTINCT path FROM metrics")} == {
        "n", "latency_ms"}


@pytest.mark.parametrize(("only", "expected"), [
    (["svc-b"], {"svc-b"}),                              # check id
    (["svc-a@tgx1"], {"svc-a@tgx1"}),                   # probe id
    (["svc"], {"svc-a@public", "svc-a@tgx1", "svc-b"}),  # target id
    (["nothing"], set()),
])
async def test_run_all_once_only(setup, only, expected):
    ctx, cat, _ = setup
    res = await run_all_once(ctx, cat, only=only)
    assert {pid for pid, _, _ in res} == expected


async def test_async_on_result_is_awaited(setup):
    ctx, cat, _ = setup
    got = []

    async def on_result(pid, via, target, check, result, rid):
        await asyncio.sleep(0)
        got.append((pid, via, target.id, check.id, result.status, rid > 0))

    await run_all_once(ctx, cat, only=["svc-b"], on_result=on_result)
    assert got == [("svc-b", "public", "svc", "svc-b", "failed", True)]


async def test_without_store_nothing_is_saved(setup):
    ctx, cat, store = setup
    ctx.store = None
    res = await run_all_once(ctx, cat, only=["svc-b"])
    assert res[0][2].status == "failed"
    assert store.query("SELECT * FROM results") == []


# ---------------------------------------------------------------- the kind boundary
async def test_crash_error_unknown_become_results(setup):
    ctx, cat, _ = setup
    target, check = cat.checks["svc-a"]
    SCRIPT["svc-a"] = [{"crash": True}]
    r = await run_probe(target, check, "svc-a", "public", ctx)
    assert r.status == "unknown" and "kaboom" in r.summary and "RuntimeError" in r.evidence
    SCRIPT["svc-a"] = [{"error": "connection refused"}]
    r = await run_probe(target, check, "svc-a", "public", ctx)
    assert r.status == "failed" and r.summary == "no answer: connection refused"
    assert r.evidence == "evidence text" and r.outcomes == []
    SCRIPT["svc-a"] = [{"unknown": "rate limited (HTTP 429)"}]
    r = await run_probe(target, check, "svc-a", "public", ctx)
    assert r.status == "unknown" and r.evidence == "evidence text"


async def test_ok_result_drops_evidence_and_failing_summary_names_assertion(setup):
    ctx, cat, _ = setup
    r = await run_probe(*cat.checks["svc-a"], "svc-a", "public", ctx)
    assert r.status == "ok" and r.evidence == "" and r.summary == "1 assertions held"
    r = await run_probe(*cat.checks["svc-b"], "svc-b", "public", ctx)
    assert r.summary == "n ≥ 5: found 1"


async def test_unknown_kind_is_unknown(setup):
    ctx, cat, _ = setup
    target, check = cat.checks["svc-a"]
    r = await run_probe(target, check.model_copy(update={"kind": "nope"}), "x", "public", ctx)
    assert r.status == "unknown" and "no kind 'nope'" in r.summary


async def test_baseline_comes_from_the_store_for_this_probe(tmp_path):
    cat = write_catalogue(tmp_path / "cat", """\
        - id: svc-drop
          kind: fake-test
          assert: [{that: n, max_drop_pct: 10, window: 7d}]
        """)
    store = Store(tmp_path / "m.db")
    clock = iter(NOW + dt.timedelta(hours=h) for h in range(100))
    ctx = Context(http=Http(mode="replay", fixture_dir=tmp_path), catalogue=cat, store=store,
                  now=lambda: next(clock))
    SCRIPT["svc-drop"] = [{"values": {"n": 100}}] * 3 + [{"values": {"n": 50}}] * 2
    statuses = [(await run_all_once(ctx, cat))[0][2] for _ in range(4)]
    assert [r.status for r in statuses] == ["ok", "ok", "ok", "failed"]
    assert "median 100" in statuses[-1].outcomes[0].expected
    store.close()


# ---------------------------------------------------------------- the retry path
SPARSE = """\
- id: svc-daily
  kind: fake-test
  every: 1d
  retry: 10m
  assert: [{that: n, eq: 1}]
"""


async def test_failed_sparse_check_schedules_one_retry(tmp_path):
    cat = write_catalogue(tmp_path / "cat", SPARSE)
    sched = Scheduler(ctx=Context(http=Http(mode="replay", fixture_dir=tmp_path),
                                  catalogue=cat), catalogue=cat)
    sched.load()
    sched._sem = asyncio.Semaphore(1)
    slot = sched.slots["svc-daily"]
    loop = asyncio.get_running_loop()

    SCRIPT["svc-daily"] = [{"values": {"n": 0}}]
    slot.running = True
    await sched._guarded(slot)
    assert slot.retry_pending and not slot.running
    assert 590 < slot.next_due - loop.time() <= 600

    # The retry fails too: no second retry, the failure now counts.
    slot.running = True
    await sched._guarded(slot)
    assert not slot.retry_pending

    # A pass clears the retry state.
    SCRIPT["svc-daily"] = [{"values": {"n": 1}}]
    slot.retry_pending = True
    await sched._guarded(slot)
    assert not slot.retry_pending


async def test_crash_outside_kind_boundary_does_not_kill_the_loop(tmp_path, monkeypatch):
    cat = write_catalogue(tmp_path / "cat", SPARSE)
    sched = Scheduler(ctx=Context(http=Http(mode="replay", fixture_dir=tmp_path),
                                  catalogue=cat), catalogue=cat,
                      on_result=lambda *a: 1 / 0)
    sched.load()
    sched._sem = asyncio.Semaphore(1)
    slot = sched.slots["svc-daily"]
    slot.running = True
    await sched._guarded(slot)  # ZeroDivisionError logged, not raised
    assert not slot.running


async def test_retry_then_back_to_regular_cadence(tmp_path):
    cat = write_catalogue(tmp_path / "cat", SPARSE.replace("retry: 10m", "retry: 1s"))
    sched = Scheduler(ctx=Context(http=Http(mode="replay", fixture_dir=tmp_path),
                                  catalogue=cat), catalogue=cat)
    sched.load()
    sched.slots["svc-daily"].next_due = 0.0  # due now; load() keeps it
    SCRIPT["svc-daily"] = [{"values": {"n": 0}}]
    task = asyncio.create_task(sched.run_forever())
    await asyncio.sleep(3.6)
    sched.stop()
    await task
    assert len(CALLS) == 2  # the run and its one retry; next run a day later


async def test_load_keeps_due_times_and_jitters_new_probes(setup):
    ctx, cat, _ = setup
    sched = Scheduler(ctx=ctx, catalogue=cat)
    sched.load()
    sched.slots["svc-b"].next_due = 123.0
    sched.load(cat)
    assert sched.slots["svc-b"].next_due == 123.0
    assert set(sched.slots) == {"svc-a@public", "svc-a@tgx1", "svc-b"}
    assert isinstance(sched.slots["svc-b"], ProbeSlot)
    assert sched.status()["probes"] == 3


def test_jitter_is_deterministic_and_bounded():
    assert _jitter("a", 900) == _jitter("a", 900)
    assert 0 <= _jitter("probe-x", 86400) < 300
    assert 0 <= _jitter("probe-x", 60) < 60
