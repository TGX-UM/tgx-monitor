"""The alert engine: probe results in, incidents and outbox rows out.

Two layers, kept apart on purpose.

**Probe health** (``probe_state.state``) is a per-probe state machine fed only by
results: ``UNKNOWN -> OK <-> PENDING -> FAILING -> OK`` plus ``FLAPPING``. Checks every
15 min or faster need 3 failed results in a row, sparser ones 1 (the scheduler has
already retried once); ``alert_after`` adds a minimum failing time; recovery takes 2
passes; ``unknown`` moves nothing. :func:`step` is pure so the rules are unit-tested
without a database.

**Suppression** (BLOCKED, MAINTENANCE, SILENCED, KNOWN_ISSUE) is *not* stored: it depends
on the clock (a window ends, a silence expires, an ancestor recovers) and a stored copy
would go stale. :meth:`AlertEngine.view` computes it for the UI.

Incidents are derived, not accumulated: :meth:`AlertEngine._evaluate` recomputes the set
of root failing targets from probe health + catalogue + silences + windows and diffs it
against the open incidents. Running it twice changes nothing, which is what makes a
restart (a new engine on the same database) safe. Every notification it decides on is
written to the outbox inside the same transaction as the incident change.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import sqlite3
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from ..assertions import parse_duration
from ..catalogue import Catalogue, Check, Target
from ..model import Result, iso, utcnow
from ..store import Store
from . import digests, outbox, router, testing, windows

log = logging.getLogger("tgx_monitor.alerts")

HOLD = dt.timedelta(minutes=2)  # let a parent incident open before a child's is sent
REMIND = dt.timedelta(hours=24)
ESCALATE = dt.timedelta(hours=2)
REOPEN = dt.timedelta(hours=24)  # a flap within this reuses the previous issue
WATCHDOG = dt.timedelta(minutes=5)
FLAP_WINDOW = dt.timedelta(hours=2)
FLAP_ENTER, FLAP_LEAVE = 6, 2  # > 6 changes in 2 h starts flapping, <= 2 ends it
RECOVER_OKS = 2
VANTAGE_SHARE, VANTAGE_SPAN, VANTAGE_MIN = 0.4, dt.timedelta(minutes=5), 5
VANTAGE_CONFIRM = dt.timedelta(minutes=10)  # degraded this long before anyone is paged
VANTAGE_CLEAR = dt.timedelta(minutes=5)  # and clear this long before it closes
VANTAGE_KINDS = {"self", "vantage"}


def is_vantage(c: Check) -> bool:
    """Only the self check that measures reachability of the outside world counts as the
    vantage. A failing token-expiry, dead-letter or selftest check must not convince the
    engine that the monitor is cut off (which would silence every other page)."""
    if c.kind == "vantage":
        return True
    return c.kind == "self" and str(c.request.get("signal", "")) == "vantage"
VANTAGE_TARGET = "monitor-vantage-degraded"
HEALTH_BAD = ("FAILING", "FLAPPING")


def _ts(s: str | None) -> dt.datetime | None:
    return dt.datetime.fromisoformat(s) if s else None


def _utc(ts: dt.datetime) -> dt.datetime:
    """Aware UTC. Timestamps are compared as ISO strings in SQL, so a +01:00 offset
    from an agent or a CLI user would sort wrongly against the UTC ones."""
    return (ts if ts.tzinfo else ts.replace(tzinfo=dt.UTC)).astimezone(dt.UTC)


def is_test(inc: dict[str, Any]) -> bool:
    """Synthetic test incidents, recognised by target and not by key prefix: a real
    target may well be called ``test-something``."""
    return inc["target_id"] == testing.TEST_TARGET


# ---------------------------------------------------------------------- probe health
def failures_needed(check: Check) -> int:
    """Frequent checks need 3 failures in a row. A sparse check with a ``retry`` needs
    the retry to fail too (else it would page before the retry has run); without one,
    a single failure counts."""
    if check.interval_s <= 900:
        return 3
    return 2 if check.retry else 1


def blank(probe_id: str) -> dict[str, Any]:
    return {"probe_id": probe_id, "check_id": None, "target_id": None, "via": None,
            "state": "UNKNOWN", "since": None, "consecutive_fail": 0, "consecutive_ok": 0,
            "last_status": None, "last_result_id": None, "last_run_at": None,
            "last_ok_at": None, "first_fail_at": None, "transitions": "[]", "warn": 0,
            "unknown_since": None}


def blind_limit(check: Check) -> dt.timedelta:
    """How long a probe may answer only 'unknown' (429s, client timeouts, a missing
    credential) before that itself counts as failing. Without it a target that hangs
    past the timeout or rate-limits us for ever would never page."""
    return max(dt.timedelta(hours=6), dt.timedelta(seconds=3 * check.interval_s))


def _confirmed(r: dict[str, Any], check: Check, ts: dt.datetime) -> bool:
    if r["consecutive_fail"] < failures_needed(check):
        return False
    first = _ts(r["first_fail_at"]) or ts
    return not check.alert_after or ts - first >= dt.timedelta(
        seconds=parse_duration(check.alert_after))


def _settled(r: dict[str, Any], check: Check, ts: dt.datetime) -> str:
    """Where a probe lands when it stops flapping."""
    if r["consecutive_fail"]:
        return "FAILING" if _confirmed(r, check, ts) else "PENDING"
    return "OK" if r["consecutive_ok"] else "UNKNOWN"


def _flips(r: dict[str, Any], ts: dt.datetime) -> list[str]:
    return [t for t in json.loads(r["transitions"] or "[]") if _ts(t) > ts - FLAP_WINDOW]


def step(row: dict[str, Any], status: str, ts: dt.datetime, check: Check) -> dict[str, Any]:
    """Advance one probe by one result. Pure: returns the new row."""
    r = dict(row)
    r["last_run_at"] = iso(ts)
    if status == "unknown":
        r["unknown_since"] = r.get("unknown_since") or iso(ts)
        r["last_status"] = "unknown"
        if ts - (_ts(r["unknown_since"]) or ts) < blind_limit(check):
            return r  # neither fails nor recovers, for now
        status = "failed"  # blind for too long: from here on, unknown counts as failing
    elif status != "ok" and status != "failed":  # skipped / blocked
        return r
    else:
        r["unknown_since"] = None
    prev = "ok" if r["consecutive_ok"] else "failed" if r["consecutive_fail"] else None
    flips = _flips(r, ts) + ([iso(ts)] if prev and prev != status else [])
    r["transitions"] = json.dumps(flips)
    r["last_status"] = status
    state = r["state"]
    if status == "ok":
        r["consecutive_ok"] += 1
        r["consecutive_fail"] = 0
        r["last_ok_at"] = iso(ts)
        new = "OK" if state in ("UNKNOWN", "PENDING", "OK") or (
            state == "FAILING" and r["consecutive_ok"] >= RECOVER_OKS) else state
    else:
        r["consecutive_fail"] += 1
        r["consecutive_ok"] = 0
        r["first_fail_at"] = r["first_fail_at"] or iso(ts)
        new = state if state in HEALTH_BAD else (
            "FAILING" if _confirmed(r, check, ts) else "PENDING")
    if state == "FLAPPING":
        new = _settled(r, check, ts) if len(flips) <= FLAP_LEAVE else "FLAPPING"
    elif len(flips) > FLAP_ENTER:
        new = "FLAPPING"
    if new == "OK":
        r["first_fail_at"] = None
    if new != state:
        r["state"], r["since"] = new, iso(ts)
    return r


# ---------------------------------------------------------------------- engine
class AlertEngine:
    def __init__(self, store: Store, catalogue: Catalogue, *,
                 now: Callable[[], dt.datetime] = utcnow, dry_run: bool = True,
                 private_base_url: str = "", public_base_url: str = "") -> None:
        self.store = store
        self.catalogue = catalogue
        self.now = now
        self.dry_run = dry_run
        self.private_url = private_base_url
        self.public_url = public_base_url
        self.degraded = False

    def reload(self, catalogue: Catalogue) -> bool:
        """Swap in a new catalogue, unless it failed to load. A YAML error in a target
        file drops that target; accepting it would close (and announce as recovered)
        every incident of the dropped targets. False: the old catalogue stays."""
        if catalogue.problems:
            log.error("catalogue reload rejected, keeping the previous one: %s",
                      "; ".join(catalogue.problems[:5]))
            return False
        self.catalogue = catalogue
        return True

    # ------------------------------------------------------------------ inputs
    def ingest(self, probe_id: str, via: str, target: Target, check: Check, result: Result,
               result_id: int = 0) -> None:
        """Feed one result. Cheap unless the probe's health changes."""
        now = self.now()
        # A clock ahead of ours (an agent) is clamped to now; a result older than the
        # probe's last one (an agent flushing a backlog) is history, not news.
        ts = min(_utc(result.started_at or now), now)
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM probe_state WHERE probe_id=?", (probe_id,)).fetchone()
            old = dict(row) if row else blank(probe_id)
            last = _ts(old["last_run_at"])
            if last is not None and ts < last <= now:
                log.info("result for %s at %s is older than the last one; ignored",
                         probe_id, iso(ts))
                return
            new = step(old, result.status, ts, check)
            new.update(check_id=check.id, target_id=target.id, via=via, warn=int(result.warn),
                       last_result_id=result_id or old["last_result_id"])
            _save(db, new)
            if new["state"] == old["state"]:
                return
            self._evaluate(db, now)
            if (new["state"] == "FLAPPING" and not self.degraded
                    and not self._blocked(db, target.id)):
                self._flapping_notice(db, target, check, now)

    def tick(self) -> None:
        """Once a minute: windows closing, silences expiring, holds, reminders, escalation,
        flapping that has calmed down, test incidents, digests, the delivery watchdog."""
        now = self.now()
        with self.store.transaction() as db:
            self._recheck_probes(db, now)
            self._evaluate(db, now)
            self._reminders(db, now)
            testing.close_due_tests(db, now, self.private_url)
            digests.enqueue_due(db, self, now)
            self._watchdog(db, now)

    def evaluate_now(self) -> None:
        with self.store.transaction() as db:
            self._evaluate(db, self.now())

    # ------------------------------------------------------------------ suppression
    def _silences(self, db: sqlite3.Connection, now: dt.datetime) -> list[dict[str, Any]]:
        return [dict(r) for r in db.execute("SELECT * FROM silences WHERE until>?", (iso(now),))]

    def ancestors(self, tid: str) -> list[str]:
        """Ancestors that can block ``tid``: those it is in a cycle with (a cycle that
        slipped past ``validate``) are left out, or every member of the cycle would be
        blocked by another and nobody would ever be told."""
        cat = self.catalogue
        return [a for a in cat.ancestors(tid) if a != tid and tid not in cat.ancestors(a)]

    def _in_window(self, target: Target, now: dt.datetime) -> bool:
        for wid in target.maintenance:
            w = self.catalogue.windows.get(wid)
            try:
                if w and windows.active(w, now):
                    return True
            except ValueError:
                log.warning("window %s is invalid; ignored", wid)
        return False

    def _blocked(self, db: sqlite3.Connection, tid: str) -> bool:
        """Is an ancestor failing (incident open, or a probe failing)?"""
        anc = self.ancestors(tid)
        if not anc:
            return False
        marks = ",".join("?" * len(anc))
        return db.execute(
            f"SELECT 1 FROM incidents WHERE closed_at IS NULL AND target_id IN ({marks}) "
            f"UNION SELECT 1 FROM probe_state WHERE state IN ('FAILING','FLAPPING') AND "
            f"target_id IN ({marks}) LIMIT 1", anc + anc).fetchone() is not None

    def suppression(self, target: Target, check: Check | None, now: dt.datetime,
                    silences: list[dict[str, Any]]) -> str | None:
        """MAINTENANCE | SILENCED | KNOWN_ISSUE | None, for one target or check.

        A window on an ancestor covers its descendants too: a reload upstream breaks
        the consumers downstream, often before the upstream's own check notices."""
        cat = self.catalogue
        if self._in_window(target, now) or any(
                self._in_window(cat.targets[a], now)
                for a in cat.ancestors(target.id) if a in cat.targets):
            return "MAINTENANCE"
        for s in silences:
            if s["target_id"] == target.id and (not s["check_id"] or (
                    check is not None and s["check_id"] == check.id)):
                return "SILENCED"
        for k in self.catalogue.known:
            if k.target == target.id and (k.check is None or (check and k.check == check.id)):
                try:
                    if now.date() <= dt.date.fromisoformat(k.until):
                        return "KNOWN_ISSUE"
                except ValueError:
                    continue
        return None

    # ------------------------------------------------------------------ the core
    def _evaluate(self, db: sqlite3.Connection, now: dt.datetime) -> None:
        cat = self.catalogue
        states = {r["probe_id"]: dict(r) for r in db.execute("SELECT * FROM probe_state")}
        probes = {pid: (t, c) for pid, _v, t, c in cat.probes()}
        open_inc = {r["target_id"]: dict(r) for r in
                    db.execute("SELECT * FROM incidents WHERE closed_at IS NULL")}
        special = {tid for tid, r in open_inc.items() if tid == VANTAGE_TARGET or is_test(r)}
        self.degraded = self._vantage(db, states, probes, open_inc, now)
        if self.degraded:
            self._announce_due(db, now, open_inc, states, probes)
            return
        sil = self._silences(db, now)
        failing: dict[str, list[str]] = defaultdict(list)
        unhealthy: set[str] = set()  # failing at all, suppressed or not: blocks descendants
        for pid, (t, c) in probes.items():
            st = states.get(pid)
            if not st or st["state"] != "FAILING" or router.severity_of(t, c) is None:
                continue
            unhealthy.add(t.id)
            if not self.suppression(t, c, now, sil):
                failing[t.id].append(pid)
        blocking = unhealthy | (set(open_inc) - special)
        blocked_by = {tid: [a for a in self.ancestors(tid) if a in blocking] for tid in blocking}
        blocked_by = {k: v for k, v in blocked_by.items() if v}
        affected: dict[str, list[str]] = defaultdict(list)
        for tid, anc in blocked_by.items():
            for a in anc:
                if a not in blocked_by:
                    affected[a].append(tid)
        roots = [tid for tid in failing if tid not in blocked_by]
        for tid in sorted(roots):
            self._upsert(db, tid, failing[tid], sorted(affected[tid]), open_inc.get(tid),
                         states, probes, now)
        for tid, inc in open_inc.items():
            if tid in roots or tid in special:
                continue
            still = sorted({p for p in json.loads(inc["failing"]) if p in probes
                            and (states.get(p) or {}).get("state", "UNKNOWN") != "OK"}
                           | set(failing.get(tid, [])))
            if not still or not inc["last_notified_at"]:
                # Recovered, or suppressed/blocked before anyone was told: close. Only
                # an announced incident announces its end. Checks that left the
                # catalogue did not recover: say so instead of "recovered".
                before = json.loads(inc["failing"])
                retired = tid not in cat.targets or (
                    bool(before) and all(p not in probes for p in before))
                self._close(db, inc, now, notify=not still and bool(inc["last_notified_at"]),
                            states=states, probes=probes,
                            event="retired" if retired else "close")
            else:
                db.execute("UPDATE incidents SET failing=?, blocked=? WHERE id=?",
                           (json.dumps(still), json.dumps(sorted(affected[tid])), inc["id"]))
        open_inc = {r["target_id"]: dict(r) for r in
                    db.execute("SELECT * FROM incidents WHERE closed_at IS NULL")}
        self._announce_due(db, now, open_inc, states, probes)

    def _upsert(self, db: sqlite3.Connection, tid: str, pids: list[str], affected: list[str],
                inc: dict[str, Any] | None, states: dict[str, Any], probes: dict[str, Any],
                now: dt.datetime) -> None:
        t = self.catalogue.targets[tid]
        if inc is not None:
            old = set(json.loads(inc["failing"]))
            old_sev = inc["severity"]
            members = sorted(old | set(pids))
            members = [p for p in members if p in probes and
                       (states.get(p) or {}).get("state", "UNKNOWN") != "OK"]
            sevs = [router.severity_of(*probes[p]) for p in members]
            sev = router.worst_severity([s for s in sevs if s] + [old_sev])
            private = router.is_private(t, [probes[p][1] for p in members])
            db.execute("UPDATE incidents SET failing=?, blocked=?, severity=?, private=? "
                       "WHERE id=?", (json.dumps(members), json.dumps(affected), sev,
                                      int(private), inc["id"]))
            inc.update(failing=json.dumps(members), blocked=json.dumps(affected),
                       severity=sev, private=int(private))
            if not inc["last_notified_at"]:
                return
            opened_issue = False
            if router.RANK[sev] > router.RANK[old_sev]:
                # A critical check joined a warning incident: the e-mail and Slack
                # page that a critical open gets must not be lost. The issue exists
                # already unless the incident was info until now.
                skip = {"github"} if old_sev != "info" else set()
                self._notify(db, inc, "open", now, states, probes, skip=skip)
                opened_issue = not skip
            if set(members) - old and not opened_issue:
                self._notify(db, inc, "update", now, states, probes)
            return
        checks = [probes[p][1] for p in pids]
        sev = router.worst_severity([router.severity_of(t, c) for c in checks])
        private = router.is_private(t, checks)
        prev = db.execute("SELECT key, issue_number FROM incidents WHERE target_id=? AND "
                          "closed_at>=? ORDER BY closed_at DESC LIMIT 1",
                          (tid, iso(now - REOPEN))).fetchone()
        key = prev["key"] if prev else f"{tid}-{now:%Y%m%d%H%M}"
        issue = prev["issue_number"] if prev and not private else None
        db.execute("INSERT INTO incidents(key,target_id,severity,title,opened_at,failing,"
                   "blocked,issue_number,private) VALUES(?,?,?,?,?,?,?,?,?)",
                   (key, tid, sev, f"{t.name} failing", iso(now), json.dumps(sorted(pids)),
                    json.dumps(affected), issue, int(private)))

    def _due_at(self, inc: dict[str, Any], states: dict[str, Any],
                probes: dict[str, Any]) -> dt.datetime:
        """When an unannounced incident may be announced.

        Normally after the hold. At once when its probes had been failing for longer
        than the hold before the incident could open: a window closed, a silence or a
        known issue expired. One check cycle of grace when an ancestor probe recovered
        in the last 15 minutes, so children that recover with it never page."""
        opened = _ts(inc["opened_at"])
        assert opened is not None
        if inc["target_id"] == VANTAGE_TARGET:
            return opened + VANTAGE_CONFIRM  # one blip of a busy network is not an outage
        members = [p for p in json.loads(inc["failing"]) if p in probes]
        anc = set(self.ancestors(inc["target_id"]))
        # An ancestor already failing but not yet confirmed (its third failure lands a
        # few minutes after ours, by jitter): wait one of its cycles for it to take over.
        pending = [probes[pid][1].interval_s for pid, st in states.items()
                   if pid in probes and st["target_id"] in anc and st["state"] == "PENDING"]
        if pending:
            return opened + max(HOLD, dt.timedelta(seconds=min(max(pending), 900) + 60))
        recent = iso(opened - dt.timedelta(minutes=15))
        if any(st["target_id"] in anc and st["state"] == "OK"
               and max(json.loads(st["transitions"] or "[]"), default="") >= recent
               for st in states.values()):  # an ancestor probe flipped back to ok lately
            cycle = min((probes[p][1].interval_s for p in members), default=0.0)
            return opened + max(HOLD, dt.timedelta(seconds=min(cycle, 900) + 60))
        sinces = [_ts((states.get(p) or {}).get("since")) for p in members]
        if sinces and all(s and s <= opened - HOLD for s in sinces):
            return opened
        return opened + HOLD

    def _announce_due(self, db: sqlite3.Connection, now: dt.datetime,
                      open_inc: dict[str, dict[str, Any]], states: dict[str, Any],
                      probes: dict[str, Any]) -> None:
        for tid, inc in open_inc.items():
            if inc["last_notified_at"] or is_test(inc):
                continue
            if self.degraded and tid != VANTAGE_TARGET:
                continue  # the vantage incident speaks for everything
            if now < self._due_at(inc, states, probes):
                continue
            members = [states.get(p) or {} for p in json.loads(inc["failing"])]
            if members and all(m.get("last_status") == "ok" for m in members):
                continue  # already passing again: page only if it fails once more
            if self._notify(db, inc, "open", now, states, probes):
                db.execute("UPDATE incidents SET last_notified_at=? WHERE id=?",
                           (iso(now), inc["id"]))

    def _close(self, db: sqlite3.Connection, inc: dict[str, Any], now: dt.datetime, *,
               notify: bool, states: dict[str, Any], probes: dict[str, Any],
               event: str = "close") -> None:
        db.execute("UPDATE incidents SET closed_at=? WHERE id=?", (iso(now), inc["id"]))
        if notify:
            self._notify(db, inc, event, now, states, probes)

    # ------------------------------------------------------------------ vantage rule
    def _vantage(self, db: sqlite3.Connection, states: dict[str, Any], probes: dict[str, Any],
                 open_inc: dict[str, dict[str, Any]], now: dt.datetime) -> bool:
        """If the monitor itself is cut off, say that once instead of 50 times."""
        recent = iso(now - VANTAGE_SPAN)
        seen: set[str] = set()
        bad: set[str] = set()
        vantage_bad, vantage_seen = False, False
        for pid, (t, c) in probes.items():
            st = states.get(pid) or {}
            fresh = (st.get("last_run_at") or "") >= recent
            if c.kind in VANTAGE_KINDS and not is_vantage(c):
                continue  # other self checks: neither vantage nor an estate target
            if is_vantage(c):
                vantage_seen |= (st.get("last_run_at") or "") >= iso(now - 3 * VANTAGE_SPAN)
                vantage_bad |= st.get("last_status") == "failed"
                continue
            if not fresh or router.severity_of(t, c) is None:
                continue
            seen.add(t.id)
            if st.get("last_status") == "failed":
                bad.add(t.id)
        degraded = ((vantage_bad or not vantage_seen) and len(seen) >= VANTAGE_MIN
                    and len(bad) > VANTAGE_SHARE * len(seen))
        inc = open_inc.get(VANTAGE_TARGET)
        if degraded:
            self.store.set_meta("vantage_ok_since", "")
            if inc is None:
                # Flapping vantage: reuse the last incident's key and issue (reopen it)
                # instead of opening a new issue for every bout.
                prev = db.execute("SELECT key, issue_number FROM incidents WHERE target_id=? "
                                  "AND closed_at>=? ORDER BY closed_at DESC LIMIT 1",
                                  (VANTAGE_TARGET, iso(now - REOPEN))).fetchone()
                db.execute("INSERT INTO incidents(key,target_id,severity,title,opened_at,failing,"
                           "issue_number) VALUES(?,?,?,?,?,?,?)",
                           (prev["key"] if prev else f"{VANTAGE_TARGET}-{now:%Y%m%d%H%M}",
                            VANTAGE_TARGET, "critical", "Monitor vantage degraded", iso(now),
                            json.dumps(sorted(bad)), prev["issue_number"] if prev else None))
                open_inc[VANTAGE_TARGET] = dict(db.execute(
                    "SELECT * FROM incidents WHERE closed_at IS NULL AND target_id=?",
                    (VANTAGE_TARGET,)).fetchone())
            return True
        if inc is None:
            return False
        if inc["last_notified_at"]:
            # Announced: stay degraded (individual alerts held) until every probe has had
            # a cycle to report from the restored vantage, or the stragglers that have
            # not re-run yet would each page the moment the share drops below 40%.
            ok_since = _ts(self.store.get_meta("vantage_ok_since") or None)
            if ok_since is None or ok_since > now:
                self.store.set_meta("vantage_ok_since", iso(now))
                return True
            if now - ok_since < VANTAGE_CLEAR:
                return True
        self.store.set_meta("vantage_ok_since", "")
        self._close(db, inc, now, notify=bool(inc["last_notified_at"]), states=states,
                    probes=probes)
        open_inc.pop(VANTAGE_TARGET, None)
        return False

    # ------------------------------------------------------------------ periodic
    def _recheck_probes(self, db: sqlite3.Connection, now: dt.datetime) -> None:
        """Time-driven health changes: flapping that calmed down, alert_after elapsed."""
        checks = self.catalogue.checks
        for r in db.execute("SELECT * FROM probe_state WHERE state IN ('FLAPPING','PENDING')"):
            row = dict(r)
            tc = checks.get(row["check_id"] or "")
            if tc is None:
                continue
            if row["state"] == "FLAPPING" and len(_flips(row, now)) <= FLAP_LEAVE:
                new = _settled(row, tc[1], now)
            elif row["state"] == "PENDING" and _confirmed(row, tc[1], now):
                new = "FAILING"
            else:
                continue
            row.update(state=new, since=iso(now), transitions=json.dumps(_flips(row, now)))
            _save(db, row)

    def _quiet(self, db: sqlite3.Connection, inc: dict[str, Any], now: dt.datetime,
               open_targets: set[str], probes: dict[str, Any]) -> bool:
        """Should reminders and escalation hold off? Behind a failing ancestor, in a
        window, silenced or a known issue: for the target, or for every check failing
        in it (a check-level silence covers the incident it is the cause of)."""
        if self.degraded and inc["target_id"] != VANTAGE_TARGET:
            return True  # the vantage incident speaks for everything
        t = self.catalogue.targets.get(inc["target_id"])
        if t is None:
            return False
        if any(a in open_targets for a in self.ancestors(t.id)):
            return True
        sil = self._silences(db, now)
        if self.suppression(t, None, now, sil) is not None:
            return True
        members = [p for p in json.loads(inc["failing"]) if p in probes]
        return bool(members) and all(self.suppression(t, probes[p][1], now, sil)
                                     for p in members)

    def _reminders(self, db: sqlite3.Connection, now: dt.datetime) -> None:
        rows = [dict(r) for r in db.execute(
            "SELECT * FROM incidents WHERE closed_at IS NULL AND last_notified_at IS NOT NULL "
            "AND severity='critical' AND target_id<>?", (testing.TEST_TARGET,))]
        open_targets = {r["target_id"] for r in db.execute(
            "SELECT target_id FROM incidents WHERE closed_at IS NULL")}
        states = {r["probe_id"]: dict(r) for r in db.execute("SELECT * FROM probe_state")}
        probes = {pid: (t, c) for pid, _v, t, c in self.catalogue.probes()}
        for inc in rows:
            if self._quiet(db, inc, now, open_targets - {inc["target_id"]}, probes):
                continue
            if (_ts(inc["last_notified_at"]) <= now - REMIND
                    and self._notify(db, inc, "reminder", now, states, probes)):
                db.execute("UPDATE incidents SET last_notified_at=? WHERE id=?",
                           (iso(now), inc["id"]))
            if (not inc["acked_at"] and not inc["escalated_at"]
                    and _ts(inc["opened_at"]) <= now - ESCALATE
                    and self._notify(db, inc, "escalate", now, states, probes)):
                db.execute("UPDATE incidents SET escalated_at=? WHERE id=?",
                           (iso(now), inc["id"]))

    def _watchdog(self, db: sqlite3.Connection, now: dt.datetime) -> None:
        """Always-firing heartbeat through the real outbox (always live: a dead-man ping
        is not a notification, and shadow mode is exactly when it must keep working)."""
        last = _ts(self.store.get_meta("watchdog_at"))
        if last and dt.timedelta(0) <= now - last < WATCHDOG:
            return  # (a clock stepped back must not silence the dead-man ping)
        outbox.enqueue(db, channel="hc", event="watchdog", now=now,
                       payload={"check": "delivery-watchdog", "status": "success",
                                "line": "delivery watchdog"})
        self.store.set_meta("watchdog_at", iso(now))

    # ------------------------------------------------------------------ notifications
    def target_for(self, tid: str) -> Target:
        if tid in self.catalogue.targets:
            return self.catalogue.targets[tid]
        owners = self.catalogue.owners
        if tid == VANTAGE_TARGET:
            return Target.model_validate({
                "id": tid, "name": "Monitor vantage point", "class": "infra",
                "criticality": "high", "owners": list(owners.admins) if owners else [],
                "public_summary": "The monitor cannot reach a large share of the estate; "
                                  "individual alerts are held back until it can."})
        # A target that has left the catalogue: its owners are unknown (fallback).
        return Target.model_validate({"id": tid, "name": tid, "class": "service",
                                      "criticality": "high", "owners": []})

    def _private_target(self, tid: str) -> bool:
        t = self.catalogue.targets.get(tid)
        return t is None or t.class_ == "security" or not t.public

    def _notify(self, db: sqlite3.Connection, inc: dict[str, Any], event: str,
                now: dt.datetime, states: dict[str, Any], probes: dict[str, Any], *,
                skip: set[str] | frozenset[str] = frozenset()) -> bool:
        """Queue ``event`` for ``inc`` on its routes. False when it could not be routed
        (no owners.yaml), so the caller does not record it as told."""
        owners = self.catalogue.owners
        if owners is None:
            log.error("owners.yaml missing: cannot route %s for %s", event, inc["key"])
            return False
        t = self.target_for(inc["target_id"])
        private = bool(inc["private"])
        members = [p for p in json.loads(inc["failing"]) if p in probes]
        sinces = [_ts((states.get(p) or {}).get("first_fail_at")) for p in members]
        since = min([s for s in sinces if s] or [_ts(inc["opened_at"])])
        blocked_ids = json.loads(inc["blocked"] or "[]")
        routes = router.routes(event, inc["severity"], t, owners, private)
        if private and event in ("close", "retired") and self._has_issue(db, inc):
            # Went private after its public issue was opened: still close that issue
            # (the close comment carries no detail), or it stays open for ever.
            gh = router.routes(event, inc["severity"], t, owners, False).get("github")
            if gh is not None:
                routes["github"] = gh
        for channel, rcpt in routes.items():
            if channel in skip:
                continue
            # A public issue must not name a private (security) target held behind it.
            names = [self.catalogue.targets[b].name if b in self.catalogue.targets else b
                     for b in blocked_ids
                     if channel != "github" or not self._private_target(b)]
            ctx = {"key": inc["key"], "target": t, "checks": [(p, probes[p][1]) for p in members],
                   "severity": inc["severity"], "since": since, "now": now,
                   "opened_at": _ts(inc["opened_at"]), "issue_number": inc["issue_number"],
                   "blocked_names": names, "private": private,
                   "recipients": rcpt, "private_url": self.private_url,
                   "public_url": self.public_url}
            outbox.enqueue(db, channel=channel, event=event, now=now, recipients=rcpt,
                           incident_id=inc["id"], dry_run=self.dry_run,
                           payload=router.render(channel, event, ctx))
        return True

    @staticmethod
    def _has_issue(db: sqlite3.Connection, inc: dict[str, Any]) -> bool:
        if inc["issue_number"]:
            return True
        return db.execute("SELECT 1 FROM outbox WHERE incident_id=? AND channel='github' AND "
                          "event='open' AND dead=0 LIMIT 1", (inc["id"],)).fetchone() is not None

    def _flapping_notice(self, db: sqlite3.Connection, target: Target, check: Check,
                         now: dt.datetime) -> None:
        sev = router.severity_of(target, check)
        owners = self.catalogue.owners
        if sev is None or owners is None or self.suppression(target, check, now,
                                                             self._silences(db, now)):
            return
        private = router.is_private(target, [check])
        for channel, rcpt in router.routes("flapping", sev, target, owners, private).items():
            ctx = {"key": f"{target.id}-flap", "target": target, "checks": [(check.id, check)],
                   "severity": sev, "since": now, "now": now, "opened_at": now,
                   "issue_number": None, "blocked_names": [], "private": private,
                   "recipients": rcpt, "private_url": self.private_url,
                   "public_url": self.public_url}
            outbox.enqueue(db, channel=channel, event="flapping", now=now, recipients=rcpt,
                           dry_run=self.dry_run, payload=router.render(channel, "flapping", ctx))

    # ------------------------------------------------------------------ for the UI / CLI
    def view(self) -> dict[str, dict[str, Any]]:
        """probe_id -> {state, health, reason}: health plus the suppression overlay."""
        now = self.now()
        sil = list_silences(self.store, now)
        states = {r["probe_id"]: r for r in self.store.query("SELECT * FROM probe_state")}
        open_targets = {r["target_id"] for r in self.store.query(
            "SELECT target_id FROM incidents WHERE closed_at IS NULL")}
        out = {}
        for pid, _via, t, c in self.catalogue.probes():
            health = (states.get(pid) or {}).get("state", "UNKNOWN")
            reason = self.suppression(t, c, now, sil)
            blocked = [a for a in self.ancestors(t.id) if a in open_targets]
            if blocked and health != "OK":
                reason = reason or "BLOCKED"
            out[pid] = {"state": reason or health, "health": health,
                        "reason": f"ancestor {blocked[0]} has an open incident"
                        if reason == "BLOCKED" else (reason or "")}
        return out

    def ack(self, ref: str, who: str) -> bool:
        return ack_incident(self.store, ref, who, self.now())


def _save(db: sqlite3.Connection, row: dict[str, Any]) -> None:
    cols = list(blank("x"))
    db.execute(f"INSERT OR REPLACE INTO probe_state({','.join(cols)}) "
               f"VALUES({','.join('?' * len(cols))})", [row.get(c) for c in cols])


# ---------------------------------------------------------------------- silences
def add_silence(store: Store, target_id: str, reason: str, until: dt.datetime, who: str,
                check_id: str | None = None, now: dt.datetime | None = None) -> int:
    cur = store.execute("INSERT INTO silences(target_id,check_id,reason,created_by,created_at,"
                        "until) VALUES(?,?,?,?,?,?)",
                        (target_id, check_id, reason, who, iso(now or utcnow()),
                         iso(_utc(until))))
    store.audit(who, "silence", f"{target_id}/{check_id or '*'} until {iso(until)}: {reason}")
    return int(cur.lastrowid or 0)


def list_silences(store: Store, now: dt.datetime | None = None) -> list[dict[str, Any]]:
    return store.query("SELECT * FROM silences WHERE until>? ORDER BY until",
                       (iso(now or utcnow()),))


def ack_incident(store: Store, ref: str, who: str, now: dt.datetime | None = None) -> bool:
    """Acknowledge an open incident (by id or key): stops escalation, not reminders."""
    cur = store.execute("UPDATE incidents SET acked_by=?, acked_at=? WHERE closed_at IS NULL AND "
                        "(key=? OR CAST(id AS TEXT)=?)", (who, iso(now or utcnow()), ref, ref))
    if cur.rowcount:
        store.audit(who, "ack", ref)
    return bool(cur.rowcount)


def remove_silence(store: Store, silence_id: int, who: str) -> bool:
    cur = store.execute("DELETE FROM silences WHERE id=?", (silence_id,))
    if cur.rowcount:
        store.audit(who, "unsilence", str(silence_id))
    return bool(cur.rowcount)
