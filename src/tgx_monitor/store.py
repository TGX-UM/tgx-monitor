"""SQLite state, one writer.

The database lives on GlusterFS (``/mnt/gluster/docker/tgx-monitor/data``), a FUSE
filesystem. Two rules follow and are not negotiable:

* ``journal_mode=TRUNCATE``, never WAL. WAL needs a shared-memory file that network
  filesystems do not reliably support; the corruption it causes shows up weeks later.
* Exactly one process writes. The swarm service runs one replica with
  ``update_config.order: stop-first``; inside the process every statement goes through
  one connection guarded by one lock.

Retention keeps the file small (<500 MB): raw results 35 days, evidence 90 days, raw
metrics 35 days, hourly rollups 400 days, daily rollups and metric dailies forever.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .model import Result, iso, utcnow

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY,
  probe_id TEXT NOT NULL, check_id TEXT NOT NULL, target_id TEXT NOT NULL, via TEXT NOT NULL,
  status TEXT NOT NULL, warn INTEGER NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL, duration_ms REAL, summary TEXT,
  outcomes TEXT, calls TEXT, config_sha TEXT
);
CREATE INDEX IF NOT EXISTS results_probe_ts ON results(probe_id, started_at);
CREATE INDEX IF NOT EXISTS results_target_ts ON results(target_id, started_at);
CREATE INDEX IF NOT EXISTS results_ts ON results(started_at);

CREATE TABLE IF NOT EXISTS evidence (result_id INTEGER PRIMARY KEY, created_at TEXT, body TEXT);

CREATE TABLE IF NOT EXISTS metrics (
  probe_id TEXT NOT NULL, path TEXT NOT NULL, ts TEXT NOT NULL, value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS metrics_probe_path_ts ON metrics(probe_id, path, ts);

CREATE TABLE IF NOT EXISTS metric_daily (
  probe_id TEXT NOT NULL, path TEXT NOT NULL, day TEXT NOT NULL,
  last REAL, min REAL, max REAL, n INTEGER,
  PRIMARY KEY (probe_id, path, day)
);

CREATE TABLE IF NOT EXISTS probe_state (
  probe_id TEXT PRIMARY KEY, check_id TEXT, target_id TEXT, via TEXT,
  state TEXT NOT NULL DEFAULT 'UNKNOWN', since TEXT,
  consecutive_fail INTEGER NOT NULL DEFAULT 0, consecutive_ok INTEGER NOT NULL DEFAULT 0,
  last_status TEXT, last_result_id INTEGER, last_run_at TEXT, last_ok_at TEXT,
  first_fail_at TEXT, transitions TEXT NOT NULL DEFAULT '[]', warn INTEGER NOT NULL DEFAULT 0,
  unknown_since TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY,
  key TEXT NOT NULL,              -- stable marker, e.g. target id + open timestamp
  target_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT,
  opened_at TEXT NOT NULL, closed_at TEXT,
  failing TEXT NOT NULL DEFAULT '[]',   -- probe ids currently failing in this incident
  blocked TEXT NOT NULL DEFAULT '[]',   -- descendant targets suppressed by this incident
  issue_number INTEGER, acked_by TEXT, acked_at TEXT,
  last_notified_at TEXT, escalated_at TEXT, private INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_open ON incidents(closed_at, target_id);

CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY,
  created_at TEXT NOT NULL, channel TEXT NOT NULL, event TEXT NOT NULL,
  incident_id INTEGER, recipients TEXT NOT NULL DEFAULT '[]', payload TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL,
  sent_at TEXT, reply TEXT, dead INTEGER NOT NULL DEFAULT 0, dry_run INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(sent_at, dead, next_attempt_at);

CREATE TABLE IF NOT EXISTS silences (
  id INTEGER PRIMARY KEY, target_id TEXT NOT NULL, check_id TEXT,
  reason TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, until TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_runs (
  id INTEGER PRIMARY KEY, job TEXT NOT NULL, task_id TEXT,
  scheduled_at TEXT, started_at TEXT, finished_at TEXT, node TEXT,
  state TEXT, exit_code INTEGER, markers TEXT, log_tail TEXT, source TEXT,
  UNIQUE (job, task_id)
);
CREATE INDEX IF NOT EXISTS job_runs_job_ts ON job_runs(job, started_at);

CREATE TABLE IF NOT EXISTS rollup_hourly (
  probe_id TEXT NOT NULL, hour TEXT NOT NULL, n INTEGER, ok INTEGER, failed INTEGER,
  unknown INTEGER, p50_ms REAL, PRIMARY KEY (probe_id, hour)
);
CREATE TABLE IF NOT EXISTS rollup_daily (
  probe_id TEXT NOT NULL, day TEXT NOT NULL, n INTEGER, ok INTEGER, failed INTEGER,
  unknown INTEGER, p50_ms REAL, PRIMARY KEY (probe_id, day)
);

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, who TEXT NOT NULL, action TEXT NOT NULL, detail TEXT
);
"""


class Store:
    """Thread-safe single-connection SQLite store with async wrappers."""

    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None,
                                   timeout=30)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=TRUNCATE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            self._db.executescript(SCHEMA)
            self.set_meta("schema_version", str(SCHEMA_VERSION))

    @classmethod
    def open_readonly(cls, path: Path | str) -> Store:
        """A read-only handle for a second process (``docker exec``): no schema or meta
        writes, so it can never become a second writer on the Gluster file."""
        self = cls.__new__(cls)
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False,
                                   isolation_level=None, timeout=30)
        self._db.row_factory = sqlite3.Row
        return self

    # ------------------------------------------------------------------ primitives
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, tuple(params))

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def transaction(self) -> _Tx:
        """``with store.transaction() as db:`` -- state change and outbox rows commit together."""
        return _Tx(self)

    async def arun(self, fn: Any, *args: Any) -> Any:
        return await asyncio.to_thread(fn, *args)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ meta
    def set_meta(self, key: str, value: str) -> None:
        self.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else default

    # ------------------------------------------------------------------ results
    def save_result(self, r: Result, probe_id: str, via: str, config_sha: str = "") -> int:
        with self.transaction() as db:
            cur = db.execute(
                "INSERT INTO results(probe_id,check_id,target_id,via,status,warn,started_at,"
                "duration_ms,summary,outcomes,calls,config_sha) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (probe_id, r.check_id, r.target_id, via, r.status, int(r.warn),
                 iso(r.started_at), r.duration_ms, r.summary,
                 json.dumps([_slots(o) for o in r.outcomes]),
                 json.dumps([_slots(c) for c in r.calls]), config_sha))
            rid = cur.lastrowid
            ts = iso(r.started_at)
            for path, value in r.metrics.items():
                db.execute("INSERT INTO metrics(probe_id,path,ts,value) VALUES(?,?,?,?)",
                           (probe_id, path, ts, value))
                day = ts[:10]
                db.execute(
                    "INSERT INTO metric_daily(probe_id,path,day,last,min,max,n) "
                    "VALUES(?,?,?,?,?,?,1) "
                    "ON CONFLICT(probe_id,path,day) DO UPDATE SET last=excluded.last, "
                    "min=MIN(min,excluded.min), max=MAX(max,excluded.max), n=n+1",
                    (probe_id, path, day, value, value, value))
            if r.evidence and r.status != "ok":
                db.execute("INSERT OR REPLACE INTO evidence(result_id,created_at,body) "
                           "VALUES(?,?,?)", (rid, ts, r.evidence[:65536]))
        return int(rid)

    def baseline(self, probe_id: str, path: str, window_s: float,
                 before: dt.datetime | None = None) -> list[float]:
        """Previous numeric values for ``path``, oldest first, excluding ``before`` onwards."""
        end = before or utcnow()
        start = end - dt.timedelta(seconds=window_s)
        if window_s <= 35 * 86400:
            rows = self.query(
                "SELECT value FROM metrics WHERE probe_id=? AND path=? AND ts>=? AND ts<? "
                "ORDER BY ts", (probe_id, path, iso(start), iso(end)))
        else:
            rows = self.query(
                "SELECT last AS value FROM metric_daily WHERE probe_id=? AND path=? AND day>=? "
                "AND day<? ORDER BY day", (probe_id, path, iso(start)[:10], iso(end)[:10]))
        return [float(r["value"]) for r in rows]

    def last_results(self, probe_id: str, n: int = 20) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM results WHERE probe_id=? ORDER BY started_at DESC "
                          "LIMIT ?", (probe_id, n))

    def audit(self, who: str, action: str, detail: str = "") -> None:
        self.execute("INSERT INTO audit(ts,who,action,detail) VALUES(?,?,?,?)",
                     (iso(), who, action, detail))

    # ------------------------------------------------------------------ maintenance
    def rollup_and_prune(self, now: dt.datetime | None = None) -> dict[str, int]:
        now = now or utcnow()
        cutoff_raw = iso(now - dt.timedelta(days=35))
        cutoff_ev = iso(now - dt.timedelta(days=90))
        cutoff_hour = iso(now - dt.timedelta(days=400))
        stats: dict[str, int] = {}
        with self.transaction() as db:
            for table, width in (("rollup_hourly", 13), ("rollup_daily", 10)):
                col = "hour" if table == "rollup_hourly" else "day"
                db.execute(
                    f"INSERT OR REPLACE INTO {table}(probe_id,{col},n,ok,failed,unknown,p50_ms) "
                    f"SELECT probe_id, substr(started_at,1,{width}) AS b, COUNT(*), "
                    "SUM(status='ok'), SUM(status='failed'), SUM(status='unknown'), "
                    "AVG(duration_ms) FROM results WHERE started_at >= ? GROUP BY probe_id, b",
                    (iso(now - dt.timedelta(days=2)),))
            stats["results"] = db.execute("DELETE FROM results WHERE started_at < ?",
                                          (cutoff_raw,)).rowcount
            stats["metrics"] = db.execute("DELETE FROM metrics WHERE ts < ?",
                                          (cutoff_raw,)).rowcount
            stats["evidence"] = db.execute("DELETE FROM evidence WHERE created_at < ?",
                                           (cutoff_ev,)).rowcount
            stats["rollup_hourly"] = db.execute("DELETE FROM rollup_hourly WHERE hour < ?",
                                                (cutoff_hour[:13],)).rowcount
        with self._lock:  # the pragma runs one step per row fetched: drain it
            self._db.execute("PRAGMA incremental_vacuum").fetchall()
        return stats

    def backup_to(self, dest: Path) -> dict[str, Any]:
        """Online backup (sqlite3 backup API) plus a manifest of what was copied."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        with self._lock:
            out = sqlite3.connect(str(tmp))
            self._db.backup(out)
            out.close()
        tmp.replace(dest)
        chk = sqlite3.connect(str(dest))
        integrity = chk.execute("PRAGMA integrity_check").fetchone()[0]
        counts = {t: chk.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("results", "incidents", "job_runs", "rollup_daily")}
        chk.close()
        return {"file": dest.name, "integrity": integrity, "counts": counts, "at": iso()}


class _Tx:
    def __init__(self, store: Store) -> None:
        self.store = store

    def __enter__(self) -> sqlite3.Connection:
        self.store._lock.acquire()
        self.store._db.execute("BEGIN IMMEDIATE")
        return self.store._db

    def __exit__(self, exc_type: Any, *exc: Any) -> None:
        try:
            self.store._db.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.store._lock.release()


def _slots(obj: Any) -> dict[str, Any]:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: getattr(obj, k) for k in obj.__dataclass_fields__}
    return dict(obj)
