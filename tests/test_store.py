"""The SQLite store, plus the backup and restore-verify commands built on it.

The store is the one piece whose bugs show up weeks later (a baseline that quietly
includes the current run, a retention rule that eats the rollups), so these tests use
fixed clocks and check the rows themselves.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3

import pytest

from tgx_monitor import backup as B
from tgx_monitor.cli import main
from tgx_monitor.model import Call, Outcome, Result
from tgx_monitor.store import Store

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "data" / "monitor.db")
    yield s
    s.close()


def result(status="ok", at=NOW, metrics=None, evidence="", check="c-1", target="t-1",
           ms=10.0):
    return Result(
        check_id=check, target_id=target, status=status, started_at=at, duration_ms=ms,
        outcomes=[Outcome("status == 200", "ok" if status == "ok" else "failed", "eq 200",
                          "200" if status == "ok" else "500")],
        calls=[Call("GET", "https://example.org/", status=200, ok=True, ms=ms)],
        metrics=metrics or {}, summary=f"{status} run", evidence=evidence)


# ---------------------------------------------------------------- basics
def test_pragmas_and_schema(store):
    assert store.one("PRAGMA journal_mode")["journal_mode"] == "truncate"
    assert store.one("PRAGMA synchronous")["synchronous"] == 2  # FULL
    assert store.get_meta("schema_version") == "1"
    tables = {r["name"] for r in store.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"results", "metrics", "metric_daily", "probe_state", "incidents", "outbox",
            "silences", "job_runs", "rollup_hourly", "rollup_daily", "audit"} <= tables


def test_reopen_keeps_data(tmp_path):
    s = Store(tmp_path / "m.db")
    s.set_meta("k", "v")
    s.close()
    s = Store(tmp_path / "m.db")
    assert s.get_meta("k") == "v" and s.get_meta("absent", "dflt") == "dflt"
    s.close()


def test_save_result_round_trip(store):
    rid = store.save_result(result("failed", evidence="body excerpt"), "c-1@tgx1", "tgx1",
                            config_sha="abc")
    row = store.last_results("c-1@tgx1")[0]
    assert row["id"] == rid and row["via"] == "tgx1" and row["config_sha"] == "abc"
    assert row["started_at"] == "2026-11-11T12:00:00+00:00"
    assert json.loads(row["outcomes"])[0] == {
        "assertion": "status == 200", "status": "failed", "expected": "eq 200",
        "found": "500", "warn_only": False}
    assert json.loads(row["calls"])[0]["url"] == "https://example.org/"
    assert store.one("SELECT body FROM evidence WHERE result_id=?", (rid,))["body"] == \
        "body excerpt"


def test_evidence_kept_only_for_non_ok_and_capped(store):
    rid_ok = store.save_result(result("ok", evidence="x"), "p", "public")
    rid_bad = store.save_result(result("unknown", evidence="y" * 100_000), "p", "public")
    assert store.one("SELECT * FROM evidence WHERE result_id=?", (rid_ok,)) is None
    body = store.one("SELECT body FROM evidence WHERE result_id=?", (rid_bad,))["body"]
    assert len(body) == 65536


def test_last_results_newest_first(store):
    for h in range(3):
        store.save_result(result(at=NOW + dt.timedelta(hours=h)), "p", "public")
    rows = store.last_results("p", n=2)
    assert [r["started_at"][11:13] for r in rows] == ["14", "13"]


def test_transaction_rolls_back_on_error(store):
    with pytest.raises(RuntimeError), store.transaction() as db:
        db.execute("INSERT INTO audit(ts,who,action) VALUES('t','me','x')")
        raise RuntimeError("boom")
    assert store.query("SELECT * FROM audit") == []
    store.audit("marvinm2", "silence", "aopwiki-sparql")
    assert store.one("SELECT who, action FROM audit") == {"who": "marvinm2",
                                                          "action": "silence"}


async def test_arun_runs_in_a_thread(store):
    assert await store.arun(store.get_meta, "schema_version") == "1"


# ---------------------------------------------------------------- metrics and baselines
def test_metrics_and_daily_aggregate(store):
    for h, v in ((1, 10.0), (2, 4.0), (3, 7.0)):
        store.save_result(result(at=NOW.replace(hour=h), metrics={"count": v}), "p", "public")
    day = store.one("SELECT * FROM metric_daily WHERE probe_id='p' AND path='count'")
    assert (day["last"], day["min"], day["max"], day["n"]) == (7.0, 4.0, 10.0, 3)
    assert store.one("SELECT COUNT(*) AS n FROM metrics")["n"] == 3


def test_baseline_window_excludes_current_run(store):
    for d in (10, 6, 3, 1, 0):
        store.save_result(result(at=NOW - dt.timedelta(days=d), metrics={"x": 100.0 - d}),
                          "p", "public")
    vals = store.baseline("p", "x", 7 * 86400, before=NOW)
    assert vals == [94.0, 97.0, 99.0]  # oldest first; day 10 outside, NOW itself excluded
    assert store.baseline("p", "other", 7 * 86400, before=NOW) == []
    assert store.baseline("q", "x", 7 * 86400, before=NOW) == []


def test_long_baseline_uses_daily_values(store):
    for d in (100, 50, 2, 0):
        store.save_result(result(at=NOW - dt.timedelta(days=d), metrics={"x": float(d)}),
                          "p", "public")
    # > 35 days reads metric_daily, whole days before today's.
    assert store.baseline("p", "x", 400 * 86400, before=NOW) == [100.0, 50.0, 2.0]


# ---------------------------------------------------------------- retention
def test_rollup_and_prune(store):
    old = NOW - dt.timedelta(days=40)
    ancient = NOW - dt.timedelta(days=100)
    store.save_result(result("failed", at=ancient, evidence="e"), "p", "public")
    store.save_result(result("failed", at=old, evidence="e", metrics={"x": 1.0}), "p", "public")
    store.execute("INSERT INTO rollup_hourly VALUES('p','2025-09-01T00',1,1,0,0,1.0)")
    recent = NOW - dt.timedelta(hours=3)
    for i, st in enumerate(("ok", "ok", "failed", "unknown")):
        store.save_result(result(st, at=recent + dt.timedelta(minutes=i), ms=10.0 * (i + 1)),
                          "p", "public")
    stats = store.rollup_and_prune(NOW)
    assert stats == {"results": 2, "metrics": 1, "evidence": 1, "rollup_hourly": 1}
    hour = store.one("SELECT * FROM rollup_hourly WHERE hour=?", (recent.isoformat()[:13],))
    assert (hour["n"], hour["ok"], hour["failed"], hour["unknown"]) == (4, 2, 1, 1)
    day = store.one("SELECT * FROM rollup_daily WHERE day='2026-11-11'")
    assert day["n"] == 4
    # Daily metric values survive raw-metric pruning: they are the long baselines.
    assert store.one("SELECT COUNT(*) AS n FROM metric_daily")["n"] == 1
    # Re-running is idempotent for the rollups.
    store.rollup_and_prune(NOW)
    assert store.one("SELECT n FROM rollup_daily WHERE day='2026-11-11'")["n"] == 4


def test_prune_returns_space_to_the_file(store):
    old = (NOW - dt.timedelta(days=200)).isoformat()
    with store.transaction() as db:  # one transaction: synchronous=FULL makes each slow
        for i in range(400):
            db.execute("INSERT INTO results(probe_id,check_id,target_id,via,status,started_at,"
                       "summary) VALUES('p','c','t','public','failed',?,?)", (old, "x" * 2000))
            db.execute("INSERT INTO evidence VALUES(?,?,?)", (i, old, "y" * 2000))
    store.rollup_and_prune(NOW)
    assert store.one("PRAGMA freelist_count")["freelist_count"] == 0


# ---------------------------------------------------------------- backup_to
def fill(store, n=5):
    for i in range(n):
        store.save_result(result("failed" if i % 2 else "ok", at=NOW - dt.timedelta(hours=i)),
                          "p", "public")
    store.execute("INSERT INTO incidents(key,target_id,severity,opened_at) "
                  "VALUES('k','t-1','high','2026-11-11')")


def test_backup_to_is_a_consistent_copy(store, tmp_path):
    fill(store)
    info = store.backup_to(tmp_path / "out" / "copy.db")
    assert info["integrity"] == "ok"
    assert info["counts"] == {"results": 5, "incidents": 1, "job_runs": 0, "rollup_daily": 0}
    copy = sqlite3.connect(tmp_path / "out" / "copy.db")
    assert copy.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 5
    copy.close()
    assert not (tmp_path / "out" / "copy.db.part").exists()


# ---------------------------------------------------------------- backup.py
def test_backup_writes_manifest_and_keeps_fourteen(store, tmp_path):
    fill(store)
    dest = tmp_path / "backups"
    for d in range(16):
        m = B.backup(store, dest, now=NOW - dt.timedelta(days=15 - d))
    assert m["ok"] and m["file"] == "monitor-2026-11-11.db"
    assert m["sha256"] == B.sha256(dest / "monitor-2026-11-11.db")
    on_disk = json.loads((dest / "monitor-2026-11-11.json").read_text())
    assert on_disk["counts"]["results"] == 5 and on_disk["schema_version"] == "1"
    assert len(list(dest.glob("monitor-*.db"))) == 14
    assert len(list(dest.glob("monitor-*.json"))) == 14
    assert m["pruned"] == ["monitor-2026-10-28.db"]
    assert not (dest / "monitor-2026-10-27.db").exists()


def test_restore_verify_ok_and_marker(store, tmp_path):
    fill(store)
    m = B.backup(store, tmp_path, now=NOW)
    out = B.restore_verify(tmp_path / m["file"])
    assert out["ok"], out["problems"]
    assert out["counts"] == m["counts"] and out["integrity"] == "ok"
    marker = json.loads((tmp_path / "monitor-2026-11-11.verified.json").read_text())
    assert marker["ok"] and marker["counts"]["results"] == 5 and marker["verified_at"]


def test_restore_verify_detects_tampering(store, tmp_path):
    fill(store)
    m = B.backup(store, tmp_path, now=NOW)
    f = tmp_path / m["file"]
    db = sqlite3.connect(f)
    db.execute("DELETE FROM results WHERE rowid IN (SELECT rowid FROM results LIMIT 2)")
    db.commit()
    db.close()
    out = B.restore_verify(f)
    assert not out["ok"]
    assert "sha256 differs from the manifest" in out["problems"]
    assert "results: 3 rows, manifest says 5" in out["problems"]
    assert json.loads((tmp_path / "monitor-2026-11-11.verified.json").read_text())["ok"] is False


def test_restore_verify_garbage_and_missing_manifest(tmp_path):
    f = tmp_path / "monitor-2026-11-11.db"
    f.write_bytes(b"not a database at all" * 100)
    out = B.restore_verify(f)
    assert not out["ok"]
    assert any("manifest" in p for p in out["problems"])
    assert any("cannot open" in p or "integrity" in p for p in out["problems"])


def test_backup_cli_reads_live_db_without_writing(tmp_path, monkeypatch, capsys):
    db = tmp_path / "live.db"
    s = Store(db)
    fill(s)
    s.close()
    before = db.stat().st_mtime_ns
    monkeypatch.setenv("TGXMON_DB", str(db))
    dest = tmp_path / "bk"
    assert main(["backup", "--db", str(db), str(dest)]) == 0
    assert db.stat().st_mtime_ns == before
    printed = json.loads(capsys.readouterr().out)
    assert printed["ok"] and (dest / printed["file"]).exists()
    assert main(["restore-verify", str(dest / printed["file"])]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_backup_cli_missing_db_does_not_create_one(tmp_path, capsys):
    db = tmp_path / "nope.db"
    assert main(["backup", "--db", str(db), str(tmp_path / "bk")]) == 2
    assert not db.exists()
    assert "no database" in capsys.readouterr().err


def test_restore_verify_cli_exit_code_on_mismatch(tmp_path, capsys):
    f = tmp_path / "monitor-2026-11-11.db"
    f.write_bytes(b"")
    assert main(["restore-verify", str(f), "--marker", str(tmp_path / "m.json")]) == 1
    assert json.loads((tmp_path / "m.json").read_text())["ok"] is False


def test_db_path_from_env(monkeypatch):
    monkeypatch.delenv("TGXMON_DB", raising=False)
    assert str(B.db_path()) == "/data/monitor.db"
    monkeypatch.setenv("TGXMON_DB", "/tmp/x.db")
    assert str(B.db_path()) == "/tmp/x.db"


# ---------------------------------------------------------------- offsite-copy
def test_offsite_copy_copies_verifies_and_skips_a_second_time(store, tmp_path):
    fill(store)
    src, dst = tmp_path / "gluster", tmp_path / "hidrive"
    dst.mkdir()
    for d in range(3):
        B.backup(store, src, now=NOW - dt.timedelta(days=2 - d))
    out = B.offsite_copy(src, dst)
    assert out["ok"], out["problems"]
    assert out["copied"] and out["file"] == "monitor-2026-11-11.db"
    assert sorted(p.name for p in dst.iterdir()) == [
        "monitor-2026-11-11.db", "monitor-2026-11-11.json", "monitor-2026-11-11.verified.json"]
    again = B.offsite_copy(src, dst)
    assert again["ok"] and not again["copied"]


def test_offsite_copy_keeps_fourteen(store, tmp_path):
    fill(store)
    src, dst = tmp_path / "gluster", tmp_path / "hidrive"
    dst.mkdir()
    for d in range(16):
        B.backup(store, src, now=NOW - dt.timedelta(days=15 - d), keep=1)
        assert B.offsite_copy(src, dst)["ok"]
    assert len(list(dst.glob("monitor-*.db"))) == 14
    assert not list(dst.glob("*.part"))


def test_offsite_copy_catches_a_damaged_copy(store, tmp_path):
    fill(store)
    src, dst = tmp_path / "gluster", tmp_path / "hidrive"
    dst.mkdir()
    m = B.backup(store, src, now=NOW)
    (dst / m["file"]).write_bytes(b"not a database")  # a stale, wrong file is replaced
    assert B.offsite_copy(src, dst)["ok"]
    # A source file damaged after its manifest was written: the copy must fail verification.
    (dst / m["file"]).unlink()
    (src / m["file"]).write_bytes((src / m["file"]).read_bytes()[:-4096])
    out = B.offsite_copy(src, dst)
    assert not out["ok"] and out["problems"]
    assert json.loads((dst / "monitor-2026-11-11.verified.json").read_text())["ok"] is False


def test_offsite_copy_without_backups_fails_loudly(tmp_path):
    out = B.offsite_copy(tmp_path / "empty", tmp_path)
    assert not out["ok"] and "no monitor-" in out["problems"][0]
    assert main(["offsite-copy", str(tmp_path / "empty"), str(tmp_path)]) == 1


def test_offsite_copy_pings_healthchecks(store, tmp_path, monkeypatch):
    import httpx

    fill(store)
    src, dst, sec = tmp_path / "g", tmp_path / "h", tmp_path / "secrets"
    dst.mkdir()
    sec.mkdir()
    (sec / "tgxmon_hc_urls").write_text(json.dumps({"hidrive-copy": "https://hc.example/p/abc"}))
    monkeypatch.setattr("tgx_monitor.secrets.SECRETS_DIR", sec)
    sent = []
    monkeypatch.setattr(httpx, "post", lambda url, **kw: sent.append(url) or
                        httpx.Response(200, request=httpx.Request("POST", url)))
    B.backup(store, src, now=NOW)
    assert main(["offsite-copy", str(src), str(dst), "--hc-check", "hidrive-copy"]) == 0
    assert sent == ["https://hc.example/p/abc"]
    assert main(["offsite-copy", str(tmp_path / "none"), str(dst), "--hc-check",
                 "hidrive-copy"]) == 1
    assert sent[-1] == "https://hc.example/p/abc/fail"
    assert "no URL" in B.hc_ping("other", True, "x")


def test_marker_is_replaced_not_overwritten(store, tmp_path):
    """HiDrive (CIFS) refuses an in-place overwrite of an existing file (ESTALE); the
    marker is written under .part and renamed over the old one, on every run."""
    fill(store)
    m = B.backup(store, tmp_path, now=NOW)
    assert B.restore_verify(tmp_path / m["file"])["ok"]
    assert B.restore_verify(tmp_path / m["file"])["ok"]  # a second run replaces it
    assert not list(tmp_path.glob("*.part"))
