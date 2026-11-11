"""Backups of the monitor's own database, and the drill that proves they restore.

``tgx-monitor backup DEST_DIR`` writes ``monitor-<UTC date>.db`` with the sqlite3 online
backup API (:meth:`Store.backup_to`), a manifest ``monitor-<date>.json`` beside it
(sha256, size, ``integrity_check``, row counts) and keeps the newest 14. Core calls
:func:`backup` in-process every night; the command exists for drills and by hand.

``tgx-monitor restore-verify FILE`` is what the weekly job runs against the HiDrive copy:
it opens the copy, runs ``integrity_check``, compares the sha256 and the row counts with
the manifest and writes ``<name>.verified.json`` (``{verified_at, ok, counts, ...}``),
which the ``restore_marker`` check reads. A backup nobody has opened is a hope, not a
backup, so the marker is written on failure too, with ``ok: false``.

``tgx-monitor offsite-copy SRC_DIR DEST_DIR`` is the nightly cluster job
(``cronjobs_tgx-monitor-offsite``): it copies the newest backup and its manifest from
GlusterFS to HiDrive (``.part`` then rename, so a half-written copy never carries the
real name), runs :func:`restore_verify` on the copy, prunes to 14 and logs
``Done: monitor-<date>.db verified``. Without it every copy sits on the volume it backs up.

Why the command opens the live database read-only instead of through :class:`Store`:
``Store()`` creates the schema and writes ``meta``, and the database on GlusterFS has
exactly one writer (core). A second writer from ``docker exec`` is the very thing the
store's rules forbid. Backup files are opened with ``immutable=1``: nothing writes them,
and it keeps SQLite from taking locks on a CIFS mount (HiDrive) that it cannot honour.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path
from typing import Any

from .model import iso, utcnow
from .store import Store

KEEP = 14
DEFAULT_DB = "/data/monitor.db"
PREFIX = "monitor-"


def db_path() -> Path:
    return Path(os.environ.get("TGXMON_DB", DEFAULT_DB))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _connect_ro(path: Path, immutable: bool = False) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(f"no database at {path}")
    flags = "mode=ro" + ("&immutable=1" if immutable else "")
    return sqlite3.connect(f"file:{path}?{flags}", uri=True, check_same_thread=False)


def readonly_store(path: Path) -> Store:
    """A :class:`Store` over a read-only connection, enough for ``backup_to``.

    Skips ``Store.__init__`` on purpose (it writes; see the module docstring).
    """
    s = Store.__new__(Store)
    s.path = str(path)
    s._lock = threading.RLock()
    s._db = _connect_ro(path)
    s._db.row_factory = sqlite3.Row
    return s


def _prune(dest_dir: Path, keep: int) -> list[str]:
    dbs = sorted(dest_dir.glob(f"{PREFIX}*.db"))
    gone = []
    for old in dbs[:-keep] if keep > 0 else []:
        stem = old.with_suffix("")
        for p in (old, stem.with_suffix(".json"), Path(f"{stem}.verified.json")):
            p.unlink(missing_ok=True)
        gone.append(old.name)
    return gone


def backup(store: Store, dest_dir: Path, keep: int = KEEP,
           now: dt.datetime | None = None) -> dict[str, Any]:
    """Copy ``store`` to ``dest_dir/monitor-<date>.db``, write its manifest, prune."""
    now = now or utcnow()
    dest_dir = Path(dest_dir)
    dest = dest_dir / f"{PREFIX}{now:%Y-%m-%d}.db"
    info = store.backup_to(dest)
    manifest = {
        **info, "sha256": sha256(dest), "bytes": dest.stat().st_size,
        "source": Path(store.path).name, "schema_version": store.get_meta("schema_version"),
        "ok": info["integrity"] == "ok",
    }
    tmp = dest.with_suffix(".json.part")
    tmp.write_text(json.dumps(manifest, indent=1, sort_keys=True))
    tmp.replace(dest.with_suffix(".json"))
    manifest["pruned"] = _prune(dest_dir, keep)
    return manifest


def _write_replace(path: Path, text: str) -> None:
    """Write via a temporary name and rename over the old file. Overwriting in place on
    HiDrive's CIFS mount fails with ESTALE ("Stale file handle") once the file exists;
    a rename does not, and readers never see half a file either."""
    part = path.with_name(path.name + ".part")
    part.unlink(missing_ok=True)
    part.write_text(text)
    try:
        part.replace(path)
    except OSError:
        path.unlink(missing_ok=True)  # some CIFS servers refuse rename-over-existing
        part.replace(path)


def restore_verify(file: Path, marker: Path | None = None) -> dict[str, Any]:
    """Open a backup, check it against its manifest, write the marker. Never raises."""
    file = Path(file)
    marker = marker or Path(f"{file.with_suffix('')}.verified.json")
    problems: list[str] = []
    counts: dict[str, int] = {}
    integrity = "not run"
    manifest: dict[str, Any] = {}
    mpath = file.with_suffix(".json")
    try:
        manifest = json.loads(mpath.read_text())
    except (OSError, ValueError) as exc:
        problems.append(f"manifest {mpath.name} unreadable: {type(exc).__name__}")
    try:
        db = _connect_ro(file, immutable=True)
        try:
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
            for table in manifest.get("counts") or {"results": 0, "incidents": 0}:
                if table.isidentifier():  # the manifest lives on a shared mount
                    counts[table] = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        finally:
            db.close()
    except (OSError, sqlite3.Error) as exc:
        problems.append(f"cannot open {file.name}: {type(exc).__name__}: {exc}")
    if integrity != "ok":
        problems.append(f"integrity_check: {integrity}")
    if manifest.get("sha256") and file.is_file() and sha256(file) != manifest["sha256"]:
        problems.append("sha256 differs from the manifest")
    for table, n in (manifest.get("counts") or {}).items():
        if counts.get(table) != n:
            problems.append(f"{table}: {counts.get(table)} rows, manifest says {n}")
    out = {"verified_at": iso(), "ok": not problems, "counts": counts, "file": file.name,
           "integrity": integrity, "backup_at": manifest.get("at"), "problems": problems}
    try:
        _write_replace(marker, json.dumps(out, indent=1, sort_keys=True))
        out["marker"] = str(marker)
    except OSError as exc:
        out["ok"] = False
        out["problems"].append(f"cannot write marker {marker}: {exc}")
    return out


def _copy(src: Path, dest: Path) -> None:
    part = dest.with_name(dest.name + ".part")
    with src.open("rb") as fi, part.open("wb") as fo:
        while chunk := fi.read(1 << 20):
            fo.write(chunk)
        fo.flush()
        os.fsync(fo.fileno())
    try:
        part.replace(dest)
    except OSError:
        dest.unlink(missing_ok=True)  # see _write_replace: CIFS and existing files
        part.replace(dest)


def offsite_copy(src_dir: Path, dest_dir: Path, keep: int = KEEP) -> dict[str, Any]:
    """Copy the newest backup + manifest to ``dest_dir``, verify the copy, prune."""
    src_dir, dest_dir = Path(src_dir), Path(dest_dir)
    dbs = sorted(src_dir.glob(f"{PREFIX}*.db"))
    if not dbs:
        return {"ok": False, "problems": [f"no {PREFIX}*.db in {src_dir}"]}
    newest = dbs[-1]
    manifest = newest.with_suffix(".json")
    if not manifest.is_file():
        return {"ok": False, "problems": [f"{manifest.name} missing beside {newest.name}"]}
    dest = dest_dir / newest.name
    want = json.loads(manifest.read_text()).get("sha256")
    copied = False
    if not (dest.is_file() and want and sha256(dest) == want):
        _copy(manifest, dest.with_suffix(".json"))
        _copy(newest, dest)
        copied = True
    out = restore_verify(dest)
    out["copied"] = copied
    out["pruned"] = _prune(dest_dir, keep)
    return out


# ---------------------------------------------------------------------- CLI
def cmd_backup(args: argparse.Namespace) -> int:
    try:
        store = readonly_store(Path(args.db))
    except (OSError, sqlite3.Error) as exc:
        print(f"backup: {exc}", file=sys.stderr)
        return 2
    try:
        m = backup(store, Path(args.dest), keep=args.keep)
    except (OSError, sqlite3.Error) as exc:
        print(f"backup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(json.dumps(m, indent=1, sort_keys=True))
    return 0 if m["ok"] else 1


def cmd_restore_verify(args: argparse.Namespace) -> int:
    out = restore_verify(Path(args.file), Path(args.marker) if args.marker else None)
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0 if out["ok"] else 1


def hc_ping(check: str, ok: bool, body: str) -> str:
    """Ping healthchecks.io ``check`` from a one-shot job, with the URL from the
    tgxmon_hc_urls secret. Never raises: a missing URL or a failed ping is reported."""
    import httpx

    from .secrets import read_secret_json

    urls = read_secret_json("tgxmon_hc_urls")
    url = urls.get(check) if isinstance(urls, dict) else None
    if not url:
        return f"healthchecks: no URL for {check}"
    try:
        r = httpx.post(str(url).rstrip("/") + ("" if ok else "/fail"),
                       content=body[:10000].encode(), timeout=15)
        return f"healthchecks: {check} {'success' if ok else 'fail'} -> {r.status_code}"
    except httpx.HTTPError as exc:
        return f"healthchecks: {check} ping failed: {type(exc).__name__}"


def cmd_offsite_copy(args: argparse.Namespace) -> int:
    try:
        out = offsite_copy(Path(args.src), Path(args.dest), keep=args.keep)
    except (OSError, ValueError) as exc:
        out = {"ok": False, "problems": [f"{type(exc).__name__}: {exc}"]}
    print(json.dumps(out, indent=1, sort_keys=True))
    ok = bool(out.get("ok"))
    line = (f"Done: {out['file']} verified" if ok
            else f"FAILED: {'; '.join(out.get('problems') or ['unknown'])}")
    if args.hc_check:
        print(hc_ping(args.hc_check, ok, line))
    print(line, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


def add_commands(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("backup", help="online backup of the monitor database, keep 14")
    p.add_argument("dest", metavar="DEST_DIR")
    p.add_argument("--db", default=str(db_path()), help="database (env TGXMON_DB)")
    p.add_argument("--keep", type=int, default=KEEP)
    p.set_defaults(fn=cmd_backup)

    v = sub.add_parser("restore-verify", help="open a backup, compare with its manifest")
    v.add_argument("file", metavar="FILE")
    v.add_argument("--marker", help="where to write the marker (default: beside FILE)")
    v.set_defaults(fn=cmd_restore_verify)

    o = sub.add_parser("offsite-copy", help="copy the newest backup off the cluster, verify it")
    o.add_argument("src", metavar="SRC_DIR")
    o.add_argument("dest", metavar="DEST_DIR")
    o.add_argument("--keep", type=int, default=KEEP)
    o.add_argument("--hc-check", metavar="NAME",
                   help="healthchecks.io check to ping (URL from the tgxmon_hc_urls secret)")
    o.set_defaults(fn=cmd_offsite_copy)
