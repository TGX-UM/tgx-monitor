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
        marker.write_text(json.dumps(out, indent=1, sort_keys=True))
        out["marker"] = str(marker)
    except OSError as exc:
        out["ok"] = False
        out["problems"].append(f"cannot write marker {marker}: {exc}")
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
