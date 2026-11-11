"""The outbox table: every notification is a row before it is a request.

The engine writes rows in the same transaction as the state change that caused them
(``store.transaction()``), so a crash between "incident opened" and "issue created"
cannot lose the issue or send it twice: on restart the dispatcher finds the unsent row
and sends it. Rows are never deleted; a sent row keeps the provider's reply (201, 250,
200) and a dead row is kept for the private outbox page.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from typing import Any

from ..model import iso
from ..redact import redact_text
from ..store import Store

MAX_ATTEMPTS = 8
BACKOFF_CAP = dt.timedelta(hours=1)


def enqueue(db: sqlite3.Connection, *, channel: str, event: str, payload: dict[str, Any],
            now: dt.datetime, recipients: list[str] | None = None,
            incident_id: int | None = None, dry_run: bool = False) -> int:
    cur = db.execute(
        "INSERT INTO outbox(created_at,channel,event,incident_id,recipients,payload,"
        "next_attempt_at,dry_run) VALUES(?,?,?,?,?,?,?,?)",
        (iso(now), channel, event, incident_id, json.dumps(recipients or []),
         json.dumps(payload), iso(now), int(dry_run)))
    return int(cur.lastrowid or 0)


def _decode(row: dict[str, Any]) -> dict[str, Any]:
    row = dict(row)
    row["recipients"] = json.loads(row["recipients"] or "[]")
    row["payload"] = json.loads(row["payload"] or "{}")
    return row


def due(store: Store, now: dt.datetime, limit: int = 500) -> list[dict[str, Any]]:
    rows = store.query("SELECT * FROM outbox WHERE sent_at IS NULL AND dead=0 AND "
                       "next_attempt_at<=? ORDER BY id LIMIT ?", (iso(now), limit))
    return [_decode(r) for r in rows]


def backoff(attempts: int) -> dt.timedelta:
    """1 min, 2, 4, ... capped at an hour."""
    return min(dt.timedelta(minutes=2 ** max(0, attempts - 1)), BACKOFF_CAP)


def _reply(reply: Any) -> str:
    return redact_text(json.dumps(reply, default=str), cap=4000)


def mark_sent(store: Store, row_id: int, reply: Any, now: dt.datetime) -> None:
    store.execute("UPDATE outbox SET sent_at=?, reply=?, attempts=attempts+1 WHERE id=?",
                  (iso(now), _reply(reply), row_id))


def mark_failed(store: Store, row: dict[str, Any], reply: Any, now: dt.datetime) -> bool:
    """Record a failed attempt; True when the row has just become a dead letter."""
    attempts = int(row["attempts"]) + 1
    dead = attempts >= MAX_ATTEMPTS
    store.execute("UPDATE outbox SET attempts=?, reply=?, next_attempt_at=?, dead=? WHERE id=?",
                  (attempts, _reply(reply), iso(now + backoff(attempts)), int(dead), row["id"]))
    return dead


def mark_dead(store: Store, row_id: int, reply: Any) -> None:
    store.execute("UPDATE outbox SET dead=1, reply=? WHERE id=?", (_reply(reply), row_id))


def sent_count(store: Store, channel: str, since: dt.datetime) -> int:
    """Real sends on ``channel`` since ``since`` (collapsed and dry-run rows excluded)."""
    row = store.one("SELECT COUNT(*) AS n FROM outbox WHERE channel=? AND sent_at>=? AND "
                    "dry_run=0 AND reply NOT LIKE '%collapsed_into%' AND "
                    "reply NOT LIKE '%skipped%'", (channel, iso(since)))
    return int(row["n"]) if row else 0


def earlier_pending(store: Store, row: dict[str, Any]) -> bool:
    """Is an older unsent row waiting for the same incident, or for the same incident
    key, on the same channel? An incident that fails again within 24 h reuses the
    previous one's key and issue, so its ``reopen`` must not overtake the previous
    incident's ``close`` (which would then close the issue of a live incident)."""
    key = (row.get("payload") or {}).get("key")
    return store.one("SELECT 1 AS x FROM outbox WHERE channel=? AND id<? AND sent_at IS NULL "
                     "AND dead=0 AND (incident_id=? OR (? IS NOT NULL AND "
                     "json_extract(payload, '$.key')=?)) LIMIT 1",
                     (row["channel"], row["id"], row["incident_id"], key, key)) is not None


def listing(store: Store, which: str = "pending", limit: int = 100) -> list[dict[str, Any]]:
    """For the CLI and the private outbox page: pending | dead | sent."""
    where = {"pending": "sent_at IS NULL AND dead=0", "dead": "dead=1",
             "sent": "sent_at IS NOT NULL"}[which]
    rows = store.query(f"SELECT * FROM outbox WHERE {where} ORDER BY id DESC LIMIT ?", (limit,))
    return [_decode(r) for r in rows]
