"""Synthetic alerts: prove the delivery path end to end, on demand.

``test-alert`` opens an incident labelled ``test`` that goes through the real outbox
and dispatcher on the channels asked for, and resolves itself after five minutes, so
the person running it sees an issue open and close, a mail and a Slack line, and the
outbox shows each provider's reply. ``test-incident --break`` instead flips the flag the
``monitor-selftest`` check reads, so the *whole* chain (probe, thresholds, hold,
routing) is exercised, not just delivery.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from typing import Any

from ..catalogue import Catalogue
from ..model import iso, utcnow
from ..store import Store
from . import outbox

TEST_TARGET = "monitor-test"
LIFETIME = dt.timedelta(minutes=5)
CHANNELS = ("github", "smtp", "slack")


def _payload(channel: str, event: str, key: str, recipients: list[str], who: str,
             private_url: str) -> dict[str, Any]:
    opened = event == "open"
    word = "opened" if opened else "resolved"
    line = f"[TEST] tgx-monitor test alert {word}"
    text = (f"This is a test of the tgx-monitor alert path, started by {who}. "
            "It resolves itself after five minutes. Nothing is broken.")
    link = f"{private_url.rstrip('/')}/incidents/{key}"
    if channel == "slack":
        return {"text": f":test_tube: {line}", "link": link, "line": line}
    if channel == "smtp":
        return {"subject": f"[TEST] tgx-monitor test alert {word}",
                "text": text + f"\n\nDetails (TGX login): {link}", "line": line}
    if not opened:
        return {"action": "close", "comment": "Test resolved.", "line": line, "key": key}
    mentions = " ".join(f"@{h}" for h in recipients)
    body = (f"{text}\n\nDetails (TGX login): {link}" + (f"\n\ncc {mentions}" if mentions else "")
            + f"\n\n<!-- tgxmon:incident={key} -->")
    return {"action": "open", "title": "[TEST] tgx-monitor test alert", "body": body,
            "labels": ["test"], "line": line, "key": key}


def enqueue_test_alert(store: Store, catalogue: Catalogue, recipients: list[str],
                       channels: list[str], who: str, *, now: dt.datetime | None = None,
                       dry_run: bool = False, private_base_url: str = "") -> str:
    """Queue a test incident on ``channels`` to ``recipients`` (handles). Returns its key."""
    now = now or utcnow()
    key = f"test-{now:%Y%m%d%H%M%S}"
    known = set(catalogue.owners.people) if catalogue.owners else set()
    unknown = [h for h in recipients if known and h not in known]
    if unknown:
        raise ValueError(f"not in owners.yaml: {', '.join(unknown)}")
    with store.transaction() as db:
        cur = db.execute("INSERT INTO incidents(key,target_id,severity,title,opened_at,"
                         "last_notified_at) VALUES(?,?,?,?,?,?)",
                         (key, TEST_TARGET, "critical", "[TEST] tgx-monitor test alert",
                          iso(now), iso(now)))
        for ch in channels:
            rcpt = [] if ch == "slack" else list(recipients)
            outbox.enqueue(db, channel=ch, event="open", now=now, recipients=rcpt,
                           incident_id=cur.lastrowid, dry_run=dry_run,
                           payload=_payload(ch, "open", key, rcpt, who, private_base_url))
    store.audit(who, "test-alert", f"{key} via {','.join(channels)} to {','.join(recipients)}")
    return key


def close_due_tests(db: sqlite3.Connection, now: dt.datetime, private_url: str = "") -> int:
    """Resolve test incidents older than five minutes on the channels they opened on."""
    # By target, not by key prefix: a real target may be called ``test-something``.
    due = db.execute("SELECT * FROM incidents WHERE closed_at IS NULL AND target_id=? "
                     "AND opened_at<=?", (TEST_TARGET, iso(now - LIFETIME))).fetchall()
    for inc in due:
        db.execute("UPDATE incidents SET closed_at=? WHERE id=?", (iso(now), inc["id"]))
        opened = db.execute("SELECT DISTINCT channel, recipients, dry_run FROM outbox WHERE "
                            "incident_id=? AND event='open'", (inc["id"],)).fetchall()
        for row in opened:
            rcpt = json.loads(row["recipients"])
            outbox.enqueue(db, channel=row["channel"], event="close", now=now, recipients=rcpt,
                           incident_id=inc["id"], dry_run=bool(row["dry_run"]),
                           payload=_payload(row["channel"], "close", inc["key"], rcpt, "",
                                            private_url))
    return len(due)


def set_selftest(store: Store, broken: bool) -> None:
    """Break or fix the ``monitor-selftest`` check (it reads this flag)."""
    store.set_meta("selftest_broken", "1" if broken else "0")


def selftest_broken(store: Store) -> bool:
    return store.get_meta("selftest_broken", "0") == "1"
