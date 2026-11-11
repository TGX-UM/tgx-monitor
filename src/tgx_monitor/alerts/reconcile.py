"""Reconcile loop (every 5 min): make the database and GitHub agree.

GitHub is the one copy of incident state that survives losing the database: every
issue body carries ``<!-- tgxmon:incident=<key> -->``. After a restore from an older
backup the incidents table may not know about issues opened since; without this loop
the engine would open a duplicate for each. So, in order:

1. re-run the engine's evaluation, closing incidents whose probes are healthy again;
2. adopt each open ``alert`` issue whose marker has no open incident, rebuilding the
   row (target from the ``target:`` label or the key, already announced) so recovery
   closes the existing issue instead of a new one being opened;
3. flag what cannot be matched (no marker, unknown target, a second issue for a target
   that already has one, an issue whose incident is closed), stored in meta
   ``reconcile_orphans`` for the private incidents page. Nothing is auto-closed: a
   human looks first.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from ..model import iso
from . import engine as E

if TYPE_CHECKING:
    from .channels.github import GitHubChannel

log = logging.getLogger("tgx_monitor.alerts.reconcile")

MARKER = re.compile(r"<!--\s*tgxmon:incident=([a-z0-9][a-z0-9-]*)\s*-->")


def _label(labels: list[str], prefix: str) -> str | None:
    return next((lb[len(prefix):] for lb in labels if lb.startswith(prefix)), None)


def target_of(key: str, labels: list[str], known: set[str]) -> str | None:
    """Target id from the ``target:`` label, else the key minus its timestamp."""
    tid = _label(labels, "target:")
    if tid:
        return tid
    head, _, stamp = key.rpartition("-")
    return head if stamp.isdigit() and head in known else None


def adopt(eng: E.AlertEngine, issues: list[dict[str, Any]]) -> dict[str, list[Any]]:
    """Match open issues to incidents. Pure database work, so it is tested offline."""
    store, cat = eng.store, eng.catalogue
    now = eng.now()
    adopted: list[str] = []
    orphans: list[dict[str, Any]] = []
    known = set(cat.targets) | {E.VANTAGE_TARGET}
    with store.transaction() as db:
        # Group by marker first: two issues for one key (a send retried after GitHub
        # created the issue but the reply was lost) must not make the incident's issue
        # number flip between them on every pass. Keep the one the incident already
        # has, else the oldest; flag the rest.
        by_key: dict[str, list[dict[str, Any]]] = {}
        for issue in issues:
            m = MARKER.search(issue.get("body") or "")
            if not m:
                orphans.append({"issue": issue["number"], "why": "no tgxmon marker"})
                continue
            by_key.setdefault(m.group(1), []).append(issue)
        chosen: list[tuple[str, dict[str, Any]]] = []
        for key, group in by_key.items():
            row = db.execute("SELECT issue_number FROM incidents WHERE key=? ORDER BY id DESC "
                             "LIMIT 1", (key,)).fetchone()
            have = row["issue_number"] if row else None
            keep = next((i for i in group if i["number"] == have),
                        min(group, key=lambda i: i["number"]))
            chosen.append((key, keep))
            orphans += [{"issue": i["number"], "key": key,
                         "why": f"duplicate of issue #{keep['number']}"}
                        for i in sorted(group, key=lambda i: i["number"]) if i is not keep]
        for key, issue in chosen:
            num = issue["number"]
            row = db.execute("SELECT * FROM incidents WHERE key=? ORDER BY id DESC LIMIT 1",
                             (key,)).fetchone()
            if row and row["closed_at"] is None:
                if row["issue_number"] != num:
                    db.execute("UPDATE incidents SET issue_number=? WHERE id=?", (num, row["id"]))
                # After a restore the open row may still be unsent: the issue exists.
                db.execute("UPDATE outbox SET sent_at=?, reply=? WHERE incident_id=? AND "
                           "channel='github' AND sent_at IS NULL AND dead=0 AND "
                           "json_extract(payload, '$.action')='open'",
                           (iso(now), json.dumps({"adopted": num}), row["id"]))
                continue
            if row:
                orphans.append({"issue": num, "key": key, "why": "incident closed, issue open"})
                continue
            tid = target_of(key, issue.get("labels", []), known)
            if tid is None or tid not in known:
                orphans.append({"issue": num, "key": key, "why": "unknown target"})
                continue
            cur = db.execute("SELECT * FROM incidents WHERE target_id=? AND closed_at IS NULL",
                             (tid,)).fetchone()
            if cur and cur["issue_number"] and cur["issue_number"] != num:
                orphans.append({"issue": num, "key": key,
                                "why": f"target already has issue #{cur['issue_number']}"})
                continue
            if cur:  # opened since the restore, not yet on GitHub: take over the old issue
                db.execute("UPDATE incidents SET issue_number=?, key=?, last_notified_at="
                           "COALESCE(last_notified_at, ?) WHERE id=?",
                           (num, key, iso(now), cur["id"]))
                db.execute("UPDATE outbox SET sent_at=?, reply=? WHERE incident_id=? AND "
                           "channel='github' AND sent_at IS NULL AND event='open'",
                           (iso(now), json.dumps({"adopted": num}), cur["id"]))
                adopted.append(key)
                continue
            failing = [pid for pid, _v, t, _c in cat.probes() if t.id == tid and
                       (store.one("SELECT state FROM probe_state WHERE probe_id=?", (pid,))
                        or {}).get("state") != "OK"]
            sev = _label(issue.get("labels", []), "sev:")
            created = (issue.get("created_at") or iso(now)).replace("Z", "+00:00")
            # An issue older than the escalation delay has been escalated already (or
            # will look as if it had): do not ping again just because we lost the row.
            old = dt.datetime.fromisoformat(created) <= now - E.ESCALATE
            db.execute("INSERT INTO incidents(key,target_id,severity,title,opened_at,failing,"
                       "issue_number,last_notified_at,escalated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (key, tid, sev if sev in ("critical", "warning", "info") else "warning",
                        issue.get("title", ""), created, json.dumps(failing), num, iso(now),
                        iso(now) if old else None))
            adopted.append(key)
    return {"adopted": adopted, "orphans": orphans}


async def run(eng: E.AlertEngine, github: GitHubChannel | None) -> dict[str, Any]:
    """One reconcile pass. Never raises: a GitHub outage is reported, not fatal."""
    report: dict[str, Any] = {"at": iso(eng.now()), "adopted": [], "orphans": []}
    if github is not None:
        try:
            report.update(adopt(eng, await github.open_alert_issues()))
        except Exception as exc:  # noqa: BLE001
            report["error"] = f"{type(exc).__name__}: {exc}"[:300]
            log.warning("reconcile could not list GitHub issues: %s", report["error"])
    eng.evaluate_now()
    eng.store.set_meta("reconcile_orphans", json.dumps(report))
    if report["adopted"]:
        log.info("reconcile adopted %s", report["adopted"])
    return report
