"""The dispatcher: sends due outbox rows, and is the only code that waits on a provider.

Rules, each from a way alerting goes wrong:

* **Backoff and dead letters.** A failed send is retried after 1, 2, 4 ... minutes
  (capped at an hour); after 8 attempts the row is dead, kept for the private outbox
  page, and the *other* channels get one self alert (at most every 6 h per channel), so
  a broken Slack webhook is reported by mail rather than by nobody.
* **Order per incident on GitHub.** A comment or close cannot go before the issue
  exists; such a row waits while an older row for the same incident is unsent.
* **Storm brake.** More than 8 rows due on one channel collapse into one summary per
  recipient set; at most 8 sends per channel per minute, Slack at most 20 an hour.
  GitHub is rate-limited the same way but never collapsed (each issue carries the
  marker reconcile needs).
* **Shadow mode.** ``dry_run`` rows are logged and marked sent, never delivered.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import yaml

from ..model import iso, utcnow
from ..store import Store
from . import outbox, router
from .channels.base import Channel, Message

log = logging.getLogger("tgx_monitor.alerts.dispatch")

PER_MINUTE = 8
SLACK_PER_HOUR = 20
DEAD_ALERT_EVERY = dt.timedelta(hours=6)
COLLAPSIBLE = {"smtp", "slack"}
SELF_CHANNELS = ("smtp", "slack")


class Dispatcher:
    def __init__(self, store: Store, channels: Mapping[str, Channel], *,
                 now: Callable[[], dt.datetime] = utcnow, admins: Sequence[str] = ()) -> None:
        self.store = store
        self.channels = dict(channels)
        self.now = now
        self.admins = list(admins)

    async def run_once(self) -> dict[str, int]:
        """Send what is due now. Returns counts by outcome."""
        now = self.now()
        stats: dict[str, int] = defaultdict(int)
        by_channel: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in outbox.due(self.store, now):
            by_channel[row["channel"]].append(row)
        for name, rows in by_channel.items():
            live = []
            for row in rows:
                if row["dry_run"]:
                    log.info("dry-run %s %s -> %s: %s", name, row["event"], row["recipients"],
                             row["payload"].get("line", ""))
                    outbox.mark_sent(self.store, row["id"], {"dry_run": True}, now)
                    stats["dry_run"] += 1
                else:
                    live.append(row)
            if not live:
                continue
            channel = self.channels.get(name)
            if channel is None:
                # A missing secret must not swallow alerts quietly: tell the others.
                for row in live:
                    outbox.mark_dead(self.store, row["id"], {"error": "channel not configured"})
                    stats["unconfigured"] += 1
                self._channel_dead(name, now)
                continue
            if name != "hc":
                live = self._brake(name, live, now)
            held: set[int | str] = set()
            for row in live:
                stats[await self._deliver(channel, row, now, held)] += 1
        return dict(stats)

    # ------------------------------------------------------------------ storm brake
    def _brake(self, name: str, rows: list[dict[str, Any]], now: dt.datetime
               ) -> list[dict[str, Any]]:
        budget = PER_MINUTE - outbox.sent_count(self.store, name, now - dt.timedelta(minutes=1))
        if name == "slack":
            budget = min(budget, SLACK_PER_HOUR - outbox.sent_count(
                self.store, name, now - dt.timedelta(hours=1)))
        if budget <= 0:
            return []
        if len(rows) <= PER_MINUTE or name not in COLLAPSIBLE:
            return rows[:budget]
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            groups[json.dumps(sorted(row["recipients"]))].append(row)
        summaries = []
        with self.store.transaction() as db:
            for rcpt, members in groups.items():
                sid = outbox.enqueue(db, channel=name, event="summary", now=now,
                                     recipients=json.loads(rcpt),
                                     payload=router.summary(members, name))
                db.executemany("UPDATE outbox SET sent_at=?, reply=? WHERE id=?",
                               [(iso(now), json.dumps({"collapsed_into": sid}), m["id"])
                                for m in members])
                summaries.append({"id": sid, "channel": name, "event": "summary",
                                  "incident_id": None, "recipients": json.loads(rcpt),
                                  "payload": router.summary(members, name), "attempts": 0,
                                  "dry_run": 0})
        log.warning("storm brake on %s: %d rows collapsed into %d", name, len(rows),
                    len(summaries))
        return summaries[:budget]

    # ------------------------------------------------------------------ one row
    async def _deliver(self, channel: Channel, row: dict[str, Any], now: dt.datetime,
                       held: set[int | str]) -> str:
        inc_id = row["incident_id"]
        key = row["payload"].get("key")
        issue = None
        if row["channel"] == "github" and inc_id is not None:
            # Strict order per incident and per key (a reopened incident shares its
            # predecessor's key and issue): wait while an older row is unsent.
            if inc_id in held or (key and key in held):
                return "waiting"
            if outbox.earlier_pending(self.store, row):
                return "waiting"
            inc = self.store.one("SELECT issue_number FROM incidents WHERE id=?", (inc_id,))
            issue = inc["issue_number"] if inc else None
            if row["payload"].get("action") != "open" and not issue:
                outbox.mark_sent(self.store, row["id"], {"skipped": "incident has no issue"}, now)
                return "skipped"
            if row["payload"].get("action") == "open" and issue:
                # Reconcile matched the incident to an existing issue meanwhile.
                outbox.mark_sent(self.store, row["id"], {"skipped": f"issue #{issue} exists"},
                                 now)
                return "skipped"
        msg = Message(row["id"], row["channel"], row["event"], row["recipients"],
                      row["payload"], issue)
        try:
            ok, reply = await channel.send(msg)
        except Exception as exc:  # noqa: BLE001 - belt and braces: channels should not raise
            ok, reply = False, {"error": f"{type(exc).__name__}: {exc}"}
        if ok:
            outbox.mark_sent(self.store, row["id"], reply, now)
            if row["channel"] == "github" and inc_id is not None and reply.get("number") \
                    and row["payload"].get("action") == "open":
                self.store.execute("UPDATE incidents SET issue_number=? WHERE id=?",
                                   (reply["number"], inc_id))
            return "sent"
        if row["channel"] == "github" and inc_id is not None:
            held.add(inc_id)
            if key:
                held.add(key)
        log.warning("send %s #%s failed: %s", row["channel"], row["id"], reply)
        if outbox.mark_failed(self.store, row, reply, now):
            self._channel_dead(row["channel"], now)
            return "dead"
        return "retry"

    def _channel_dead(self, name: str, now: dt.datetime) -> None:
        """Tell the other channels, once per channel per 6 h."""
        key = f"dead_alert:{name}"
        last = self.store.get_meta(key)
        if last and now - dt.datetime.fromisoformat(last) < DEAD_ALERT_EVERY:
            return
        count = self.store.one("SELECT COUNT(*) AS n FROM outbox WHERE channel=? AND dead=1",
                               (name,))
        payloads = router.channel_dead(name, int(count["n"]) if count else 1)
        with self.store.transaction() as db:
            for other in SELF_CHANNELS:
                if other == name or other not in self.channels:
                    continue
                outbox.enqueue(db, channel=other, event="self", now=now,
                               recipients=self.admins if other == "smtp" else [],
                               payload=payloads[other])
            self.store.set_meta(key, iso(now))


def build_channels(secrets_reader: Callable[[str], str | None],
                   env: Mapping[str, str] | None = None) -> dict[str, Channel]:
    """Every channel whose credentials are present. A missing secret leaves the channel
    out (its rows then dead-letter as 'not configured') rather than failing start-up."""
    from .channels.github import GitHubChannel
    from .channels.hc import HcChannel
    from .channels.slack import SlackChannel
    from .channels.smtp import SmtpChannel

    env = os.environ if env is None else env
    out: dict[str, Channel] = {}
    repo = env.get("TGXMON_GH_REPO")
    key, pat = secrets_reader("tgxmon_gh_app_key"), secrets_reader("tgxmon_gh_token")
    if repo and (pat or (key and env.get("TGXMON_GH_APP_ID"))):
        out["github"] = GitHubChannel(repo, app_id=env.get("TGXMON_GH_APP_ID"),
                                      installation_id=env.get("TGXMON_GH_INSTALLATION_ID"),
                                      app_key=key, token=pat)
    smtp, contacts = _json(secrets_reader, "tgxmon_smtp"), _json(secrets_reader,
                                                                 "tgxmon_contacts")
    if isinstance(smtp, dict) and smtp.get("host") and smtp.get("from"):
        out["smtp"] = SmtpChannel(smtp, contacts if isinstance(contacts, dict) else {})
    hook = secrets_reader("tgxmon_slack_webhook")
    if hook and hook.startswith("https://hooks.slack.com/"):  # a placeholder is not a hook
        out["slack"] = SlackChannel(hook)
    urls = _json(secrets_reader, "tgxmon_hc_urls")
    if isinstance(urls, dict) and urls:
        out["hc"] = HcChannel({str(k): str(v) for k, v in urls.items()})
    return out


def _json(reader: Callable[[str], str | None], name: str) -> Any:
    """JSON (or YAML) secret content, None when absent or unreadable."""
    raw = reader(name)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        try:
            return yaml.safe_load(raw)
        except yaml.YAMLError:
            log.error("secret %s is neither JSON nor YAML", name)
            return None
