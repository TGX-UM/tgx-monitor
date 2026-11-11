"""Who hears about what, and what they read. Pure functions: no clock, no I/O.

Routing is a table, not a chain of ifs, so ``tests/test_alerts_routing.py`` can state
the whole policy as (class, severity, notify flags) -> {channel: recipients} and a
change to who gets paged shows up as a one-line diff in review.

Recipients are handles from ``owners.yaml``, never addresses: the SMTP channel resolves
them from the ``tgxmon_contacts`` secret at send time, so nothing written to the
outbox (or shown on the private outbox page) carries an e-mail address. An e-mail cc
is written ``cc:<handle>``.

Every text built here is public-safe by construction: it is assembled only from
catalogue fields that ``Catalogue.validate`` scans for leaks (target name, check
``describe``, ``public_summary``) plus timestamps and links. Raw response bodies,
evidence and result summaries never reach a notification. Private targets (class
``security``, ``public: false`` on the target or a failing check) get no GitHub issue
and their texts say only the ``public_summary``.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from ..catalogue import Check, Owners, Target

SEVERITY = {"high": "critical", "medium": "warning", "low": "info"}  # muted -> None
RANK = {"info": 0, "warning": 1, "critical": 2}
CC_CLASSES = {"infra", "backup", "security"}
EMOJI = {"critical": ":red_circle:", "warning": ":large_orange_circle:", "info": ":white_circle:"}

# (severity, event) -> {channel: action}. Absent means nothing is sent at once; info
# incidents and warning e-mail travel in the digests (see digests.py).
TABLE: dict[tuple[str, str], dict[str, str]] = {
    ("critical", "open"): {"github": "open", "smtp": "mail", "slack": "post"},
    ("critical", "reminder"): {"github": "comment", "slack": "post"},
    ("critical", "escalate"): {"github": "comment", "smtp": "mail"},
    ("critical", "update"): {"github": "comment"},
    ("critical", "close"): {"github": "close", "smtp": "mail", "slack": "post"},
    ("critical", "retired"): {"github": "close", "smtp": "mail", "slack": "post"},
    ("critical", "flapping"): {"slack": "post"},
    ("warning", "open"): {"github": "open", "slack": "post"},
    ("warning", "update"): {"github": "comment"},
    ("warning", "close"): {"github": "close", "slack": "post"},
    ("warning", "retired"): {"github": "close", "slack": "post"},
    ("warning", "flapping"): {"slack": "post"},
}


# ---------------------------------------------------------------------- classification
def severity_of(target: Target, check: Check | None = None) -> str | None:
    """critical | warning | info, or None for muted (recorded, never sent)."""
    return SEVERITY.get((check.severity if check and check.severity else None)
                        or target.criticality)


def worst_severity(sevs: list[str]) -> str:
    return max(sevs, key=lambda s: RANK[s]) if sevs else "info"


# Classes whose incidents never become public GitHub issues: a missing backup or an
# exposed admin page is operational intelligence, not service status. E-mail and Slack
# only. Infrastructure targets follow their own ``public`` flag: the edge, DNS and TLS
# are visible from outside anyway, a degraded array or a Gluster heal is not.
PRIVATE_CLASSES = frozenset({"security", "backup"})


def is_private(target: Target, checks: list[Check]) -> bool:
    if target.class_ in PRIVATE_CLASSES or not target.public:
        return True
    # A security canary inside an ordinary target (aopsuite's "debugger stays off") must
    # not announce its own regression in public either.
    return any(c.public is False or c.kind == "security" for c in checks)


def _person(owners: Owners, handle: str) -> dict[str, Any]:
    return owners.people.get(handle) or {}


def notify_owners(target: Target, owners: Owners) -> list[str]:
    """Owners who agreed to be alerted, else the fallback."""
    on = [h for h in target.owners if _person(owners, h).get("notify") is True]
    return on or list(owners.fallback)


def infra_cc(owners: Owners) -> list[str]:
    """The infra cc list minus anyone who has said ``notify: false``."""
    return [h for h in owners.infra_cc if _person(owners, h).get("notify") is not False]


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def recipients(channel: str, event: str, target: Target, owners: Owners) -> list[str]:
    cc_class = target.class_ in CC_CLASSES
    if channel == "slack":
        return []
    if event == "escalate":
        return infra_cc(owners) or list(owners.fallback)
    if channel == "github":
        if event not in ("open", "reminder"):
            return []
        people = [h for h in notify_owners(target, owners)
                  if _person(owners, h).get("github", True) is not False]
        people = people or list(owners.fallback)
        return _dedupe(people + (infra_cc(owners) if cc_class else []))
    # smtp (critical only): owners (or fallback) plus the fallback (Marvin); the infra
    # cc only for infra, backup and security, as the plan's routing table says.
    to = _dedupe(notify_owners(target, owners) + list(owners.fallback))
    cc = [f"cc:{h}" for h in infra_cc(owners) if cc_class and h not in to]
    return to + cc


def routes(event: str, severity: str | None, target: Target, owners: Owners,
           private: bool = False) -> dict[str, list[str]]:
    """{channel: recipients} for one incident event. Empty when nothing goes out now."""
    if severity is None:
        return {}
    out = {}
    for channel in TABLE.get((severity, event), {}):
        if channel == "github" and private:
            continue
        out[channel] = recipients(channel, event, target, owners)
    return out


def digest_recipients(target: Target, owners: Owners) -> list[str]:
    """Daily/weekly digest readers: owners (or fallback), always the fallback, infra cc."""
    extra = infra_cc(owners) if target.class_ in CC_CLASSES else []
    return _dedupe(notify_owners(target, owners) + list(owners.fallback) + extra)


# ---------------------------------------------------------------------- texts
def duration(a: dt.datetime, b: dt.datetime) -> str:
    mins = max(0, int((b - a).total_seconds() // 60))
    d, rest = divmod(mins, 1440)
    h, m = divmod(rest, 60)
    if d:
        return f"{d} d {h} h"
    return f"{h} h {m} min" if h else f"{m} min"


def stamp(ts: dt.datetime) -> str:
    return ts.astimezone(dt.UTC).strftime("%Y-%m-%d %H:%M UTC")


def check_lines(checks: list[tuple[str, Check]]) -> list[str]:
    """One line per failing check, vantage points folded together."""
    by: dict[str, tuple[Check, list[str]]] = {}
    for pid, c in checks:
        via = pid.split("@", 1)[1] if "@" in pid else c.via[0]
        by.setdefault(c.id, (c, []))[1].append(via)
    return [f"{c.describe or c.id} (via {', '.join(sorted(vias))})"
            for c, vias in by.values()]


def render(channel: str, event: str, ctx: dict[str, Any]) -> dict[str, Any]:
    """Payload for one outbox row. ``ctx`` keys: key, target, checks [(pid, Check)],
    severity, since, now, opened_at, issue_number, blocked_names, private, recipients,
    private_url, public_url."""
    t: Target = ctx["target"]
    sev, private = ctx["severity"], ctx["private"]
    since, now = ctx["since"], ctx["now"]
    what = [] if private else check_lines(ctx["checks"])
    link = f"{ctx['private_url'].rstrip('/')}/incidents/{ctx['key']}"
    summary = t.public_summary or t.name
    word = {"open": "failing", "close": "recovered", "reminder": "still failing",
            "escalate": "unacknowledged", "update": "more checks failing",
            "flapping": "flapping", "retired": "no longer monitored"}[event]
    line = f"[{sev}] {t.name}: {word}"
    if event == "close":
        line += f" after {duration(ctx['opened_at'], now)}"

    if channel == "slack":
        icon = ":white_check_mark:" if event in ("close", "retired") else (
            ":repeat:" if event == "flapping" else EMOJI[sev])
        detail = summary if private or not what else "; ".join(what)
        if event == "flapping":
            detail = "results keep changing; quiet until it settles"
        return {"text": f"{icon} {line} - {detail}", "link": link, "line": line}

    body = [f"**{t.name}** ({sev}) has been failing since {stamp(since)}.", "", summary]
    if what:
        body += ["", "Failing checks:"] + [f"- {w}" for w in what]
    if ctx.get("blocked_names") and not private:
        body += ["", "Also affected (their alerts are held back): "
                 + ", ".join(ctx["blocked_names"])]
    body += ["", f"Details (TGX login): {link}"]
    if ctx.get("public_url"):
        body.append(f"Status page: {ctx['public_url']}")

    if channel == "smtp":
        subj = {"open": f"{sev.upper()}: {t.name} failing",
                "close": f"RESOLVED: {t.name} recovered after {duration(ctx['opened_at'], now)}",
                "retired": f"CLOSED: {t.name} no longer monitored",
                "escalate": f"ESCALATION: {t.name} failing, unacknowledged for "
                            f"{duration(ctx['opened_at'], now)}"}.get(event, line)
        text = "\n".join(body).replace("**", "")
        if event == "close":
            text = f"{t.name} recovered at {stamp(now)}.\n\n" + text
        elif event == "retired":
            text = (f"{t.name} is no longer monitored (removed from the catalogue) as of "
                    f"{stamp(now)}; the incident is closed without a recovery.\n\n" + text)
        return {"subject": "[tgx-monitor] " + subj, "text": text, "line": line}

    # github
    mentions = " ".join(f"@{h}" for h in ctx["recipients"])
    marker = f"<!-- tgxmon:incident={ctx['key']} -->"
    ids = sorted({c.id for _, c in ctx["checks"]})
    title = f"[{t.id}] " + (f"{ids[0]} failing" if len(ids) == 1
                            else f"{len(ids)} checks failing" if ids else "failing")
    out: dict[str, Any] = {"line": line, "key": ctx["key"]}
    if event == "open":
        full = "\n".join(body + ([f"\ncc {mentions}"] if mentions else []) + ["", marker])
        if ctx.get("issue_number"):
            out.update(action="reopen", comment=f"Failing again since {stamp(since)}."
                       + (f"\n\ncc {mentions}" if mentions else ""))
        else:
            out.update(action="open", title=title, body=full,
                       labels=["alert", f"sev:{sev}", f"target:{t.id}"])
        return out
    comment = {
        "reminder": f"Still failing after {duration(ctx['opened_at'], now)}.",
        "escalate": f"Open and unacknowledged for {duration(ctx['opened_at'], now)}; "
                    "escalating.",
        "update": "Now failing:\n" + "\n".join(f"- {w}" for w in what),
        "close": f"Recovered at {stamp(now)} after {duration(ctx['opened_at'], now)}.",
        "retired": f"No longer monitored as of {stamp(now)} (removed from the catalogue); "
                   "closing without a recovery.",
    }[event]
    if mentions:
        comment += f"\n\ncc {mentions}"
    out.update(action="close" if event in ("close", "retired") else "comment",
               comment=comment)
    return out


def channel_dead(channel: str, count: int) -> dict[str, dict[str, Any]]:
    """Self alert raised on the *other* channels when one channel dead-letters."""
    text = (f"tgx-monitor could not deliver {count} notification(s) via {channel} after "
            "8 attempts. They are listed as dead letters on the private outbox page.")
    line = f"[critical] tgx-monitor: delivery via {channel} failing"
    return {"smtp": {"subject": f"[tgx-monitor] CRITICAL: delivery via {channel} failing",
                     "text": text, "line": line},
            "slack": {"text": f":rotating_light: {line} - {count} dead letter(s)",
                      "line": line}}


def summary(rows: list[dict[str, Any]], channel: str) -> dict[str, Any]:
    """One message standing in for a burst (storm brake)."""
    lines = [r["payload"].get("line", r["event"]) for r in rows]
    head = f"{len(rows)} alerts in a burst, collapsed into one message"
    if channel == "slack":
        return {"text": f":warning: {head}:\n" + "\n".join(f"- {x}" for x in lines[:30]),
                "line": head}
    return {"subject": f"[tgx-monitor] {head}", "text": "\n".join(lines), "line": head}
