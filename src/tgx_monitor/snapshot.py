"""The public status snapshot, and the state and drawing helpers the private UI shares.

Why a static snapshot rather than a second live app: the public page must stay truthful
when the core is down. The core writes plain files every minute; a separate ``public``
service with no secrets and no database serves them. If the core stops, the page goes
on saying what was last known, with a "data as of" banner that ages visibly, and
``status.json`` tells the watchdogs how old the last cycle is.

What may reach these files is decided here and nowhere else: target and check names,
``public_summary``, ``describe``, window descriptions, a state word and day counts. No
evidence, outcomes, outbox payloads, notes or owners are ever read for it, and every
string that does go out passes :func:`public_text`, which withholds anything shaped
like an e-mail address, a host path or a non-node IP even if the catalogue let it in.

The swap is atomic: each build goes into a fresh ``snap-<stamp>/`` directory and the
``current`` symlink is replaced in one rename. Renaming a directory that a container
has bind-mounted would leave that container serving the old inode for ever, so the
public service mounts the parent and follows ``current`` per request.

Charts are inline SVG drawn here (no JavaScript, so the strict CSP holds and the page
archives in one piece); every bar and line carries a text equivalent.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

from .assertions import parse_duration
from .catalogue import ALLOWED_IPS, EMAIL_RE, IPV4_RE, Catalogue, Check, Target, Window
from .model import iso
from .store import Store

WEB = Path(__file__).parent / "web"
TEMPLATES = WEB / "templates"
STATIC = WEB / "static"
KEEP_SNAPSHOTS = 2  # the live one and the previous, for requests still in flight

# Target-level states shown to people: word + glyph, so colour is never the only cue.
STATES: dict[str, dict[str, str]] = {
    "operational": {"word": "Operational", "glyph": "✓"},
    "degraded": {"word": "Degraded", "glyph": "⚠"},
    "down": {"word": "Down", "glyph": "✕"},
    "maintenance": {"word": "Maintenance", "glyph": "⏸"},
    "unknown": {"word": "Unknown", "glyph": "?"},
}
# Per-probe class -> the target-level state word it is shown with.
CLASS_STATE = {"ok": "operational", "warn": "degraded", "fail": "down",
               "maint": "maintenance", "unknown": "unknown"}
SEVERITY_WORD = {"high": "critical", "critical": "critical", "medium": "warning",
                 "warning": "warning", "low": "info", "info": "info"}

_HOSTPATH = re.compile(r"(?:/mnt/|/home/|/var/run/|/run/secrets)\S*")


def jinja_env() -> Environment:
    """One template environment for both UIs. Autoescape on for every template."""
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True,
                      trim_blocks=True, lstrip_blocks=True)
    env.globals.update(STATES=STATES, CLASS_STATE=CLASS_STATE)
    return env


def public_text(text: str | None) -> str:
    """Withhold e-mail addresses, host paths and stray IPs from a public string."""
    if not text:
        return ""
    t = EMAIL_RE.sub("[withheld]", str(text))
    t = _HOSTPATH.sub("[withheld]", t)
    return IPV4_RE.sub(lambda m: m.group(0) if m.group(0) in ALLOWED_IPS else "[withheld]", t)


def parse_ts(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        ts = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.UTC)


# --------------------------------------------------------------------------- state
def enabled_probes(t: Target, public_only: bool = False) -> list[tuple[str, str, Check]]:
    out = []
    for c in t.checks:
        if not c.enabled or (public_only and not is_public(t, c)):
            continue
        out += [(pid, via, c) for pid, via in c.probe_ids()]
    return out


def is_public(t: Target, c: Check | None = None) -> bool:
    """What the public status page may show: services and data, never infrastructure,
    backups or security canaries (a red canary would say where the hole is)."""
    from .alerts.router import PRIVATE_CLASSES

    if not t.public or t.class_ in PRIVATE_CLASSES:
        return False
    if c is None:
        return True
    if c.kind == "security":
        return False
    return c.public if c.public is not None else True


def probe_views(store: Store, probe_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """probe_id -> its alert-engine state row plus the latest result, and a class."""
    states = {r["probe_id"]: r for r in store.query("SELECT * FROM probe_state")}
    out: dict[str, dict[str, Any]] = {}
    cols = "id, status, warn, started_at, summary, duration_ms, config_sha"
    for pid in probe_ids:
        st = states.get(pid, {})
        last = None
        if st.get("last_result_id"):
            last = store.one(f"SELECT {cols} FROM results WHERE id=?", (st["last_result_id"],))
        if last is None:
            last = store.one(f"SELECT {cols} FROM results WHERE probe_id=? "
                             "ORDER BY started_at DESC LIMIT 1", (pid,))
        view = {**st, "probe_id": pid, "state": str(st.get("state") or "UNKNOWN").upper(),
                "last": last}
        view["cls"] = classify(view)
        out[pid] = view
    return out


def classify(view: dict[str, Any]) -> str:
    """ok | warn | fail | unknown | maint for one probe.

    The alert engine's state wins where it exists (it has seen the consecutive-failure
    threshold); without it, a single failed result counts as a warning, not as down.
    """
    s = view.get("state", "UNKNOWN")
    last = view.get("last") or {}
    status = last.get("status")
    if s == "MAINTENANCE":
        return "maint"
    if s in ("FAILING", "FLAPPING"):
        return "fail"
    if s in ("BLOCKED", "SILENCED", "KNOWN_ISSUE"):
        return {"failed": "fail", "ok": "ok"}.get(status or "", "unknown")
    if s == "PENDING" or status == "failed":
        return "warn"
    if status == "ok":
        return "warn" if last.get("warn") else "ok"
    return "unknown"


def target_state(classes: list[str], window_active: bool = False) -> str:
    if window_active or "maint" in classes:
        return "maintenance"
    judged = [c for c in classes if c in ("ok", "warn", "fail")]
    if not judged:
        return "unknown"
    if all(c == "fail" for c in judged):
        return "down"
    if any(c in ("fail", "warn") for c in judged):
        return "degraded"
    return "operational"


def target_states(store: Store, cat: Catalogue, now: dt.datetime,
                  public_only: bool = False) -> dict[str, dict[str, Any]]:
    """target id -> {state, probes: [view], window}. Only public targets if asked."""
    targets = [t for t in cat.targets.values() if not public_only or is_public(t)]
    pids = [pid for t in targets for pid, _, _ in enabled_probes(t, public_only)]
    views = probe_views(store, pids)
    out = {}
    for t in targets:
        tv = [views[pid] for pid, _, _ in enabled_probes(t, public_only)]
        win = active_window(cat, t, now)
        out[t.id] = {"state": target_state([v["cls"] for v in tv], win is not None),
                     "probes": tv, "window": win}
    return out



# --------------------------------------------------------------------------- windows
_DAYS = ("MO", "TU", "WE", "TH", "FR", "SA", "SU")


def occurrences(w: Window, start: dt.datetime, end: dt.datetime) -> list[tuple[dt.datetime,
                                                                                dt.datetime]]:
    """Occurrences of window ``w`` overlapping [start, end).

    Uses the alert engine's RRULE code (``alerts.windows``) when it is importable, so the
    page and the engine agree on when a window is open; otherwise a fallback covering
    the subset maintenance.yaml uses (DAILY, WEEKLY;BYDAY, MONTHLY;BYMONTHDAY).
    """
    try:
        from .alerts import windows as wmod

        length = dt.timedelta(seconds=parse_duration(w.duration))
        cur = wmod.active(w, start)
        out = [cur] if cur else []
        t = start
        while (s := wmod.next_start(w, t, horizon_days=(end - t).days + 2)) and s < end:
            out.append((s, s + length))
            t = s
        return out
    except Exception:  # noqa: BLE001 - absent or rejecting the rule: fall back
        pass
    try:
        rule = dict(p.split("=", 1) for p in w.rrule.upper().split(";") if "=" in p)
        dur = dt.timedelta(seconds=parse_duration(w.duration))
        hh, mm = (int(x) for x in w.start.split(":"))
    except ValueError:
        return []
    out = []
    day = (start - dur).date()
    while day <= end.date():
        if _rule_matches(rule, day):
            s = dt.datetime(day.year, day.month, day.day, hh, mm, tzinfo=dt.UTC)
            if s < end and s + dur > start:
                out.append((s, s + dur))
        day += dt.timedelta(days=1)
    return out


def _rule_matches(rule: dict[str, str], day: dt.date) -> bool:
    freq = rule.get("FREQ")
    if freq == "DAILY":
        return True
    if freq == "WEEKLY":
        return _DAYS[day.weekday()] in rule.get("BYDAY", "").split(",")
    if freq == "MONTHLY":
        return str(day.day) in rule.get("BYMONTHDAY", "").split(",")
    return False


def active_window(cat: Catalogue, t: Target, now: dt.datetime) -> Window | None:
    for wid in t.maintenance:
        w = cat.windows.get(wid)
        if w and occurrences(w, now, now + dt.timedelta(seconds=1)):
            return w
    return None


def upcoming_windows(cat: Catalogue, targets: list[Target], now: dt.datetime,
                     days: int = 14) -> list[dict[str, Any]]:
    by_window: dict[str, list[Target]] = {}
    for t in targets:
        for wid in t.maintenance:
            by_window.setdefault(wid, []).append(t)
    rows = []
    for wid, ts in by_window.items():
        w = cat.windows.get(wid)
        if w is None:
            continue
        for s, e in occurrences(w, now, now + dt.timedelta(days=days))[:3]:
            rows.append({"start": s, "end": e, "describe": w.describe, "targets": ts})
    return sorted(rows, key=lambda r: r["start"])


# --------------------------------------------------------------------------- numbers
def daily_uptime(store: Store, probe_ids: list[str], now: dt.datetime,
                 days: int = 90) -> list[dict[str, Any]]:
    """One row per day, oldest first: ok/failed counts across the probes, None = no data."""
    first = (now - dt.timedelta(days=days - 1)).date()
    agg: dict[str, dict[str, int]] = {}
    if probe_ids:
        marks = ",".join("?" * len(probe_ids))
        for r in store.query(
                f"SELECT day, SUM(ok) AS ok, SUM(failed) AS failed, SUM(n) AS n FROM rollup_daily "
                f"WHERE probe_id IN ({marks}) AND day >= ? GROUP BY day",
                [*probe_ids, first.isoformat()]):
            agg[r["day"]] = r
    out = []
    for i in range(days):
        d = (first + dt.timedelta(days=i)).isoformat()
        r = agg.get(d)
        judged = (r["ok"] or 0) + (r["failed"] or 0) if r else 0
        pct = 100.0 * (r["ok"] or 0) / judged if r and judged else None
        out.append({"day": d, "pct": pct, "n": int(r["n"] or 0) if r else 0})
    return out


def uptime_pct(days: list[dict[str, Any]]) -> float | None:
    vals = [d["pct"] for d in days if d["pct"] is not None]
    return sum(vals) / len(vals) if vals else None


def _bar_class(pct: float | None) -> tuple[str, str]:
    if pct is None:
        return "none", "no data"
    if pct >= 99.5:
        return "ok", "operational"
    if pct >= 95:
        return "warn", "degraded"
    return "down", "major outage"


def uptime_svg(days: list[dict[str, Any]], label: str) -> Markup:
    """90 thin bars. Height as well as colour carries the state; each has a <title>."""
    heights = {"ok": 30, "warn": 22, "down": 14, "none": 6}
    parts = []
    for i, d in enumerate(days):
        cls, word = _bar_class(d["pct"])
        h = heights[cls]
        pct = "–" if d["pct"] is None else f"{d['pct']:.2f}%"
        parts.append(f'<rect class="bar bar--{cls}" x="{i * 4}" y="{30 - h}" width="3" '
                     f'height="{h}" rx="1"><title>{escape(d["day"])}: {escape(word)}, '
                     f'{pct}</title></rect>')
    overall = uptime_pct(days)
    summary = (f"{label}: {overall:.2f}% available over {len(days)} days" if overall is not None
               else f"{label}: no data yet")
    return Markup(f'<svg class="bars" viewBox="0 0 {len(days) * 4} 30" role="img" '
                  f'aria-label="{escape(summary)}" preserveAspectRatio="none">'
                  f'{"".join(parts)}</svg>')


def sparkline_svg(points: list[tuple[str, float]], label: str, unit: str = "") -> Markup:
    """A line for the main metric of a check, with min/last/max stated in the label."""
    if len(points) < 2:
        return Markup('<p class="muted">Not enough history to draw yet.</p>')
    w, h, pad = 600, 80, 4
    vals = [v for _, v in points]
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1.0
    step = (w - 2 * pad) / (len(vals) - 1)
    xy = " ".join(f"{pad + i * step:.1f},{h - pad - (v - lo) / span * (h - 2 * pad):.1f}"
                  for i, v in enumerate(vals))
    desc = (f"{label}: {len(vals)} points from {points[0][0]} to {points[-1][0]}; "
            f"min {lo:g}{unit}, max {hi:g}{unit}, last {vals[-1]:g}{unit}")
    return Markup(f'<svg class="spark" viewBox="0 0 {w} {h}" role="img" '
                  f'aria-label="{escape(desc)}" preserveAspectRatio="none">'
                  f'<polyline class="spark__line" points="{xy}"/></svg>'
                  f'<p class="muted small">{escape(desc)}</p>')


def outbox_oldest_age_s(store: Store, now: dt.datetime) -> float:
    row = store.one("SELECT MIN(created_at) AS t FROM outbox WHERE sent_at IS NULL AND dead=0")
    ts = parse_ts(row["t"] if row else None)
    return round(max(0.0, (now - ts).total_seconds()), 1) if ts else 0.0


def status_doc(store: Store, cat: Catalogue, now: dt.datetime, public_only: bool = True,
               states: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """What the watchdogs read: freshness of the loop and of the outbox, plus states."""
    states = states if states is not None else target_states(store, cat, now, public_only)
    return {
        "generated_at": iso(now),
        "last_cycle_at": store.get_meta("last_tick"),
        "outbox_oldest_age_s": outbox_oldest_age_s(store, now),
        "targets": [{"id": tid, "name": public_text(cat.targets[tid].name),
                     "group": public_text(cat.targets[tid].group), "state": s["state"]}
                    for tid, s in states.items()],
    }


# --------------------------------------------------------------------------- public build
def _public_model(store: Store, cat: Catalogue, now: dt.datetime) -> dict[str, Any]:
    states = target_states(store, cat, now, public_only=True)
    targets = [cat.targets[tid] for tid in states]
    rows = []
    for t in targets:
        pids = [pid for pid, _, _ in enabled_probes(t, public_only=True)]
        days = daily_uptime(store, pids, now)
        checks = [public_text(c.describe) for c in t.checks
                  if c.enabled and is_public(t, c) and c.describe]
        rows.append({
            "id": t.id, "name": public_text(t.name), "group": public_text(t.group),
            "summary": public_text(t.public_summary), "state": states[t.id]["state"],
            "uptime": uptime_pct(days), "bars": uptime_svg(days, public_text(t.name)),
            "checks": checks,
            "links": [public_text(u) for u in t.links if u.startswith("https://")],
        })
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in sorted(rows, key=lambda r: (r["group"].lower(), r["name"].lower())):
        groups.setdefault(r["group"], []).append(r)
    ids = {t.id for t in targets}
    incidents = [
        {"target": public_text(cat.targets[i["target_id"]].name), "target_id": i["target_id"],
         "summary": public_text(cat.targets[i["target_id"]].public_summary),
         "severity": SEVERITY_WORD.get(str(i["severity"]).lower(), "warning"),
         "opened_at": i["opened_at"]}
        for i in store.query("SELECT target_id, severity, opened_at FROM incidents "
                             "WHERE closed_at IS NULL AND private=0 ORDER BY opened_at")
        if i["target_id"] in ids]
    windows = [{"start": w["start"], "end": w["end"], "describe": public_text(w["describe"]),
                "targets": [public_text(t.name) for t in w["targets"]]}
               for w in upcoming_windows(cat, targets, now)]
    tick = parse_ts(store.get_meta("last_tick"))
    age = (now - tick).total_seconds() if tick else None
    return {"groups": groups, "rows": rows, "incidents": incidents, "windows": windows,
            "now": now, "tick": tick, "stale": age is None or age > 600,
            "doc": status_doc(store, cat, now, True, states)}


def build_public(store: Store, catalogue: Catalogue, out_dir: Path | str,
                 now: dt.datetime) -> Path:
    """Render the public site into ``out_dir/snap-<stamp>`` and point ``current`` at it."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    model = _public_model(store, catalogue, now)
    env = jinja_env()
    stamp = now.strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}-{now.microsecond:06d}"
    snap = out / f"snap-{stamp}"
    tmp = out / f".tmp-{stamp}"
    shutil.rmtree(tmp, ignore_errors=True)
    (tmp / "target").mkdir(parents=True)
    shutil.copytree(STATIC, tmp / "static")
    common = {"m": model, "site_name": "TGX status"}
    (tmp / "index.html").write_text(
        env.get_template("public_index.html").render(root="", title="Service status", **common))
    for r in model["rows"]:
        (tmp / "target" / f"{r['id']}.html").write_text(
            env.get_template("public_target.html").render(root="../", title=r["name"], t=r,
                                                          **common))
    (tmp / "status.json").write_text(json.dumps(model["doc"], indent=1))
    tmp.rename(snap)
    link_tmp = out / f".current-{stamp}"
    link_tmp.symlink_to(snap.name)
    link_tmp.replace(out / "current")
    _prune(out, keep=snap.name)
    return snap


def _prune(out: Path, keep: str) -> None:
    snaps = sorted(p for p in out.glob("snap-*") if p.is_dir())
    for p in snaps[:-KEEP_SNAPSHOTS]:
        if p.name != keep:
            shutil.rmtree(p, ignore_errors=True)
    for p in out.glob(".tmp-*"):
        shutil.rmtree(p, ignore_errors=True)
