"""The private UI, served by core at monitor.bigcat-bioinformatics.org.

Deny by default: :class:`Gate` sends every request without a session to the login page,
except ``/livez`` (the swarm healthcheck), ``/login``, the static assets and
``/api/push/<job>`` (bearer token per job, and refused when it carries
``X-Forwarded-For``: cron scripts reach the core over the overlay network, and a push
that came through Traefik is somebody else).

The pages answer one question each. The overview says what is red; ``/check/<probe>``
says *why*, in the order a person debugging it asks: what is checked and how to repeat
it by hand (a copyable curl), which assertion broke and by how much, since when, whether
an ancestor or a window explains it, who was told, and what the target actually sent
back. Pages render from the database in a worker thread, so a slow page never stalls
the scheduler that shares this event loop.

The core wires it as::

    app = create_private_app(store, catalogue, settings=WebSettings())
    app.state.catalogue = new_catalogue          # after a reload
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import yaml
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .. import snapshot as S
from ..assertions import parse_duration
from ..catalogue import Catalogue, Check, Target
from ..http import NODES
from ..model import iso, utcnow
from ..redact import redact_text
from ..secrets import read_secret_json
from ..store import Store
from . import auth, github_login

log = logging.getLogger("tgx_monitor.web")

BACKUP_KINDS = {"file_age", "sqlite_backup", "restore_marker"}
NODE_KINDS = {"host", "swarm"}
EVIDENCE_CAP = 65536
_JOB_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_SECRET_NAME = re.compile(r"(?i)(auth|cookie|token|secret|pass|key|credential)")
NAV = [("/", "Overview"), ("/incidents", "Incidents"), ("/outbox", "Outbox"),
       ("/silences", "Silences"), ("/known-issues", "Known issues"),
       ("/catalogue", "Catalogue"), ("/cron", "Cron"), ("/backups", "Backups"),
       ("/nodes", "Nodes"), ("/test-alert", "Test alert")]


@dataclass
class WebSettings:
    secrets_dir: Path | None = None  # None: TGXMON_SECRETS_DIR or /run/secrets
    secure_cookies: bool = True  # False only for a local http tunnel
    base_url: str = ""  # the private UI's public https address (messages, OAuth callback)
    gh_client_id: str = ""  # GitHub App client id for "Sign in with GitHub" (not secret)
    gh_transport: Any = None  # httpx transport override (tests)
    password_login: bool = True  # TGXMON_PASSWORD_LOGIN=0: GitHub sign-in only
    max_tick_age_s: float = 180.0
    push_max_bytes: int = 65536
    now: Callable[[], dt.datetime] = utcnow


# --------------------------------------------------------------------------- plumbing
class Gate(BaseHTTPMiddleware):
    """Session loading and the deny-by-default rule."""

    OPEN = ("/livez", "/login", "/login/github", "/login/github/callback")

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        st = request.app.state
        path = request.url.path
        sess = st.sessions.load(request.cookies.get(auth.SESSION_COOKIE))
        if sess and sess.get("u") and not await run_in_threadpool(
                auth.session_current, sess, st.settings.secrets_dir):
            sess = None  # user removed or password changed since this session began
        request.state.had_session = sess is not None
        fresh = sess is None and path.startswith("/login") and st.sessions.enabled
        if fresh:
            sess = {"csrf": auth.new_csrf()}
        request.state.session = sess or {}
        handle = (sess or {}).get("u")
        request.state.role = auth.role_for(handle, st.catalogue) if handle else None
        open_ = (path in self.OPEN or path.startswith("/static/")
                 or path.startswith("/api/push/"))
        if not open_ and request.state.role is None:
            if request.method in ("GET", "HEAD"):
                return RedirectResponse(f"/login?next={quote(path)}", status_code=303)
            return PlainTextResponse("login required", status_code=401)
        response = await call_next(request)
        new = getattr(request.state, "new_session", None)
        if new == {}:
            response.delete_cookie(auth.SESSION_COOKIE, path="/")
        elif new is not None or fresh:
            response.set_cookie(auth.SESSION_COOKIE, st.sessions.dump(new or sess),
                                max_age=auth.SESSION_MAX_AGE, httponly=True,
                                secure=st.settings.secure_cookies, samesite="lax", path="/")
        return response


async def _form(request: Request) -> dict[str, str]:
    """Parse a POST form and enforce its CSRF token."""
    form = await request.form()
    if not auth.csrf_ok(request.state.session, str(form.get("csrf", ""))):
        raise HTTPException(403, "CSRF token missing or wrong")
    return {k: str(v) for k, v in form.items()}


def _page(request: Request, template: str, status: int = 200, **ctx: Any) -> HTMLResponse:
    st = request.app.state
    tick = S.parse_ts(st.store.get_meta("last_tick"))
    now = st.settings.now()
    html = st.env.get_template(template).render(
        root="/", nav=NAV, path=request.url.path, role=request.state.role,
        csrf=request.state.session.get("csrf", ""), sha=st.catalogue.sha, now=now,
        tick_age=(now - tick).total_seconds() if tick else None, site_name="TGX monitor",
        **ctx)
    return HTMLResponse(html, status_code=status)


async def _data(request: Request, fn: Callable[..., Any], *args: Any) -> Any:
    st = request.app.state
    return await run_in_threadpool(fn, st.store, st.catalogue, st.settings.now(), *args)


def _not_found(request: Request, what: str) -> HTMLResponse:
    return _page(request, "message.html", status=404, title="Not found",
                 message=f"No {what} with that id.")


# --------------------------------------------------------------------------- data
def _overview(store: Store, cat: Catalogue, now: dt.datetime) -> dict[str, Any]:
    states = S.target_states(store, cat, now)
    groups: dict[str, list[dict[str, Any]]] = {}
    for t in sorted(cat.targets.values(), key=lambda t: (t.group.lower(), t.name.lower())):
        s = states[t.id]
        bad = [v for v in s["probes"] if v["cls"] not in ("ok",)]
        groups.setdefault(t.group, []).append({"t": t, "state": s["state"], "bad": bad,
                                               "n": len(s["probes"])})
    counts: dict[str, int] = {}
    for s in states.values():
        counts[s["state"]] = counts.get(s["state"], 0) + 1
    return {"groups": groups, "counts": counts, "incidents": _open_incidents(store),
            "problems": len(cat.problems)}


def _open_incidents(store: Store) -> list[dict[str, Any]]:
    rows = store.query("SELECT * FROM incidents WHERE closed_at IS NULL ORDER BY opened_at DESC")
    for r in rows:
        r["failing"] = _json(r.get("failing"), [])
        r["blocked"] = _json(r.get("blocked"), [])
    return rows


def _json(raw: Any, default: Any) -> Any:
    try:
        return json.loads(raw) if raw else default
    except (TypeError, ValueError):
        return default


def _target(store: Store, cat: Catalogue, now: dt.datetime, tid: str) -> dict[str, Any]:
    t = cat.targets[tid]
    s = S.target_states(store, cat, now)
    probes = []
    for c in t.checks:
        for pid, via in c.probe_ids():
            v = next((p for p in s[tid]["probes"] if p["probe_id"] == pid), None)
            probes.append({"pid": pid, "via": via, "check": c, "view": v})
    people = cat.owners.people if cat.owners else {}
    return {"t": t, "state": s[tid]["state"], "window": s[tid]["window"], "probes": probes,
            "owners": [(h, people.get(h, {}).get("name", h)) for h in t.owners],
            "ancestors": [(a, s[a]["state"] if a in s else "unknown") for a in cat.ancestors(tid)],
            "incidents": store.query("SELECT * FROM incidents WHERE target_id=? "
                                     "ORDER BY opened_at DESC LIMIT 10", (tid,))}


def _probe(cat: Catalogue, pid: str) -> tuple[str, Target, Check] | None:
    for p, via, t, c in cat.probes():
        if p == pid:
            return via, t, c
    for t in cat.targets.values():  # disabled checks still have a page
        for c in t.checks:
            for p, via in c.probe_ids():
                if p == pid:
                    return via, t, c
    return None


def _check(store: Store, cat: Catalogue, now: dt.datetime, pid: str) -> dict[str, Any]:
    via, t, c = _probe(cat, pid)  # type: ignore[misc]
    view = S.probe_views(store, [pid])[pid]
    states = S.target_states(store, cat, now)
    last = store.one("SELECT * FROM results WHERE probe_id=? ORDER BY started_at DESC LIMIT 1",
                     (pid,))
    if last:
        last["outcomes"] = _json(last.get("outcomes"), [])
        last["calls"] = _json(last.get("calls"), [])
    ev = store.one("SELECT r.id, r.started_at, e.body FROM results r JOIN evidence e "
                   "ON e.result_id = r.id WHERE r.probe_id=? ORDER BY r.started_at DESC LIMIT 1",
                   (pid,))
    ancestors = [(a, states.get(a, {}).get("state", "unknown")) for a in cat.ancestors(t.id)]
    incidents = store.query("SELECT * FROM incidents WHERE target_id=? ORDER BY opened_at DESC "
                            "LIMIT 5", (t.id,))
    deliveries = []
    if incidents:
        ids = [i["id"] for i in incidents]
        deliveries = store.query(
            f"SELECT * FROM outbox WHERE incident_id IN ({','.join('?' * len(ids))}) "
            "ORDER BY created_at DESC LIMIT 50", ids)
        for d in deliveries:
            d["reply"] = redact_text(d.get("reply") or "", 300)
    metric = _main_metric(store, c, pid, now)
    win = S.active_window(cat, t, now)
    nxt = [o for w in t.maintenance if w in cat.windows
           for o in S.occurrences(cat.windows[w], now, now + dt.timedelta(days=14))[:1]]
    return {
        "pid": pid, "via": via, "t": t, "c": c, "view": view, "last": last,
        "definition": redact_text(yaml.safe_dump(_redacted_check(c), sort_keys=False,
                                                 allow_unicode=True)),
        "curl": curl_for(c, via, cat),
        "evidence": ({**ev, "body": redact_text(ev["body"] or "", EVIDENCE_CAP)} if ev else None),
        "ancestors": ancestors,
        "blockers": [a for a, s in ancestors if s in ("down", "degraded")],
        "window": win, "next_window": min(nxt) if nxt else None,
        "silences": store.query(
            "SELECT * FROM silences WHERE target_id=? AND (check_id IS NULL OR check_id=?) "
            "AND until > ? ORDER BY until", (t.id, c.id, iso(now))),
        "known": [k for k in cat.known if k.target == t.id and k.check in (None, c.id)],
        "incidents": incidents, "deliveries": deliveries, "metric": metric,
        "history": store.query("SELECT id, status, warn, started_at, duration_ms, summary "
                               "FROM results WHERE probe_id=? ORDER BY started_at DESC LIMIT 30",
                               (pid,)),
    }


def _main_metric(store: Store, c: Check, pid: str, now: dt.datetime) -> dict[str, Any]:
    """The first asserted number that has history, else latency."""
    paths = [a.get("that") for a in c.assert_ if a.get("that") and a.get("that") != "latency_ms"]
    since = iso(now - dt.timedelta(days=7))
    for path in [*paths, "latency_ms"]:
        rows = store.query("SELECT ts, value FROM metrics WHERE probe_id=? AND path=? AND ts>=? "
                           "ORDER BY ts DESC LIMIT 300", (pid, path, since))
        if rows:
            pts = [(r["ts"], float(r["value"])) for r in reversed(rows)]
            unit = " ms" if path == "latency_ms" else ""
            return {"path": path, "svg": S.sparkline_svg(pts, path, unit)}
    return {"path": None, "svg": None}


def _redacted_check(c: Check) -> dict[str, Any]:
    d = c.model_dump(by_alias=True, exclude_defaults=True)
    req = d.get("request") or {}
    for k in ("headers", "params", "data"):
        if isinstance(req.get(k), dict):
            req[k] = {hk: "[redacted]" if _SECRET_NAME.search(hk) else hv
                      for hk, hv in req[k].items()}
    return d


def curl_for(c: Check, via: str, cat: Catalogue) -> str | None:
    """A command that repeats an http or sparql check by hand, secrets redacted."""
    r = c.request
    args = ["curl", "-sS", "-i", "--max-time", f"{c.timeout_s:g}"]
    if c.kind == "http" and "url" in r:
        url, method = str(r["url"]), str(r.get("method", "GET")).upper()
        if method != "GET":
            args += ["-X", method]
        if r.get("follow", True):
            args.append("-L")
        if r.get("verify", True) is False:
            args.append("-k")
        for k, v in (r.get("headers") or {}).items():
            args += ["-H", f"{k}: {'[redacted]' if _SECRET_NAME.search(k) else v}"]
        if r.get("params"):
            url += ("&" if "?" in url else "?") + urlencode(r["params"])
        if "json" in r:
            args += ["-H", "Content-Type: application/json", "--data", json.dumps(r["json"])]
        elif isinstance(r.get("data"), dict):
            args += ["--data", urlencode(r["data"])]
        elif r.get("data"):
            args += ["--data", str(r["data"])]
    elif c.kind == "sparql" and "endpoint" in r:
        url = str(r["endpoint"])
        try:
            query = cat.query_text(r["file"]) if "file" in r else (r.get("ask") or r.get("select"))
        except (OSError, ValueError):
            query = f"<query file {r.get('file')} not readable>"
        args += ["-H", "Accept: application/sparql-results+json"]
        if str(r.get("method", "GET")).upper() != "POST":
            args.append("-G")
        args += ["--data-urlencode", f"query={query}"]
    else:
        return None
    if via in NODES:
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        args += ["--resolve", f"{parts.hostname}:{port}:{NODES[via]}"]
    args.append(url)
    return redact_text(" ".join(shlex.quote(a) for a in args), 8000)


def _results_for(store: Store, cat: Catalogue, now: dt.datetime,
                 pick: Callable[[Target, Check], bool]) -> list[dict[str, Any]]:
    probes = [(pid, via, t, c) for t in cat.targets.values() for c in t.checks if pick(t, c)
              for pid, via in c.probe_ids()]
    views = S.probe_views(store, [p[0] for p in probes])
    rows = []
    for pid, via, t, c in probes:
        last = views[pid]["last"]
        outcomes = []
        if last:
            full = store.one("SELECT outcomes FROM results WHERE id=?", (last["id"],))
            outcomes = _json(full and full["outcomes"], [])
        rows.append({"pid": pid, "via": via, "t": t, "c": c, "view": views[pid],
                     "outcomes": outcomes})
    return rows


def _incidents(store: Store, cat: Catalogue, now: dt.datetime) -> dict[str, Any]:
    closed = store.query("SELECT * FROM incidents WHERE closed_at IS NOT NULL AND closed_at >= ? "
                         "ORDER BY opened_at DESC LIMIT 200", (iso(now - dt.timedelta(days=30)),))
    for r in closed:
        r["failing"] = _json(r.get("failing"), [])
        r["blocked"] = _json(r.get("blocked"), [])
    return {"open": _open_incidents(store), "closed": closed}


def _outbox(store: Store, cat: Catalogue, now: dt.datetime) -> dict[str, Any]:
    q = "SELECT * FROM outbox WHERE {} ORDER BY created_at DESC LIMIT 100"
    out = {"pending": store.query(q.format("sent_at IS NULL AND dead=0")),
           "dead": store.query(q.format("dead=1")),
           "sent": store.query(q.format("sent_at IS NOT NULL AND dead=0"))}
    for rows in out.values():
        for r in rows:
            r["reply"] = redact_text(r.get("reply") or "", 300)
            r["recipients"] = _json(r.get("recipients"), [])
            r["payload"] = redact_text(r.get("payload") or "", 2000)
    return out


def _silences(store: Store, cat: Catalogue, now: dt.datetime) -> dict[str, Any]:
    return {"active": store.query("SELECT * FROM silences WHERE until > ? ORDER BY until",
                                  (iso(now),)),
            "recent": store.query("SELECT * FROM silences WHERE until <= ? ORDER BY until DESC "
                                  "LIMIT 20", (iso(now),))}


def _cron(store: Store, cat: Catalogue, now: dt.datetime) -> dict[str, Any]:
    rows = store.query("SELECT * FROM job_runs WHERE COALESCE(started_at, scheduled_at) >= ? "
                       "ORDER BY COALESCE(started_at, scheduled_at) DESC LIMIT 1000",
                       (iso(now - dt.timedelta(days=14)),))
    jobs: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        r["log_tail"] = redact_text(r.get("log_tail") or "", 2000)
        jobs.setdefault(r["job"], []).append(r)
    return {"jobs": dict(sorted(jobs.items()))}


def _catalogue_view(store: Store, cat: Catalogue, now: dt.datetime) -> dict[str, Any]:
    try:
        from ..kinds import KINDS

        problems = cat.validate(known_kinds=set(KINDS))
    except Exception as exc:  # noqa: BLE001 - the page must render even then
        problems = [f"validation crashed: {type(exc).__name__}: {exc}"]
    return {"problems": problems,
            "targets": sorted(cat.targets.values(), key=lambda t: (t.group.lower(), t.id)),
            "windows": list(cat.windows.values())}


def parse_until(text: str, now: dt.datetime) -> dt.datetime:
    """'2h' / '3d' or an ISO date-time (UTC); at most 30 days ahead."""
    text = text.strip()
    try:
        until = now + dt.timedelta(seconds=parse_duration(text))
    except ValueError:
        until = S.parse_ts(text) or now
    if until <= now:
        raise ValueError("until must be in the future")
    if until > now + dt.timedelta(days=30):
        raise ValueError("a silence may last at most 30 days; use known_issues.yaml for longer")
    return until


# --------------------------------------------------------------------------- routes
async def livez(request: Request) -> Response:
    st = request.app.state
    tick = S.parse_ts(st.store.get_meta("last_tick"))
    age = (st.settings.now() - tick).total_seconds() if tick else None
    if age is not None and age < st.settings.max_tick_age_s:
        return PlainTextResponse("ok")
    return PlainTextResponse("stale", status_code=503)


async def login(request: Request) -> Response:
    st = request.app.state
    nxt = request.query_params.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        nxt = "/"
    if request.method == "GET":
        return login_page(request, None)
    if not st.sessions.enabled:
        return login_page(request, "Login is disabled: no session key is configured.", 503)
    if not st.settings.password_login:
        return login_page(request, "Password login is switched off: sign in with GitHub.",
                          403)
    raw = await request.form()
    if not auth.csrf_ok(request.state.session, str(raw.get("csrf", ""))):
        # Not an attack worth a bare 403: almost always a browser that did not send the
        # session cookie back (plain http or an SSH tunnel to a Secure cookie, cookies
        # blocked) or a login page left open across a logout. Show a fresh form (the Gate
        # has just set a new cookie) and say what to check.
        why = ("Your browser did not send the login cookie back. Open this page over "
               f"https ({st.settings.base_url or 'the monitor address'}) rather than "
               "plain http or a tunnel, allow cookies for this site, and try again."
               if not request.state.had_session else
               "This login form had expired. Please try again.")
        return login_page(request, why, 400)
    form = {k: str(v) for k, v in raw.items()}
    user = form.get("username", "").strip()[:64]
    password = form.get("password", "")
    ip = auth.client_ip(request.scope)
    # The per-account limit ignores the address: core also sits on the shared overlay,
    # where a caller could rotate X-Forwarded-For around the per-address limits.
    if (not st.login_ip_limiter.hit(ip) or not st.login_limiter.hit(f"{ip}|{user.lower()}")
            or not st.login_user_limiter.hit(user.lower())):
        return login_page(request, "Too many attempts. Wait a minute and try again.", 429)
    ok = False
    if len(password) <= auth.MAX_PASSWORD:
        async with st.login_slots:
            ok = await run_in_threadpool(auth.verify_password, user, password,
                                         st.settings.secrets_dir)
    if not ok:
        return login_page(request, "Wrong username or password.", 401)
    fp = await run_in_threadpool(auth.user_fingerprint, user, st.settings.secrets_dir)
    request.state.new_session = {"u": user, "fp": fp, "csrf": auth.new_csrf()}
    await run_in_threadpool(st.store.audit, user, "login", ip)
    return RedirectResponse(nxt, status_code=303)


def login_page(request: Request, error: str | None, status: int = 200) -> HTMLResponse:
    st = request.app.state
    nxt = request.query_params.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        nxt = "/"
    return _page(request, "login.html", status, title="Log in", next=nxt, error=error,
                 disabled=not st.sessions.enabled,
                 github=github_login.configured(st.settings),
                 password=st.settings.password_login)


async def logout(request: Request) -> Response:
    await _form(request)
    request.state.new_session = {}
    return RedirectResponse("/login", status_code=303)


async def overview(request: Request) -> Response:
    return _page(request, "overview.html", title="Overview", **await _data(request, _overview))


async def target_page(request: Request) -> Response:
    tid = request.path_params["tid"]
    if tid not in request.app.state.catalogue.targets:
        return _not_found(request, "target")
    d = await _data(request, _target, tid)
    return _page(request, "target.html", title=d["t"].name, **d)


async def check_page(request: Request) -> Response:
    pid = request.path_params["pid"]
    if _probe(request.app.state.catalogue, pid) is None:
        return _not_found(request, "check")
    d = await _data(request, _check, pid)
    return _page(request, "check.html", title=pid, **d)


async def evidence_download(request: Request) -> Response:
    pid, rid = request.path_params["pid"], request.path_params["rid"]
    store: Store = request.app.state.store
    row = await run_in_threadpool(
        store.one, "SELECT e.body FROM evidence e JOIN results r ON r.id = e.result_id "
                   "WHERE e.result_id=? AND r.probe_id=?", (rid, pid))
    if row is None:
        return PlainTextResponse("no such evidence", status_code=404)
    return PlainTextResponse(redact_text(row["body"] or "", EVIDENCE_CAP), headers={
        "content-disposition": f'attachment; filename="evidence-{rid}.txt"',
        "x-content-type-options": "nosniff"})


async def incidents_page(request: Request) -> Response:
    return _page(request, "incidents.html", title="Incidents", **await _data(request, _incidents))


async def outbox_page(request: Request) -> Response:
    return _page(request, "outbox.html", title="Outbox", **await _data(request, _outbox))


async def silences_page(request: Request, error: str | None = None, status: int = 200) -> Response:
    role: auth.Role = request.state.role
    cat = request.app.state.catalogue
    mine = [t for t in sorted(cat.targets.values(), key=lambda t: t.id) if role.may_change(t.id)]
    return _page(request, "silences.html", status, title="Silences", targets=mine, error=error,
                 **await _data(request, _silences))


async def silence_create(request: Request) -> Response:
    st, role = request.app.state, request.state.role
    form = await _form(request)
    tid, cid = form.get("target_id", ""), form.get("check_id", "").strip() or None
    reason = form.get("reason", "").strip()
    if tid not in st.catalogue.targets:
        return await silences_page(request, "Unknown target.", 400)
    if not role.may_change(tid):
        return await silences_page(request, "You may only silence targets you own.", 403)
    if cid and cid not in {c.id for c in st.catalogue.targets[tid].checks}:
        return await silences_page(request, "That check does not belong to the target.", 400)
    if not reason or len(reason) > 500:
        return await silences_page(request, "Give a reason (at most 500 characters).", 400)
    now = st.settings.now()
    try:
        until = parse_until(form.get("until", ""), now)
    except ValueError as exc:
        return await silences_page(request, str(exc), 400)

    def write() -> None:
        st.store.execute("INSERT INTO silences(target_id,check_id,reason,created_by,created_at,"
                         "until) VALUES(?,?,?,?,?,?)",
                         (tid, cid, reason, role.handle, iso(now), iso(until)))
        st.store.audit(role.handle, "silence", f"{tid}/{cid or '*'} until {iso(until)}: {reason}")

    await run_in_threadpool(write)
    return RedirectResponse("/silences", status_code=303)


async def silence_end(request: Request) -> Response:
    st, role = request.app.state, request.state.role
    await _form(request)
    sid = request.path_params["sid"]
    row = await run_in_threadpool(st.store.one, "SELECT * FROM silences WHERE id=?", (sid,))
    if row is None:
        return await silences_page(request, "No such silence.", 404)
    if not role.may_change(row["target_id"]):
        return await silences_page(request, "You may only end silences on your targets.", 403)
    now = iso(st.settings.now())

    def write() -> None:
        st.store.execute("UPDATE silences SET until=? WHERE id=?", (now, sid))
        st.store.audit(role.handle, "unsilence", f"silence {sid} on {row['target_id']}")

    await run_in_threadpool(write)
    return RedirectResponse("/silences", status_code=303)


async def known_page(request: Request) -> Response:
    cat = request.app.state.catalogue
    today = request.app.state.settings.now().date().isoformat()
    return _page(request, "known_issues.html", title="Known issues", known=cat.known, today=today)


async def catalogue_page(request: Request) -> Response:
    return _page(request, "catalogue.html", title="Catalogue",
                 **await _data(request, _catalogue_view))


async def cron_page(request: Request) -> Response:
    return _page(request, "cron.html", title="Cron", **await _data(request, _cron))


async def backups_page(request: Request) -> Response:
    rows = await _data(request, _results_for,
                       lambda t, c: c.kind in BACKUP_KINDS or t.class_ == "backup")
    return _page(request, "results.html", title="Backups", rows=rows,
                 intro="Latest result of every backup check (file age, integrity, off-disk copy).")


async def nodes_page(request: Request) -> Response:
    rows = await _data(request, _results_for,
                       lambda t, c: c.kind in NODE_KINDS or t.class_ == "infra")
    return _page(request, "results.html", title="Nodes", rows=rows,
                 intro="Host and swarm signals: RAID, disks, Gluster, replicas, local images.")


async def test_alert(request: Request) -> Response:
    st, role = request.app.state, request.state.role
    people = sorted((st.catalogue.owners.people if st.catalogue.owners else {}).keys())
    ctx = {"title": "Test alert", "people": people, "result": None, "error": None}
    if request.method == "GET":
        return _page(request, "test_alert.html", **ctx)
    form = await _form(request)
    recipients = [h.strip() for h in form.get("recipients", "").split(",") if h.strip()]
    channels = [ch for ch in ("github", "email", "slack") if form.get(f"ch_{ch}")]
    if not recipients or any(h not in people for h in recipients):
        return _page(request, "test_alert.html", 400, **{**ctx, "error": "Unknown recipient."})
    if not role.admin and recipients != [role.handle]:
        return _page(request, "test_alert.html", 403,
                     **{**ctx, "error": "Only admins may send test alerts to other people."})
    if not channels:
        return _page(request, "test_alert.html", 400, **{**ctx, "error": "Pick a channel."})
    try:
        from ..alerts.testing import enqueue_test_alert
    except ImportError:
        return _page(request, "test_alert.html", 503,
                     **{**ctx, "error": "Test alerts are not available in this build."})
    res = await run_in_threadpool(enqueue_test_alert, st.store, st.catalogue, recipients,
                                  channels, role.handle)
    if asyncio.iscoroutine(res):
        res = await res
    await run_in_threadpool(st.store.audit, role.handle, "test-alert",
                            f"{','.join(channels)} -> {','.join(recipients)}")
    return _page(request, "test_alert.html", **{**ctx, "result": res})


async def status_json(request: Request) -> Response:
    st = request.app.state
    doc = await run_in_threadpool(S.status_doc, st.store, st.catalogue, st.settings.now(), False)
    return JSONResponse(doc)


async def push(request: Request) -> Response:
    """Cron scripts report a finished run. Internal overlay only, bearer token per job."""
    st = request.app.state
    if any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip")):
        return JSONResponse({"error": "push only over the internal network"}, status_code=403)
    job = request.path_params["job"]
    if not _JOB_RE.match(job):
        return JSONResponse({"error": "bad job name"}, status_code=400)
    # Per caller and job: a noisy neighbour on the overlay cannot use up a job's budget.
    if not st.push_limiter.hit(f"{auth.client_ip(request.scope)}|{job}"):
        return JSONResponse({"error": "too many pushes"}, status_code=429)
    tokens = read_secret_json("tgxmon_push_tokens", st.settings.secrets_dir)
    expected = tokens.get(job) if isinstance(tokens, dict) else None
    given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not auth.token_ok(expected if isinstance(expected, str) else None, given):
        return JSONResponse({"error": "unauthorised"}, status_code=401)
    body = await request.body()
    if len(body) > st.settings.push_max_bytes:
        return JSONResponse({"error": "payload too large"}, status_code=413)
    try:
        payload = json.loads(body) if body.strip() else {}
    except ValueError:
        return JSONResponse({"error": "body is not JSON"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
    try:
        from ..kinds.infra import ingest_push
    except ImportError:
        return JSONResponse({"error": "push ingest not available"}, status_code=503)
    try:
        res = await run_in_threadpool(ingest_push, st.store, job, payload)
        if asyncio.iscoroutine(res):
            res = await res
    except ValueError as exc:  # the payload's fault: say what was wrong with it
        return JSONResponse({"error": str(exc)[:200]}, status_code=400)
    except Exception:  # noqa: BLE001 - never echo internals to the caller
        log.exception("push ingest for %s failed", job)
        return JSONResponse({"error": "ingest failed"}, status_code=500)
    return JSONResponse({"ok": True}, status_code=202)


def create_private_app(store: Store, catalogue: Catalogue, *,
                       settings: WebSettings | None = None) -> Starlette:
    settings = settings or WebSettings()
    routes = [
        Route("/livez", livez),
        Route("/login", login, methods=["GET", "POST"]),
        Route("/login/github", github_login.start),
        Route("/login/github/callback", github_login.callback),
        Route("/logout", logout, methods=["POST"]),
        Route("/api/push/{job}", push, methods=["POST"]),
        Route("/", overview),
        Route("/status.json", status_json),
        Route("/target/{tid}", target_page),
        Route("/check/{pid}", check_page),
        Route("/check/{pid}/evidence/{rid:int}", evidence_download),
        Route("/incidents", incidents_page),
        Route("/outbox", outbox_page),
        Route("/silences", silences_page),
        Route("/silences/new", silence_create, methods=["POST"]),
        Route("/silences/{sid:int}/end", silence_end, methods=["POST"]),
        Route("/known-issues", known_page),
        Route("/catalogue", catalogue_page),
        Route("/cron", cron_page),
        Route("/backups", backups_page),
        Route("/nodes", nodes_page),
        Route("/test-alert", test_alert, methods=["GET", "POST"]),
        Mount("/static", StaticFiles(directory=S.STATIC), name="static"),
    ]
    app = Starlette(routes=routes, middleware=[Middleware(auth.SecurityHeaders),
                                               Middleware(Gate)])
    app.state.store = store
    app.state.catalogue = catalogue
    app.state.settings = settings
    app.state.sessions = auth.Sessions.from_secret(settings.secrets_dir)
    app.state.login_limiter = auth.RateLimiter(5, 60.0)  # per address and user
    app.state.login_ip_limiter = auth.RateLimiter(20, 60.0)  # per address, any user
    app.state.login_user_limiter = auth.RateLimiter(10, 300.0)  # per account, any address
    app.state.login_slots = asyncio.Semaphore(auth.LOGIN_SLOTS)
    app.state.push_limiter = auth.RateLimiter(30, 60.0)
    app.state.env = S.jinja_env()
    return app
