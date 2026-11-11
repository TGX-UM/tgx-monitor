"""Sign in with GitHub, so the private page gets GitHub's own login and two-factor check.

The tgx-monitor GitHub App doubles as the OAuth client: its client id is
``TGXMON_GH_CLIENT_ID`` (not secret) and its client secret the Docker secret
``tgxmon_gh_oauth_secret``. The App's callback URL must be
``<TGXMON_PRIVATE_URL>/login/github/callback``.

Flow: ``/login/github`` stores a random ``state`` (and where to go next) in the
pre-login session and sends the browser to GitHub. ``/login/github/callback`` checks the
state, swaps the code for a user token, asks GitHub who this is, revokes the token again
(the monitor never acts as the user) and admits the handle only when it is a key of
``tgxmon_users``. The value there may be an argon2 hash (password login too) or the word
``github`` (GitHub sign-in only). Roles still come from ``owners.yaml``.

``TGXMON_GITHUB_ONLY=1`` turns the password form off once GitHub sign-in works, so a
leaked password alone no longer opens the page.
"""

from __future__ import annotations

import contextlib
import hmac
import logging
import secrets as pysecrets
from typing import Any
from urllib.parse import urlencode

import httpx
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ..secrets import read_secret, read_secret_json
from . import auth

log = logging.getLogger(__name__)

AUTHORIZE = "https://github.com/login/oauth/authorize"
TOKEN = "https://github.com/login/oauth/access_token"
API = "https://api.github.com"
SECRET = "tgxmon_gh_oauth_secret"


def configured(settings: Any) -> bool:
    return bool(settings.gh_client_id and settings.base_url
                and read_secret(SECRET, settings.secrets_dir))


def _callback(settings: Any) -> str:
    return settings.base_url.rstrip("/") + "/login/github/callback"


def allowed_handle(login: str, secrets_dir: Any) -> str | None:
    """The tgxmon_users key matching this GitHub login (case-insensitive), else None."""
    users = read_secret_json("tgxmon_users", secrets_dir)
    if not isinstance(users, dict):
        return None
    for key in users:
        if isinstance(key, str) and key.lower() == login.lower():
            return key
    return None


def _safe_next(nxt: str) -> str:
    return nxt if nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt else "/"


async def start(request: Request) -> Response:
    st = request.app.state
    if not configured(st.settings) or not st.sessions.enabled:
        return RedirectResponse("/login", status_code=303)
    state = pysecrets.token_urlsafe(32)
    sess = dict(request.state.session)
    sess.setdefault("csrf", auth.new_csrf())
    sess["oauth_state"] = state
    sess["oauth_next"] = _safe_next(request.query_params.get("next", "/"))
    request.state.new_session = sess
    query = urlencode({"client_id": st.settings.gh_client_id,
                       "redirect_uri": _callback(st.settings),
                       "state": state, "allow_signup": "false"})
    return RedirectResponse(f"{AUTHORIZE}?{query}", status_code=303)


def _fail(request: Request, why: str) -> Response:
    """Back to the login page with a reason; the pre-login session drops its state."""
    sess = {k: v for k, v in request.state.session.items()
            if k not in ("oauth_state", "oauth_next")}
    sess.setdefault("csrf", auth.new_csrf())
    request.state.new_session = sess
    from .app import login_page  # late import: app imports this module

    return login_page(request, why, 403)


async def callback(request: Request) -> Response:
    st = request.app.state
    if not configured(st.settings):
        return RedirectResponse("/login", status_code=303)
    ip = auth.client_ip(request.scope)
    if not st.login_ip_limiter.hit(ip):
        return _fail(request, "Too many attempts. Wait a minute and try again.")
    want = str(request.state.session.get("oauth_state") or "")
    got = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    if request.query_params.get("error"):
        return _fail(request, "GitHub sign-in was cancelled.")
    if not (want and got and code and hmac.compare_digest(want, got)):
        return _fail(request, "That GitHub sign-in link had expired. Please try again.")
    secret = read_secret(SECRET, st.settings.secrets_dir) or ""
    login = None
    try:
        async with httpx.AsyncClient(transport=st.settings.gh_transport, timeout=15,
                                     follow_redirects=False) as http:
            r = await http.post(TOKEN, headers={"Accept": "application/json"}, data={
                "client_id": st.settings.gh_client_id, "client_secret": secret,
                "code": code, "redirect_uri": _callback(st.settings)})
            token = r.json().get("access_token") if r.status_code == 200 else None
            if token:
                u = await http.get(f"{API}/user", headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json"})
                login = u.json().get("login") if u.status_code == 200 else None
                # The monitor never acts as the user: give the token back at once.
                with contextlib.suppress(httpx.HTTPError):
                    await http.request(
                        "DELETE", f"{API}/applications/{st.settings.gh_client_id}/token",
                        auth=(st.settings.gh_client_id, secret),
                        json={"access_token": token},
                        headers={"Accept": "application/vnd.github+json"})
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("GitHub sign-in failed: %s", type(exc).__name__)
        return _fail(request, "GitHub did not answer. Please try again.")
    if not isinstance(login, str) or not login:
        return _fail(request, "GitHub did not confirm who you are. Please try again.")
    handle = allowed_handle(login, st.settings.secrets_dir)
    if handle is None:
        await _audit(request, login, "login-refused", ip)
        return _fail(request, f"GitHub user {login} has no access to this page.")
    fp = auth.user_fingerprint(handle, st.settings.secrets_dir)
    nxt = _safe_next(str(request.state.session.get("oauth_next") or "/"))
    request.state.new_session = {"u": handle, "fp": fp, "csrf": auth.new_csrf(),
                                 "via": "github"}
    await _audit(request, handle, "login", f"{ip} via GitHub")
    return RedirectResponse(nxt, status_code=303)


async def _audit(request: Request, who: str, action: str, detail: str) -> None:
    from starlette.concurrency import run_in_threadpool

    await run_in_threadpool(request.app.state.store.audit, who, action, detail)
