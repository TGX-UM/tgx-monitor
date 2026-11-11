"""Sign in with GitHub: state check, allowlist from tgxmon_users, token revoked, password off."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import httpx
from test_web_fixtures import (
    NOW,
    PASSWORDS,
    client,
    csrf_of,
    make_catalogue,
    make_secrets,
    make_store,
)

from tgx_monitor.web.app import WebSettings, create_private_app

BASE = "https://monitor.example.org"


class FakeGitHub:
    def __init__(self, login: str = "alice", token_status: int = 200) -> None:
        self.login = login
        self.token_status = token_status
        self.calls: list[tuple[str, str]] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append((req.method, str(req.url)))
        if req.url.path == "/login/oauth/access_token":
            form = parse_qs(req.content.decode())
            assert form["client_secret"] == ["oauth-secret"]
            assert form["redirect_uri"] == [f"{BASE}/login/github/callback"]
            return httpx.Response(self.token_status, json={"access_token": "user-tok"})
        if req.url.path == "/user":
            assert req.headers["authorization"] == "Bearer user-tok"
            return httpx.Response(200, json={"login": self.login})
        if req.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(404)


def make(tmp_path, fake: FakeGitHub, *, password_login: bool = True, users=None):
    secrets = make_secrets(tmp_path / "secrets")
    (secrets / "tgxmon_gh_oauth_secret").write_text("oauth-secret")
    if users is not None:
        (secrets / "tgxmon_users").write_text(json.dumps(users))
    settings = WebSettings(secrets_dir=secrets, now=lambda: NOW, base_url=BASE,
                           gh_client_id="Iv-test", gh_transport=httpx.MockTransport(fake),
                           password_login=password_login)
    app = create_private_app(make_store(True), make_catalogue(tmp_path / "catalogue"),
                             settings=settings)
    return client(app)


def _start(c) -> str:
    r = c.get("/login/github?next=/catalogue", follow_redirects=False)
    assert r.status_code == 303
    loc = urlsplit(r.headers["location"])
    assert loc.netloc == "github.com" and loc.path == "/login/oauth/authorize"
    q = parse_qs(loc.query)
    assert q["client_id"] == ["Iv-test"] and q["redirect_uri"] == [f"{BASE}/login/github/callback"]
    return q["state"][0]


def test_login_page_offers_github_when_configured(tmp_path):
    c = make(tmp_path, FakeGitHub())
    page = c.get("/login").text
    assert 'href="/login/github?next=' in page and 'name="password"' in page


def test_github_sign_in_admits_a_listed_user_and_revokes_the_token(tmp_path):
    fake = FakeGitHub(login="Alice")  # GitHub logins are case-insensitive
    c = make(tmp_path, fake)
    state = _start(c)
    r = c.get(f"/login/github/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/catalogue"
    assert c.get("/", follow_redirects=False).status_code == 200
    assert ("DELETE", "https://api.github.com/applications/Iv-test/token") in fake.calls


def test_github_sign_in_refuses_an_unlisted_user(tmp_path):
    c = make(tmp_path, FakeGitHub(login="mallory"))
    state = _start(c)
    r = c.get(f"/login/github/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 403 and "mallory has no access" in r.text
    assert c.get("/", follow_redirects=False).status_code == 303  # still logged out


def test_callback_without_the_matching_state_is_refused(tmp_path):
    fake = FakeGitHub()
    c = make(tmp_path, fake)
    _start(c)
    r = c.get("/login/github/callback?code=abc&state=forged", follow_redirects=False)
    assert r.status_code == 403 and "expired" in r.text
    other = make(tmp_path / "b", fake)  # a fresh browser that never started the flow
    r = other.get("/login/github/callback?code=abc&state=x", follow_redirects=False)
    assert r.status_code == 403
    assert not [c for c in fake.calls if "access_token" in c[1]], "no code exchange"


def test_a_state_works_once(tmp_path):
    c = make(tmp_path, FakeGitHub())
    state = _start(c)
    assert c.get(f"/login/github/callback?code=a&state={state}",
                 follow_redirects=False).status_code == 303
    c.cookies.clear()
    assert c.get(f"/login/github/callback?code=a&state={state}",
                 follow_redirects=False).status_code == 403


def test_github_only_users_and_password_login_off(tmp_path):
    users = {"alice": "github", "admin1": json.loads(
        (make_secrets(tmp_path / "s0") / "tgxmon_users").read_text())["admin1"]}
    c = make(tmp_path, FakeGitHub(login="alice"), password_login=False, users=users)
    page = c.get("/login").text
    assert "Sign in with GitHub" in page and 'name="password"' not in page
    tok = csrf_of(c.get("/login").text) if 'name="csrf"' in page else ""
    r = c.post("/login", data={"csrf": tok, "username": "admin1",
                               "password": PASSWORDS["admin1"]}, follow_redirects=False)
    assert r.status_code in (400, 403) and "location" not in r.headers
    state = _start(c)
    assert c.get(f"/login/github/callback?code=a&state={state}",
                 follow_redirects=False).status_code == 303


def test_a_github_only_entry_never_matches_a_password(tmp_path):
    c = make(tmp_path, FakeGitHub(), users={"alice": "github"})
    tok = csrf_of(c.get("/login").text)
    r = c.post("/login", data={"csrf": tok, "username": "alice", "password": "github"},
               follow_redirects=False)
    assert r.status_code == 401


def test_github_down_is_a_message_not_a_crash(tmp_path):
    def broken(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    c = make(tmp_path, FakeGitHub())
    c.app.state.settings.gh_transport = httpx.MockTransport(broken)
    state = _start(c)
    r = c.get(f"/login/github/callback?code=a&state={state}", follow_redirects=False)
    assert r.status_code == 403 and "did not answer" in r.text
