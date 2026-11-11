"""The private UI: login, roles, silences, push, test alert and the per-check page."""

from __future__ import annotations

import datetime as dt
import sys
import types

from test_web_fixtures import NOW, client, csrf_of, login, make_app

from tgx_monitor.catalogue import Check
from tgx_monitor.model import iso
from tgx_monitor.web.app import curl_for, parse_until


def test_livez_follows_the_tick_only(tmp_path):
    app, store, _ = make_app(tmp_path)
    c = client(app)
    assert c.get("/livez").status_code == 200  # targets are failing; the monitor is fine
    store.set_meta("last_tick", iso(NOW - dt.timedelta(minutes=4)))
    assert c.get("/livez").status_code == 503


def test_login_cookie_and_rate_limit(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    tok = csrf_of(c.get("/login").text)
    bad = c.post("/login", data={"csrf": tok, "username": "alice", "password": "nope"})
    assert bad.status_code == 401
    r = c.post("/login?next=/catalogue", data={"csrf": tok, "username": "alice",
                                               "password": "alice-pw"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/catalogue"
    cookie = r.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert "max-age=43200" in cookie
    # The session rotated its CSRF token at login.
    assert csrf_of(c.get("/silences").text) != tok
    other = client(app)
    tok = csrf_of(other.get("/login").text)
    codes = [other.post("/login", data={"csrf": tok, "username": "bob", "password": "x"})
             .status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_login_refuses_offsite_next(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    tok = csrf_of(c.get("/login").text)
    r = c.post("/login?next=//evil.example/x", data={"csrf": tok, "username": "alice",
                                                      "password": "alice-pw"},
               follow_redirects=False)
    assert r.headers["location"] == "/"


def test_logout(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    tok = login(c, "alice")
    assert c.post("/logout", data={"csrf": tok}, follow_redirects=False).status_code == 303
    assert c.get("/", follow_redirects=False).status_code == 303


def test_pages_render_for_a_user(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    login(c, "alice")
    for path in ("/", "/target/svc-a", "/check/svc-a-up@public", "/check/svc-b-backup",
                 "/incidents", "/outbox", "/silences", "/known-issues", "/catalogue", "/cron",
                 "/backups", "/nodes", "/test-alert"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert r.headers["cache-control"] == "no-store"
    assert c.get("/target/nope").status_code == 404
    assert c.get("/check/nope").status_code == 404
    assert "svc-b-backup" in c.get("/backups").text
    doc = c.get("/status.json").json()
    assert {t["id"] for t in doc["targets"]} == {"svc-a", "svc-b"}
    assert doc["outbox_oldest_age_s"] == 0.0


def test_check_page_explains(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    login(c, "admin1")
    html = c.get("/check/svc-a-up@public").text
    assert "status == 200" in html and "Failing since" in html
    assert "Bearer" not in html.split("Repeat it by hand")[1].split("</pre>")[0]
    assert "[redacted]" in html
    assert "next window" in html  # svc-a has a weekly window
    assert "email" in html and "250" in html  # the delivery log


def test_silences_follow_ownership(tmp_path):
    app, store, _ = make_app(tmp_path)
    c = client(app)
    tok = login(c, "alice")
    ok = c.post("/silences/new", data={"csrf": tok, "target_id": "svc-a", "reason": "deploy",
                                       "until": "2h"}, follow_redirects=False)
    assert ok.status_code == 303
    row = store.one("SELECT * FROM silences")
    assert row["created_by"] == "alice" and row["until"] == iso(NOW + dt.timedelta(hours=2))
    no = c.post("/silences/new", data={"csrf": tok, "target_id": "svc-b", "reason": "x",
                                       "until": "2h"})
    assert no.status_code == 403
    long = c.post("/silences/new", data={"csrf": tok, "target_id": "svc-a", "reason": "x",
                                         "until": "40d"})
    assert long.status_code == 400
    end = c.post(f"/silences/{row['id']}/end", data={"csrf": tok}, follow_redirects=False)
    assert end.status_code == 303
    assert store.one("SELECT until FROM silences")["until"] == iso(NOW)
    admin = client(app)
    tok = login(admin, "admin1")
    assert admin.post("/silences/new", data={"csrf": tok, "target_id": "svc-b", "reason": "x",
                                             "until": "1d"}, follow_redirects=False
                      ).status_code == 303
    assert store.one("SELECT COUNT(*) AS n FROM audit WHERE action='silence'")["n"] == 2


def test_parse_until():
    assert parse_until("90m", NOW) == NOW + dt.timedelta(minutes=90)
    assert parse_until("2026-11-12T08:00", NOW) == dt.datetime(2026, 11, 12, 8, tzinfo=dt.UTC)
    for bad in ("2026-01-01T00:00", "31d", "soon"):
        try:
            parse_until(bad, NOW)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_push(tmp_path, monkeypatch):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    seen = []
    import tgx_monitor.kinds.infra as infra

    def fake_ingest(store, job, payload):  # noqa: ANN001, ANN202
        if "boom" in payload:
            raise ValueError("bad exit_code")
        seen.append((job, payload))
        return 1

    monkeypatch.setattr(infra, "ingest_push", fake_ingest)
    auth = {"Authorization": "Bearer push-token-1"}
    url = "/api/push/wp-reload"
    assert c.post(url, json={"exit_code": 0}, headers={**auth, "X-Forwarded-For": "1.2.3.4"}
                  ).status_code == 403
    assert c.post(url, json={}, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.post("/api/push/other", json={}, headers=auth).status_code == 401
    assert c.post(url, content=b"not json", headers=auth).status_code == 400
    assert c.post(url, json={"boom": 1}, headers=auth).status_code == 400
    r = c.post(url, json={"exit_code": 0}, headers=auth)
    assert r.status_code == 202 and seen == [("wp-reload", {"exit_code": 0})]
    assert "set-cookie" not in r.headers


def test_test_alert(tmp_path, monkeypatch):
    app, _, _ = make_app(tmp_path)
    calls = []
    mod = types.ModuleType("tgx_monitor.alerts.testing")
    mod.enqueue_test_alert = lambda store, cat, rec, ch, who: calls.append((rec, ch, who)) or 3
    monkeypatch.setitem(sys.modules, "tgx_monitor.alerts.testing", mod)
    c = client(app)
    tok = login(c, "alice")
    r = c.post("/test-alert", data={"csrf": tok, "recipients": "bob", "ch_email": "1"})
    assert r.status_code == 403 and not calls
    r = c.post("/test-alert", data={"csrf": tok, "recipients": "alice", "ch_email": "1"})
    assert r.status_code == 200 and calls == [(["alice"], ["email"], "alice")]
    admin = client(app)
    tok = login(admin, "admin1")
    r = admin.post("/test-alert", data={"csrf": tok, "recipients": "alice,bob", "ch_github": "1",
                                        "ch_slack": "1"})
    assert r.status_code == 200 and calls[-1] == (["alice", "bob"], ["github", "slack"],
                                                  "admin1")
    assert admin.post("/test-alert", data={"csrf": tok, "recipients": "mallory",
                                           "ch_email": "1"}).status_code == 400


def test_curl_for(tmp_path):
    _, _, cat = make_app(tmp_path)
    c = Check.model_validate({"id": "x-up", "kind": "http", "request": {
        "url": "https://a.example.org/p", "headers": {"Authorization": "Bearer abc",
                                                      "Accept": "text/html"},
        "params": {"q": "1"}}, "assert": [{"that": "status", "eq": 200}]})
    cmd = curl_for(c, "tgx1", cat)
    assert "abc" not in cmd and "Accept: text/html" in cmd
    assert "--resolve a.example.org:443:" in cmd and "https://a.example.org/p?q=1" in cmd
    s = Check.model_validate({"id": "x-ask", "kind": "sparql", "request": {
        "endpoint": "https://s.example.org/sparql", "ask": "ASK { ?s ?p ?o }"},
        "assert": [{"that": "boolean", "eq": True}]})
    cmd = curl_for(s, "public", cat)
    assert "-G" in cmd and "--data-urlencode 'query=ASK { ?s ?p ?o }'" in cmd
    other = Check.model_validate({"id": "x-f", "kind": "file_age", "request": {},
                                  "assert": [{"that": "n", "eq": 1}]})
    assert curl_for(other, "public", cat) is None


def test_session_ends_when_the_user_is_removed_or_the_password_changes(tmp_path):
    import json

    from argon2 import PasswordHasher

    app, _, _ = make_app(tmp_path)
    alice, bob = client(app), client(app)
    login(alice, "alice")
    login(bob, "bob")
    assert alice.get("/", follow_redirects=False).status_code == 200
    users = tmp_path / "secrets" / "tgxmon_users"
    doc = json.loads(users.read_text())
    del doc["alice"]
    doc["bob"] = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("new-pw")
    users.write_text(json.dumps(doc))
    for c in (alice, bob):
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), r.text


def test_login_is_limited_per_address_across_usernames(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    tok = csrf_of(c.get("/login").text)
    codes = [c.post("/login", data={"csrf": tok, "username": f"user{i}", "password": "x"})
             .status_code for i in range(21)]
    assert codes[:20] == [401] * 20 and codes[20] == 429


def test_overlong_password_is_not_hashed(tmp_path, monkeypatch):
    from tgx_monitor.web import auth

    app, _, _ = make_app(tmp_path)
    calls = []
    monkeypatch.setattr(auth, "verify_password", lambda *a: calls.append(a) or False)
    c = client(app)
    tok = csrf_of(c.get("/login").text)
    r = c.post("/login", data={"csrf": tok, "username": "alice", "password": "x" * 5000})
    assert r.status_code == 401 and calls == []


def test_push_rate_limit_is_per_caller(tmp_path):
    from starlette.testclient import TestClient

    app, _, _ = make_app(tmp_path)
    noisy = TestClient(app, base_url="https://testserver", client=("10.0.9.1", 5000))
    codes = [noisy.post("/api/push/wp-reload", json={}).status_code for _ in range(31)]
    assert codes[-1] == 429
    cron = TestClient(app, base_url="https://testserver", client=("10.0.9.2", 5000))
    r = cron.post("/api/push/wp-reload", json={}, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401  # its own budget, untouched by the noisy caller
