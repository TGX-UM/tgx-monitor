"""Nothing private reaches the public snapshot, and the private app holds its line.

Canary strings (a secret, a host path, an e-mail address, a private IP) are planted in
evidence, outcomes, summaries, outbox payloads and replies, incident titles, target
notes, a private target and a private check. None may appear in any file the public
service serves. The private app must refuse every route without a session except the
three that are open by design, enforce CSRF on every POST, send the CSP everywhere and
escape what targets sent back.
"""

from __future__ import annotations

import re

import pytest
from starlette.routing import Route
from test_web_fixtures import CANARIES, NOW, client, login, make_app

from tgx_monitor import snapshot as S

OPEN_PATHS = {"/livez", "/login", "/api/push/{job}"}


def _concrete(path: str) -> str:
    return (path.replace("{pid}", "svc-a-up@public").replace("{tid}", "svc-a")
            .replace("{rid:int}", "1").replace("{sid:int}", "1").replace("{job}", "wp-reload"))


def _routes(app) -> list[Route]:  # noqa: ANN001
    return [r for r in app.routes if isinstance(r, Route)]


def test_public_snapshot_has_no_canaries(tmp_path):
    app, store, cat = make_app(tmp_path)
    snap = S.build_public(store, cat, tmp_path / "public", NOW)
    files = [p for p in snap.rglob("*") if p.suffix in (".html", ".json")]
    assert {p.name for p in files} >= {"index.html", "status.json", "svc-a.html"}
    for p in files:
        text = p.read_text()
        for canary in CANARIES:
            assert canary not in text, f"{canary} leaked into {p.relative_to(snap)}"
        assert "Private B" not in text and "svc-b" not in text
        assert "internal probe" not in text  # a public: false check's description
        assert "<script" not in text


def test_public_text_withholds_shapes():
    out = S.public_text("mail someone@example.org at /mnt/gluster/x on 10.0.0.5 or 81.169.246.233")
    assert "someone@" not in out and "/mnt/" not in out and "10.0.0.5" not in out
    assert "81.169.246.233" in out  # a node address is public already


def test_every_private_route_refuses_anonymous(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    checked = 0
    for route in _routes(app):
        if route.path in OPEN_PATHS:
            continue
        for method in sorted(route.methods or {"GET"}):
            if method == "HEAD":
                continue
            r = c.request(method, _concrete(route.path), follow_redirects=False)
            if method == "GET":
                assert r.status_code == 303 and r.headers["location"].startswith("/login"), \
                    (method, route.path, r.status_code)
            else:
                assert r.status_code == 401, (method, route.path, r.status_code)
            assert "svc-a" not in r.text
            checked += 1
    assert checked >= 18


def test_open_routes_stay_narrow(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    assert c.get("/livez").status_code == 200
    assert c.get("/login").status_code == 200
    r = c.post("/api/push/wp-reload", json={"exit_code": 0})
    assert r.status_code == 401  # no token
    assert c.get("/static/tgx-monitor.css").status_code == 200


def test_csrf_enforced_on_every_post(tmp_path):
    app, _, _ = make_app(tmp_path)
    c = client(app)
    # Logging in itself needs the token from the login form: refused (400 with a fresh
    # form and an explanation), no session, no redirect.
    r = c.post("/login", data={"username": "admin1", "password": "admin-pw"},
               follow_redirects=False)
    assert r.status_code == 400 and "location" not in r.headers
    assert c.get("/", follow_redirects=False).status_code == 303  # still logged out
    login(c, "admin1")
    posts = [r for r in _routes(app) if "POST" in (r.methods or set())
             and r.path not in OPEN_PATHS]
    assert {r.path for r in posts} >= {"/logout", "/silences/new", "/test-alert"}
    for route in posts:
        for data in ({}, {"csrf": "forged"}):
            r = c.post(_concrete(route.path), data={**data, "reason": "x", "target_id": "svc-a",
                                                     "until": "1h"}, follow_redirects=False)
            assert r.status_code == 403, (route.path, data, r.status_code)
    assert c.get("/").status_code == 200  # still logged in: logout was refused too


@pytest.mark.parametrize("path", ["/livez", "/login", "/static/tgx-monitor.css", "/nope"])
def test_security_headers_everywhere(tmp_path, path):
    app, _, _ = make_app(tmp_path)
    r = client(app).get(path, follow_redirects=False)
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_pages_have_no_inline_script_or_style(tmp_path):
    app, store, cat = make_app(tmp_path)
    c = client(app)
    login(c, "admin1")
    pages = [c.get(p).text for p in ("/", "/check/svc-a-up@public", "/silences", "/outbox")]
    S.build_public(store, cat, tmp_path / "public", NOW)
    pages.append((tmp_path / "public" / "current" / "index.html").read_text())
    for html in pages:
        assert not re.search(r"<script|\sstyle=|\son[a-z]+=", html)


def test_evidence_is_escaped_and_downloads_as_text(tmp_path):
    app, store, _ = make_app(tmp_path)
    c = client(app)
    login(c, "admin1")
    page = c.get("/check/svc-a-up@public").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    rid = store.one("SELECT result_id FROM evidence ORDER BY result_id LIMIT 1")["result_id"]
    r = c.get(f"/check/svc-a-up@public/evidence/{rid}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in r.headers["content-disposition"]
    # A result id that belongs to another probe is not served under this one.
    other = store.one("SELECT r.id FROM results r JOIN evidence e ON e.result_id=r.id "
                      "WHERE r.probe_id='svc-b-backup'")["id"]
    assert c.get(f"/check/svc-a-up@public/evidence/{other}").status_code == 404
