"""Shared builders for the web, snapshot and leak tests (no tests of its own).

A tiny catalogue with one public target owned by alice, one private target owned by bob,
and a store seeded with results, evidence, incidents and outbox rows. ``planted=True``
puts canary strings everywhere the public snapshot must never read from.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

from argon2 import PasswordHasher
from starlette.testclient import TestClient

from tgx_monitor import catalogue as catmod
from tgx_monitor.model import Outcome, Result, iso
from tgx_monitor.store import Store
from tgx_monitor.web.app import WebSettings, create_private_app

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)
CANARIES = ["SECRET-CANARY-123", "/mnt/gluster/secret", "someone@example.org", "10.0.0.5"]
PLANT = " ".join(CANARIES)
PASSWORDS = {"admin1": "admin-pw", "alice": "alice-pw", "bob": "bob-pw"}

OWNERS = """admins: [admin1]
fallback: [admin1]
people:
  admin1: {name: Admin One}
  alice: {name: Alice}
  bob: {name: Bob}
"""
MAINT = """- id: weekly
  describe: Weekly reload
  rrule: FREQ=WEEKLY;BYDAY=SU
  start: "05:50"
  duration: 100m
"""
TARGETS = """- id: svc-a
  name: Service A
  group: Group A
  class: service
  owners: [alice]
  maintenance: [weekly]
  public_summary: Service A answers.
  notes: "{plant}"
  links: [https://a.example.org/]
  checks:
    - id: svc-a-up
      kind: http
      via: [public, tgx1]
      describe: The front page answers 200.
      request: {{url: "https://a.example.org/", headers: {{Authorization: "Bearer {plant}"}}}}
      assert: [{{that: status, eq: 200}}]
    - id: svc-a-inner
      kind: http
      public: false
      describe: "internal probe {plant}"
      request: {{url: "https://a.example.org/admin"}}
      assert: [{{that: status, eq: 401}}]
- id: svc-b
  name: Private B
  group: Hidden
  class: backup
  public: false
  owners: [bob]
  public_summary: "{plant}"
  checks:
    - id: svc-b-backup
      kind: file_age
      describe: "backup in {plant}"
      request: {{mount: x}}
      assert: [{{that: newest_age_h, lt: 26}}]
"""


def make_catalogue(root: Path, plant: str = PLANT) -> catmod.Catalogue:
    (root / "targets").mkdir(parents=True, exist_ok=True)
    (root / "owners.yaml").write_text(OWNERS)
    (root / "maintenance.yaml").write_text(MAINT)
    (root / "targets" / "t.yaml").write_text(TARGETS.format(plant=plant))
    cat = catmod.load(root)
    assert not cat.problems, cat.problems
    return cat


def make_store(planted: bool = True) -> Store:
    s = Store(":memory:")
    plant = PLANT if planted else "nothing here"
    s.set_meta("last_tick", iso(NOW - dt.timedelta(seconds=5)))
    probes = [("svc-a-up@public", "svc-a-up", "svc-a", "failed"),
              ("svc-a-up@tgx1", "svc-a-up", "svc-a", "ok"),
              ("svc-a-inner", "svc-a-inner", "svc-a", "failed"),
              ("svc-b-backup", "svc-b-backup", "svc-b", "failed")]
    for i, (pid, cid, tid, status) in enumerate(probes):
        r = Result(cid, tid, status, NOW - dt.timedelta(minutes=i + 1), 42.0,
                   outcomes=[Outcome("status == 200", status, "200", f"500 {plant}")],
                   summary=f"found {plant}", evidence=f"<script>alert(1)</script> {plant}")
        rid = s.save_result(r, pid, pid.partition("@")[2] or "public", "sha1")
        s.execute("INSERT INTO probe_state(probe_id,check_id,target_id,state,last_status,"
                  "last_result_id,first_fail_at) VALUES(?,?,?,?,?,?,?)",
                  (pid, cid, tid, "FAILING" if status == "failed" else "OK", status, rid,
                   iso(NOW - dt.timedelta(hours=1)) if status == "failed" else None))
        for d in range(3):
            s.execute("INSERT INTO rollup_daily(probe_id,day,n,ok,failed,unknown,p50_ms) "
                      "VALUES(?,?,?,?,?,?,?)", (pid, (NOW.date() - dt.timedelta(days=d))
                                               .isoformat(), 10, 9, 1, 0, 40.0))
    for tid, private in (("svc-a", 0), ("svc-b", 1)):
        cur = s.execute("INSERT INTO incidents(key,target_id,severity,title,opened_at,failing,"
                        "private) VALUES(?,?,?,?,?,?,?)",
                        (f"{tid}-1", tid, "high", f"{tid} failing {plant}",
                         iso(NOW - dt.timedelta(hours=1)), json.dumps([f"{tid}-up@public"]),
                         private))
        s.execute("INSERT INTO outbox(created_at,channel,event,incident_id,recipients,payload,"
                  "next_attempt_at,reply) VALUES(?,?,?,?,?,?,?,?)",
                  (iso(NOW), "email", "open", cur.lastrowid, json.dumps(["alice"]),
                   json.dumps({"to": plant, "body": plant}), iso(NOW), f"250 {plant}"))
    return s


def make_secrets(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    ph = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    (root / "tgxmon_users").write_text(json.dumps({u: ph.hash(p) for u, p in PASSWORDS.items()}))
    (root / "tgxmon_session_key").write_text("test-session-key-" + "x" * 32)
    (root / "tgxmon_push_tokens").write_text(json.dumps({"wp-reload": "push-token-1"}))
    return root


def make_app(tmp_path: Path, planted: bool = True):  # noqa: ANN201 - test helper
    cat = make_catalogue(tmp_path / "catalogue")
    store = make_store(planted)
    settings = WebSettings(secrets_dir=make_secrets(tmp_path / "secrets"), now=lambda: NOW)
    return create_private_app(store, cat, settings=settings), store, cat


def client(app) -> TestClient:  # noqa: ANN001
    return TestClient(app, base_url="https://testserver")


def csrf_of(html: str) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "no csrf field on the page"
    return m.group(1)


def login(c: TestClient, user: str) -> str:
    """Log in and return the session's CSRF token."""
    tok = csrf_of(c.get("/login").text)
    r = c.post("/login", data={"csrf": tok, "username": user, "password": PASSWORDS[user]},
               follow_redirects=False)
    assert r.status_code == 303, r.text
    return csrf_of(c.get("/silences").text)
