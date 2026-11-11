"""The routing policy as a table: (event, class, severity, owners, private) -> recipients.

A change to who gets paged must change a row here.
"""

from __future__ import annotations

import pytest

from tgx_monitor.alerts import router
from tgx_monitor.catalogue import Owners, Target

OWNERS = Owners.model_validate({
    "admins": ["marvinm2", "egonw"], "fallback": ["marvinm2"], "infra_cc": ["egonw"],
    "people": {"marvinm2": {"notify": True}, "egonw": {"notify": True},
               "alice": {"notify": True}, "bob": {"notify": False},
               "ext-01": {"notify": True, "github": False}}})

M, E, A = "marvinm2", "egonw", "alice"

CASES = [
    # event, class, criticality, owners, private, expected {channel: recipients}
    # Critical mail: owners + the fallback (Marvin); Egon only as cc, and only for
    # infra, backup and security (plan, Alert policy / Routing).
    ("open", "service", "high", ["alice"], False,
     {"github": [A], "smtp": [A, M], "slack": []}),
    ("open", "service", "high", ["bob"], False,  # bob has not opted in: fallback
     {"github": [M], "smtp": [M], "slack": []}),
    ("open", "service", "high", ["ext-01"], False,  # no GitHub account: e-mail only
     {"github": [M], "smtp": ["ext-01", M], "slack": []}),
    ("open", "infra", "high", ["alice"], False,
     {"github": [A, E], "smtp": [A, M, "cc:egonw"], "slack": []}),
    ("open", "backup", "medium", ["alice"], False,
     {"github": [A, E], "slack": []}),
    ("open", "service", "medium", ["alice", "bob"], False, {"github": [A], "slack": []}),
    ("open", "service", "low", ["alice"], False, {}),
    ("open", "service", "muted", ["alice"], False, {}),
    ("open", "security", "high", ["alice"], True, {"smtp": [A, M, "cc:egonw"], "slack": []}),
    ("open", "service", "medium", ["alice"], True, {"slack": []}),
    ("close", "service", "high", ["alice"], False,
     {"github": [], "smtp": [A, M], "slack": []}),
    ("retired", "service", "high", ["alice"], False,
     {"github": [], "smtp": [A, M], "slack": []}),
    ("close", "data", "medium", ["alice"], False, {"github": [], "slack": []}),
    ("close", "service", "low", ["alice"], False, {}),
    ("reminder", "service", "high", ["alice"], False, {"github": [A], "slack": []}),
    ("reminder", "service", "medium", ["alice"], False, {}),
    ("escalate", "service", "high", ["alice"], False, {"github": [E], "smtp": [E]}),
    ("escalate", "security", "high", ["alice"], True, {"smtp": [E]}),
    ("update", "service", "high", ["alice"], False, {"github": []}),
    ("flapping", "service", "medium", ["alice"], False, {"slack": []}),
    ("flapping", "service", "low", ["alice"], False, {}),
]


@pytest.mark.parametrize(("event", "cls", "crit", "owners", "private", "want"), CASES)
def test_routing_table(event, cls, crit, owners, private, want) -> None:
    t = Target.model_validate({"id": "t-x", "name": "T", "class": cls, "criticality": crit,
                               "owners": owners})
    sev = router.severity_of(t)
    assert router.routes(event, sev, t, OWNERS, private) == want


def test_infra_cc_when_egon_is_not_admin() -> None:
    owners = OWNERS.model_copy(update={"admins": ["marvinm2"]})
    t = Target.model_validate({"id": "t-x", "name": "T", "class": "infra",
                               "criticality": "high", "owners": ["alice"]})
    assert router.routes("open", "critical", t, owners)["smtp"] == [A, M, "cc:egonw"]


def test_check_severity_overrides_target() -> None:
    from tgx_monitor.catalogue import Check

    t = Target.model_validate({"id": "t-x", "name": "T", "class": "service",
                               "criticality": "high"})
    c = Check.model_validate({"id": "c-x", "kind": "http", "severity": "low"})
    assert router.severity_of(t, c) == "info"
    assert router.severity_of(t) == "critical"
    assert router.is_private(t, [c.model_copy(update={"public": False})])


def test_digest_recipients() -> None:
    t = Target.model_validate({"id": "t-x", "name": "T", "class": "backup",
                               "criticality": "medium", "owners": ["alice", "bob"]})
    assert router.digest_recipients(t, OWNERS) == [A, M, E]


def test_security_canary_inside_a_public_target_stays_private():
    """aopsuite's 'debugger stays off' regressing must not open a public issue."""
    from tgx_monitor.alerts import router
    from tgx_monitor.catalogue import Check, Target

    t = Target.model_validate({"id": "svc-x", "name": "X", "class": "service",
                               "owners": ["marvinm2"], "public_summary": "x"})
    sec = Check.model_validate({"id": "svc-x-debugger-off", "kind": "security",
                                "assert": [{"that": "exposed", "eq": False}]})
    web = Check.model_validate({"id": "svc-x-home", "kind": "http",
                                "assert": [{"that": "status", "eq": 200}]})
    assert router.is_private(t, [sec]) and router.is_private(t, [web, sec])
    assert not router.is_private(t, [web])
    b = t.model_copy(update={"class_": "backup"})
    assert router.is_private(b, [web])
