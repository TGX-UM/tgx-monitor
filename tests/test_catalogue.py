"""Catalogue loading and ``validate()``: every problem reported, none swallowed.

The repository is public, so the leak rules (no e-mail, no host paths, no stray IPs)
matter as much as the schema rules.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tgx_monitor import catalogue as catmod
from tgx_monitor.kinds import KINDS

REPO_CATALOGUE = Path(__file__).resolve().parents[1] / "catalogue"

OWNERS = """
admins: [alice]
fallback: [alice]
infra_cc: [bob]
people:
  alice: {name: Alice, notify: true}
  bob: {name: Bob, notify: false}
"""

WINDOWS = """
- id: weekly-reload
  describe: Sunday reload
  rrule: FREQ=WEEKLY;BYDAY=SU
  start: "05:50"
  duration: 100m
"""


def target(tid="svc-a", **over):
    t = {
        "id": tid, "name": tid.upper(), "class": "service", "owners": ["alice"],
        "public_summary": "A service.",
        "checks": [{"id": f"{tid}-up", "kind": "http", "request": {"url": "https://example.org/"},
                    "describe": "The front page answers 200.",
                    "purpose": "Shows that people can open the service.",
                    "assert": [{"that": "status", "eq": 200}]}],
    }
    t.update(over)
    return t


def make(tmp_path: Path, targets: list[dict] | None = None, owners: str = OWNERS,
         windows: str = WINDOWS, extra: dict[str, str] | None = None) -> catmod.Catalogue:
    import yaml

    (tmp_path / "targets").mkdir(parents=True, exist_ok=True)
    (tmp_path / "queries").mkdir(exist_ok=True)
    if owners is not None:
        (tmp_path / "owners.yaml").write_text(textwrap.dedent(owners))
    (tmp_path / "maintenance.yaml").write_text(textwrap.dedent(windows))
    for t in targets if targets is not None else [target()]:
        (tmp_path / "targets" / f"{t['id']}.yaml").write_text(yaml.safe_dump(t))
    for name, text in (extra or {}).items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return catmod.load(tmp_path)


def problems(cat, kinds=None):
    return cat.validate(known_kinds=set(KINDS) if kinds is None else kinds)


# ---------------------------------------------------------------- the real catalogue
def test_repository_catalogue_is_clean():
    cat = catmod.load(REPO_CATALOGUE)
    assert cat.targets, "catalogue/targets is empty"
    assert problems(cat) == []


def test_check_needs_describe_and_purpose(tmp_path):
    t = target()
    del t["checks"][0]["purpose"]
    assert problems(make(tmp_path, [t])) == [
        "svc-a/svc-a-up: needs describe (what is checked) and purpose (why, in plain words)"]


def test_minimal_catalogue_is_clean(tmp_path):
    cat = make(tmp_path)
    assert problems(cat) == []
    assert list(cat.checks) == ["svc-a-up"]
    assert cat.windows["weekly-reload"].duration == "100m"


# ---------------------------------------------------------------- schema
def test_schema_errors_are_collected_per_file(tmp_path):
    bad = target("bad-one", **{"class": "website"})
    bad["checks"][0]["frequency"] = "5m"  # extra key: forbidden
    cat = make(tmp_path, [bad, target("Bad_ID")])
    probs = problems(cat)
    assert any("bad-one.yaml: class" in p for p in probs)
    assert any("frequency" in p and "Extra inputs" in p for p in probs)
    assert any("kebab-case" in p for p in probs)
    assert cat.targets == {}


def test_yaml_error_is_a_problem_not_a_crash(tmp_path):
    cat = make(tmp_path, [], extra={"targets/broken.yaml": "id: [unclosed\n"})
    assert any("YAML error" in p for p in problems(cat))


def test_multiple_targets_in_one_file(tmp_path):
    import yaml

    cat = make(tmp_path, [], extra={"targets/two.yaml": yaml.safe_dump(
        [target("svc-a"), target("svc-b")])})
    assert set(cat.targets) == {"svc-a", "svc-b"}


def test_duplicates(tmp_path):
    import yaml

    t2 = target("svc-b")
    t2["checks"][0]["id"] = "svc-a-up"
    cat = make(tmp_path, [target(), t2],
               extra={"targets/zz-copy.yaml": yaml.safe_dump(target())})
    probs = problems(cat)
    assert any("duplicate target id svc-a" in p for p in probs)
    assert any("check id svc-a-up also in" in p for p in probs)


def test_owners_must_resolve(tmp_path):
    cat = make(tmp_path, [target(owners=["mallory"])])
    assert any("owner 'mallory' not in owners.yaml" in p for p in problems(cat))


def test_owners_yaml_handles_must_be_people(tmp_path):
    owners = OWNERS.replace("infra_cc: [bob]", "infra_cc: [carol]")
    assert any("carol is not listed under people" in p for p in problems(make(tmp_path,
                                                                             owners=owners)))


def test_missing_owners_yaml(tmp_path):
    cat = make(tmp_path, owners=None)
    assert "owners.yaml missing" in problems(cat)


def test_unowned_target_needs_explicit_owner_unless_muted(tmp_path):
    cat = make(tmp_path, [target(owners=[]), target("svc-m", owners=[], criticality="muted")])
    probs = problems(cat)
    assert "svc-a: no owners (use fallback explicitly)" in probs
    assert not any(p.startswith("svc-m: no owners") for p in probs)


def test_public_target_needs_summary(tmp_path):
    cat = make(tmp_path, [target(public_summary=""), target("svc-p", public=False,
                                                            public_summary="")])
    probs = problems(cat)
    assert "svc-a: public target needs public_summary" in probs
    assert not any(p.startswith("svc-p:") for p in probs)


def test_unknown_dependency_and_window(tmp_path):
    cat = make(tmp_path, [target(depends_on=["ghost"], maintenance=["never"])])
    probs = problems(cat)
    assert "svc-a: depends_on unknown target 'ghost'" in probs
    assert "svc-a: unknown maintenance window 'never'" in probs


def test_dependency_cycles(tmp_path):
    cat = make(tmp_path, [target("svc-a", depends_on=["svc-b"]),
                          target("svc-b", depends_on=["svc-c"]),
                          target("svc-c", depends_on=["svc-a"]),
                          target("svc-d", depends_on=["svc-a"])])
    cycles = [p for p in problems(cat) if "cycle" in p]
    assert sorted(cycles) == ["svc-a: dependency cycle", "svc-b: dependency cycle",
                              "svc-c: dependency cycle"]
    assert set(cat.ancestors("svc-d")) == {"svc-a", "svc-b", "svc-c"}


def test_ancestors_of_a_chain(tmp_path):
    cat = make(tmp_path, [target("edge-x"), target("traefik-x", depends_on=["edge-x"]),
                          target("app-x", depends_on=["traefik-x"])])
    assert cat.ancestors("app-x") == ["traefik-x", "edge-x"]
    assert cat.ancestors("edge-x") == []
    assert cat.ancestors("not-there") == []


# ---------------------------------------------------------------- checks
def check_problem(tmp_path, kinds=None, **check):
    t = target()
    t["checks"][0].update(check)
    return problems(make(tmp_path, [t]), kinds)


def test_unknown_kind(tmp_path):
    assert any("unknown kind 'carrier-pigeon'" in p
               for p in check_problem(tmp_path, kind="carrier-pigeon"))


def test_known_kinds_none_skips_the_kind_check(tmp_path):
    t = target()
    t["checks"][0]["kind"] = "carrier-pigeon"
    assert make(tmp_path, [t]).validate(known_kinds=None) == []


def test_todo_kind_must_be_structured_or_disabled(tmp_path):
    probs = check_problem(tmp_path, kinds={"todo", "http"}, kind="todo")
    assert "svc-a/svc-a-up: kind 'todo' must be structured or disabled" in probs
    probs = check_problem(tmp_path / "b", kinds={"todo", "http"}, kind="todo", enabled=False)
    assert probs == []


def test_bad_durations(tmp_path):
    probs = check_problem(tmp_path, every="often", timeout="1 minute", alert_after="1x",
                          retry="10m")
    assert sum("bad duration" in p for p in probs) == 3


def test_check_needs_assertions_when_enabled(tmp_path):
    assert "svc-a/svc-a-up: no assertions" in check_problem(tmp_path, **{"assert": []})


def test_bad_assertion_is_reported_with_its_check(tmp_path):
    probs = check_problem(tmp_path, **{"assert": [{"that": "status", "equals": 200}]})
    assert any(p.startswith("svc-a/svc-a-up: unknown operator 'equals'") for p in probs)


def test_unknown_via_is_rejected(tmp_path):
    probs = check_problem(tmp_path, via=["tgx3"])
    assert any("via" in p for p in probs)


def test_probe_ids_per_vantage_point(tmp_path):
    t = target()
    t["checks"][0]["via"] = ["public", "tgx1", "tgx2"]
    t["checks"].append({"id": "svc-a-off", "kind": "http", "enabled": False,
                        "request": {"url": "https://example.org/"},
                        "assert": [{"that": "status", "eq": 200}]})
    cat = make(tmp_path, [t])
    assert [(p, v) for p, v, _, _ in cat.probes()] == [
        ("svc-a-up@public", "public"), ("svc-a-up@tgx1", "tgx1"), ("svc-a-up@tgx2", "tgx2")]
    single = cat.checks["svc-a-off"][1]
    assert single.probe_ids() == [("svc-a-off", "public")]


def test_check_defaults(tmp_path):
    c = make(tmp_path).checks["svc-a-up"][1]
    assert c.interval_s == 900 and c.timeout_s == 30 and c.via == ["public"]
    assert c.enabled and c.public is None and c.assert_ == [{"that": "status", "eq": 200}]


# ---------------------------------------------------------------- leaks
@pytest.mark.parametrize(("text", "needle"), [
    ("notes: mail someone@example.org about it\n", "e-mail address 'someone@example.org'"),
    ("notes: legacy box 192.0.2.17 still answers\n", "IP address 192.0.2.17"),
    ("notes: data in /mnt/gluster/docker/x\n", "host path '/mnt/'"),
    ("notes: see /run/secrets/tgxmon_smtp\n", "host path '/run/secrets'"),
    ("notes: a home dir /home/someone/x\n", "host path '/home/'"),
])
def test_leaks_in_targets(tmp_path, text, needle):
    import yaml

    doc = yaml.safe_dump(target()) + text
    cat = make(tmp_path, [], extra={"targets/svc-a.yaml": doc})
    assert any(needle in p for p in problems(cat)), problems(cat)


def test_node_ips_and_resolvers_are_allowed(tmp_path):
    import yaml

    doc = yaml.safe_dump(target()) + "notes: nodes 81.169.246.233 and 85.214.252.63 via 1.1.1.1\n"
    cat = make(tmp_path, [], extra={"targets/svc-a.yaml": doc})
    assert problems(cat) == []


def test_leaks_in_query_files_and_other_yaml(tmp_path):
    cat = make(tmp_path, extra={
        "queries/q.rq": "# ask admin@example.org\nASK { ?s ?p ?o }\n",
        "known_issues.yaml": "# box 10.0.0.12\n[]\n",
        "payloads/body.json": '{"contact": "admin@example.org"}\n',
    })
    probs = problems(cat)
    assert "queries/q.rq: e-mail address 'admin@example.org'" in probs
    assert "known_issues.yaml: IP address 10.0.0.12" in probs
    # Everything under catalogue/ is published, payloads included (as CI's grep sees it).
    assert "payloads/body.json: e-mail address 'admin@example.org'" in probs


@pytest.mark.parametrize("secret", [
    "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "https://hooks.slack.com/services/" + "T000/B000/XXXX",
    "https://hc-ping.com/" + "0f1e2d3c-4b5a-6978-8091-a2b3c4d5e6f7",
    "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxIn0.c2ln",
])
def test_credentials_in_the_catalogue_are_problems(tmp_path, secret):
    import yaml

    t = target()
    t["checks"][0]["request"]["headers"] = {"Authorization": f"Bearer {secret}"}
    cat = make(tmp_path, [], extra={"targets/svc-a.yaml": yaml.safe_dump(t)})
    assert "targets/svc-a.yaml: credential-shaped string" in problems(cat)


def test_links_must_be_http(tmp_path):
    cat = make(tmp_path, [target(links=["javascript:alert(1)", "https://ok.example.org/"])])
    assert problems(cat) == ["svc-a: link 'javascript:alert(1)' must be an http(s) URL"]


def test_private_import_dir_is_not_scanned(tmp_path):
    cat = make(tmp_path, extra={"_import/private/inv.yaml": "who: a@b.org at /mnt/x\n"})
    assert problems(cat) == []


# ---------------------------------------------------------------- misc access
def test_query_text_reads_and_refuses_escapes(tmp_path):
    cat = make(tmp_path, extra={"queries/counts.rq": "SELECT * {}"})
    assert cat.query_text("q/counts.rq") == "SELECT * {}"
    with pytest.raises(ValueError, match="escapes"):
        cat.query_text("q/../../../etc/passwd")
    with pytest.raises(ValueError, match="escapes"):  # inside the catalogue, outside queries/
        cat.query_text("q/../owners.yaml")


def test_sha_changes_with_content(tmp_path):
    cat = make(tmp_path)
    before = cat.sha
    (tmp_path / "queries" / "new.rq").write_text("ASK {}")
    assert catmod.load(tmp_path).sha != before
    assert len(before) == 12


def test_known_issues_and_windows_are_validated(tmp_path):
    cat = make(tmp_path, windows="- {id: w, describe: x}\n", extra={
        "known_issues.yaml": "- {target: svc-a, reason: flaky}\n"})
    probs = problems(cat)
    assert any(p.startswith("maintenance.yaml:") for p in probs)
    assert any(p.startswith("known_issues.yaml:") for p in probs)
