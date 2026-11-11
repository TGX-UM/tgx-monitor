"""The assertion grammar: every operator, the warn/crit ladder, baselines, missing paths.

These pin down what a catalogue line *means*, so a refactor of the engine cannot quietly
change which checks go red.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tgx_monitor import assertions as A

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)

VALUES = {
    "status": 200,
    "status_text": "200",
    "version": "2026.11.07",
    "boolean": True,
    "body": "Default Data\nline two",
    "headers": {"content-type": "text/plain; charset=UTF-8", "location": ""},
    "rows": [{"n": 5}, {"n": 7}],
    "by": {"KeyEvent": 1600, "AOP": "595"},
    "left": 42, "right": "42", "other": 41,
    "created_on": "2026-11-08",
    "stamp": "20261110",
    "epoch": NOW.timestamp() - 3600,
    "nothing": None,
    "empty": [],
}


def ev(a, values=VALUES, baseline=None):
    return A.evaluate(a, values, NOW, baseline)


# ---------------------------------------------------------------- comparisons
@pytest.mark.parametrize(("a", "status"), [
    ({"that": "status", "eq": 200}, "ok"),
    ({"that": "status", "eq": 404}, "failed"),
    ({"that": "status", "ne": 404}, "ok"),
    ({"that": "status", "gt": 199}, "ok"),
    ({"that": "status", "gte": 200}, "ok"),
    ({"that": "status", "lt": 200}, "failed"),
    ({"that": "status", "lte": 200}, "ok"),
    ({"that": "by.KeyEvent", "gte": 1580}, "ok"),
    ({"that": "by.KeyEvent", "lt": 1580}, "failed"),
    ({"that": "rows.1.n", "eq": 7}, "ok"),
    ({"that": "boolean", "eq": True}, "ok"),
    ({"that": "boolean", "eq": False}, "failed"),
])
def test_compare_ops(a, status):
    assert ev(a).status == status


def test_numeric_vs_string_eq():
    # A number in the catalogue compares numerically against a numeric string...
    assert ev({"that": "status_text", "eq": 200}).status == "ok"
    assert ev({"that": "by.AOP", "gte": 590}).status == "ok"
    # ...while a string in the catalogue means a string comparison (versions).
    assert ev({"that": "status", "eq": "200"}).status == "ok"
    assert ev({"that": "version", "eq": "2026.11.07"}).status == "ok"
    assert ev({"that": "version", "eq": "2026.11.7"}).status == "failed"
    assert ev({"that": "version", "ne": "2026.10.31"}).status == "ok"


def test_ordering_on_non_numbers_is_unknown_not_a_crash():
    o = ev({"that": "body", "gt": 5})
    assert o.status == "unknown"
    assert "assertion error" in o.found


def test_list_ops():
    assert ev({"that": "status", "in": [200, 301]}).status == "ok"
    assert ev({"that": "status", "in": [301, 302]}).status == "failed"
    assert ev({"that": "status", "not_in": [500, 502]}).status == "ok"
    assert ev({"that": "status", "not_in": [200]}).status == "failed"


def test_text_ops():
    assert ev({"that": "body", "contains": "Default Data"}).status == "ok"
    assert ev({"that": "body", "contains": "Conductor"}).status == "failed"
    assert ev({"that": "body", "not_contains": "Conductor"}).status == "ok"
    assert ev({"that": "body", "matches": r"^line two$"}).status == "ok"  # re.M
    o = ev({"that": "body", "not_matches": r"Default\s+\w+"})
    assert o.status == "failed" and o.found == "Default Data"
    assert ev({"that": "headers.content-type", "matches": "^text/plain"}).status == "ok"
    # A non-string value is matched on its text form.
    assert ev({"that": "status", "matches": r"^2\d\d$"}).status == "ok"


def test_len_ops():
    assert ev({"that": "rows", "len_eq": 2}).status == "ok"
    assert ev({"that": "rows", "len_gte": 3}).status == "failed"
    assert ev({"that": "empty", "len_lte": 0}).status == "ok"
    o = ev({"that": "status", "len_gte": 1})
    assert o.status == "failed" and "not a collection" in o.found


def test_exists_and_absent():
    assert ev({"that": "status", "exists": True}).status == "ok"
    assert ev({"that": "nope", "exists": True}).status == "failed"
    assert ev({"that": "nothing", "exists": True}).status == "failed"
    assert ev({"that": "nope", "absent": True}).status == "ok"
    assert ev({"that": "headers.location", "absent": True}).status == "ok"  # "" counts
    assert ev({"that": "status", "absent": True}).status == "failed"


# ---------------------------------------------------------------- missing paths
@pytest.mark.parametrize("path", ["nope", "by.Nope", "rows.9.n", "rows.x", "status.deeper"])
def test_missing_path_fails_with_missing(path):
    o = ev({"that": path, "eq": 1})
    assert o.status == "failed"
    assert o.found == "missing"


def test_missing_path_under_warn_is_amber_not_red():
    o = ev({"that": "nope", "eq": 1, "warn": True})
    assert o.status == "ok" and o.warn_only


def test_resolve_walks_dicts_and_lists():
    assert A.resolve(VALUES, "rows.0.n") == 5
    assert A.resolve({"a": [{"b": {"c": 3}}]}, "a.0.b.c") == 3
    assert A.resolve(VALUES, "rows.-1.n") == 7  # python indexing, documented by test


# ---------------------------------------------------------------- warn flag and label
def test_warn_only_breach_is_ok_but_flagged():
    o = ev({"that": "status", "eq": 500, "warn": True})
    assert o.status == "ok" and o.warn_only
    o = ev({"that": "status", "eq": 200, "warn": True})
    assert o.status == "ok" and not o.warn_only


def test_label_replaces_generated_text():
    o = ev({"that": "by.KeyEvent", "gte": 1, "label": "key events present"})
    assert o.assertion == "key events present"


def test_describe_texts():
    assert A.describe({"that": "status", "eq": 200}) == "status == 200"
    assert "drops ≤2%" in A.describe({"that": "x", "max_drop_pct": 2, "window": "7d"})
    assert A.describe({"that": "d", "max_age": {"warn": "8d", "crit": "15d"}}) == \
        "age of d below warn 8d, crit 15d"
    assert A.describe({"that": "a", "eq_path": "b"}) == "a == b"
    assert A.describe({"that": "c", "monotonic": True}) == "c monotonic"


# ---------------------------------------------------------------- max_age
def test_max_age_fresh_warn_crit():
    a = {"that": "created_on", "max_age": {"warn": "2d", "crit": "5d"}}
    o = ev(a)  # 3.5 days old
    assert o.status == "ok" and o.warn_only
    assert "3.5d old" in o.found
    o = ev({"that": "created_on", "max_age": {"warn": "8d", "crit": "15d"}})
    assert o.status == "ok" and not o.warn_only
    o = ev({"that": "created_on", "max_age": {"crit": "2d"}})
    assert o.status == "failed"


def test_max_age_parses_release_labels_and_epochs():
    assert ev({"that": "stamp", "max_age": {"crit": "2d"}}).status == "ok"
    assert ev({"that": "stamp", "max_age": {"crit": "1h"}}).status == "failed"
    assert ev({"that": "epoch", "max_age": {"crit": "2h"}}).status == "ok"
    o = ev({"that": "body", "max_age": {"crit": "1d"}})
    assert o.status == "failed" and o.expected == "a date"


def test_max_age_with_datetime_objects():
    vals = {"d": NOW - dt.timedelta(hours=30), "naive": dt.datetime(2026, 11, 11, 11, 0)}
    assert A.evaluate({"that": "d", "max_age": {"crit": "1d"}}, vals, NOW).status == "failed"
    assert A.evaluate({"that": "naive", "max_age": {"crit": "2h"}}, vals, NOW).status == "ok"
    vals = {"day": dt.date(2026, 11, 1)}
    assert A.evaluate({"that": "day", "max_age": {"crit": "15d"}}, vals, NOW).status == "ok"


def test_max_age_crit_under_warn_flag_is_amber():
    o = ev({"that": "created_on", "max_age": {"crit": "1d"}, "warn": True})
    assert o.status == "ok" and o.warn_only


# ---------------------------------------------------------------- eq_path / within
def test_eq_path():
    assert ev({"that": "left", "eq_path": "right"}).status == "ok"  # 42 == "42"
    o = ev({"that": "left", "eq_path": "other"})
    assert o.status == "failed" and "41" in o.expected
    o = ev({"that": "left", "eq_path": "nope"})
    assert o.status == "failed" and "missing" in o.expected


def test_within_pct_of_path():
    a = {"that": "other", "within_pct_of_path": {"path": "left", "pct": 5}}
    assert ev(a).status == "ok"
    a = {"that": "other", "within_pct_of_path": {"path": "left", "pct": 1}}
    assert ev(a).status == "failed"
    a = {"that": "other", "within_pct_of_path": {"path": "body", "pct": 1}}
    assert ev(a).status == "failed"


# ---------------------------------------------------------------- baselines
def provider(history):
    calls = []

    def baseline(path, window_s):
        calls.append((path, window_s))
        return list(history)

    baseline.calls = calls
    return baseline


def test_max_drop_pct_against_median():
    a = {"that": "by.KeyEvent", "max_drop_pct": 2, "window": "7d"}
    b = provider([1610, 1620, 1630])
    o = ev(a, baseline=b)
    assert o.status == "ok"  # 1600 >= 1620 * 0.98
    assert b.calls == [("by.KeyEvent", 7 * 86400)]
    o = ev(a, {"by": {"KeyEvent": 1500}}, baseline=b)
    assert o.status == "failed" and "median 1620" in o.expected


def test_max_drop_pct_builds_baseline_first():
    a = {"that": "by.KeyEvent", "max_drop_pct": 2}
    o = ev({**a}, {"by": {"KeyEvent": 1}}, baseline=provider([1600, 1600]))
    assert o.status == "ok" and "baseline building (2/3)" in o.expected
    assert ev(a, baseline=None).expected == "no baseline yet"
    o = ev(a, {"by": {"KeyEvent": "n/a"}}, baseline=provider([1, 2, 3]))
    assert o.status == "failed" and o.expected == "a number"


def test_max_drop_pct_default_window_is_seven_days():
    b = provider([5, 5, 5])
    ev({"that": "status", "max_drop_pct": 10}, baseline=b)
    assert b.calls[0][1] == 7 * 86400


def test_monotonic():
    a = {"that": "status", "monotonic": True}
    assert ev(a, baseline=provider([])).expected == "no previous value"
    assert ev(a, baseline=provider([150, 203])).status == "ok"  # within 2%
    assert ev(a, baseline=provider([250])).status == "failed"
    b = provider([1])
    ev(a, baseline=b)
    assert b.calls[0][1] == 400 * 86400


# ---------------------------------------------------------------- static validation
@pytest.mark.parametrize(("a", "needle"), [
    ("eq 200", "must be a mapping"),
    ({"eq": 200}, "missing 'that'"),
    ({"that": "x"}, "exactly one operator"),
    ({"that": "x", "eq": 1, "gt": 0}, "exactly one operator"),
    ({"that": "x", "bigger": 1}, "unknown operator"),
    ({"that": "x", "max_age": "8d"}, "max_age needs"),
    ({"that": "x", "max_age": {"warn": "8 days"}}, "bad duration"),
    ({"that": "x", "max_drop_pct": "lots"}, "must be a number"),
    ({"that": "x", "max_drop_pct": 2, "window": "a week"}, "bad duration"),
    ({"that": "x", "matches": "(unclosed"}, "missing )"),
    ({"that": "x", "in": 200}, "needs a list"),
    ({"that": "x", "len_gte": "many"}, "needs a number"),
])
def test_validate_finds_problems(a, needle):
    probs = A.validate(a)
    assert any(needle in p for p in probs), probs


def test_validate_accepts_good_assertions():
    for a in ({"that": "status", "eq": 200}, {"that": "d", "max_age": {"crit": "15d"}},
              {"that": "x", "max_drop_pct": 2, "window": "7d"},
              {"that": "b", "matches": "^ok$", "warn": True, "label": "ok"}):
        assert A.validate(a) == []


def test_bad_assertion_never_raises_from_evaluate():
    o = ev({"that": "status"})
    assert o.status == "unknown" and "assertion error" in o.found


@pytest.mark.parametrize(("text", "seconds"), [
    ("30s", 30), ("15m", 900), ("6h", 21600), ("8d", 691200), ("2w", 1209600),
    ("1.5h", 5400), (45, 45.0), (" 5m ", 300),
])
def test_parse_duration(text, seconds):
    assert A.parse_duration(text) == seconds


def test_parse_duration_rejects_nonsense():
    with pytest.raises(ValueError):
        A.parse_duration("soon")


def test_numeric_paths_collects_metrics_for_baselines():
    asserts = [{"that": "by.KeyEvent", "gte": 1}, {"that": "body", "contains": "x"},
               {"that": "by.AOP", "gte": 1}, {"that": "nope", "exists": True}]
    m = A.numeric_paths(asserts, {**VALUES, "latency_ms": 12.5})
    assert m == {"by.KeyEvent": 1600.0, "by.AOP": 595.0, "latency_ms": 12.5}


def test_max_age_parses_http_dates():
    now = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)
    vals = {"lm": "Tue, 10 Nov 2026 04:01:02 GMT", "v": "2026.11.07"}
    assert A.evaluate({"that": "lm", "max_age": {"crit": "3d"}}, vals, now).status == "ok"
    assert A.evaluate({"that": "lm", "max_age": {"crit": "1d"}}, vals, now).status == "failed"
    assert A.evaluate({"that": "v", "max_age": {"crit": "8d"}}, vals, now).status == "ok"
