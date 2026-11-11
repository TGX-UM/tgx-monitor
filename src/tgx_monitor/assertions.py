"""One assertion grammar for every check kind.

A kind *observes* (fills :class:`~tgx_monitor.model.Observation.values`); this module
*judges*. Keeping the two apart means every check in the catalogue reads the same way,
whatever produced the numbers, and ``doctor`` can validate all of them without knowing
the kinds.

An assertion is a mapping with ``that`` (a dotted path into the observation) and one
operator::

    {that: status, eq: 200}
    {that: body, contains: "Default Data"}
    {that: by.KeyEvent, gte: 1580}
    {that: by.KeyEvent, max_drop_pct: 2, window: 7d}      # vs the median of the window
    {that: created_on, max_age: {warn: 8d, crit: 15d}}     # a date/datetime value
    {that: left, eq_path: right}                            # two observed values agree
    {that: count, monotonic: true}                          # never falls by more than 2%
    {that: headers.location, absent: true}
    {that: san, has: aopwiki-rdf.vhp4safety.nl}             # exact list membership

Optional on any assertion: ``warn: true`` (breach shows amber, never fails) and
``label`` (what the page shows instead of the generated text).

Paths: ``a.b.0.c`` walks dicts and lists. Missing paths fail the assertion with
"missing", except under ``absent``/``exists``.
"""

from __future__ import annotations

import datetime as dt
import re
import statistics
from collections.abc import Callable
from typing import Any

from .model import Outcome

COMPARE_OPS = ("eq", "ne", "gt", "gte", "lt", "lte")
LIST_OPS = ("in", "not_in", "has", "lacks")
TEXT_OPS = ("matches", "not_matches", "contains", "not_contains")
LEN_OPS = ("len_eq", "len_gte", "len_lte")
SPECIAL_OPS = ("max_drop_pct", "max_age", "eq_path", "monotonic", "exists", "absent",
               "within_pct_of_path")
ALL_OPS = COMPARE_OPS + LIST_OPS + TEXT_OPS + LEN_OPS + SPECIAL_OPS
META_KEYS = {"that", "warn", "label", "window"}

_MISSING = object()
_DUR = re.compile(r"^(\d+(?:\.\d+)?)\s*(s|m|h|d|w)$")
_DUR_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# A baseline provider: (path, window_seconds) -> list of previous numeric values,
# oldest first, excluding the current run.
Baseline = Callable[[str, float], list[float]]


def parse_duration(text: str | int | float) -> float:
    """'15m' -> 900.0 seconds. Numbers are taken as seconds."""
    if isinstance(text, int | float):
        return float(text)
    m = _DUR.match(str(text).strip())
    if not m:
        raise ValueError(f"bad duration {text!r}; use e.g. 30s, 15m, 6h, 8d, 2w")
    return float(m.group(1)) * _DUR_UNITS[m.group(2)]


def resolve(values: Any, path: str) -> Any:
    cur = values
    for part in str(path).split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        elif isinstance(cur, list | tuple):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return _MISSING
        else:
            return _MISSING
    return cur


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, int | float):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def _as_datetime(v: Any) -> dt.datetime | None:
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=dt.UTC)
    if isinstance(v, dt.date):
        return dt.datetime(v.year, v.month, v.day, tzinfo=dt.UTC)
    if isinstance(v, int | float):  # epoch seconds
        return dt.datetime.fromtimestamp(float(v), tz=dt.UTC)
    if isinstance(v, str) and v.strip():
        s = v.strip().replace("Z", "+00:00")
        try:
            d = dt.datetime.fromisoformat(s)
        except ValueError:
            # yyyymmdd release labels (WikiPathways style)
            if re.fullmatch(r"\d{8}", s):
                d = dt.datetime.strptime(s, "%Y%m%d")
            elif re.fullmatch(r"\d{4}[./]\d{2}[./]\d{2}", s):  # AOP-Wiki pav:version 2026.11.07
                d = dt.datetime.strptime(s.replace("/", "."), "%Y.%m.%d")
            else:
                # HTTP dates (Last-Modified: "Tue, 10 Nov 2026 04:01:02 GMT", RFC 7231)
                from email.utils import parsedate_to_datetime

                try:
                    d = parsedate_to_datetime(s)
                except (TypeError, ValueError, IndexError):
                    return None
        return d if d.tzinfo else d.replace(tzinfo=dt.UTC)
    return None


def _short(v: Any, n: int = 120) -> str:
    if v is _MISSING:
        return "missing"
    s = repr(v) if not isinstance(v, str) else v
    s = s.replace("\n", "⏎")
    return s if len(s) <= n else s[: n - 1] + "…"


def operator_of(a: dict[str, Any]) -> str:
    ops = [k for k in a if k not in META_KEYS]
    if len(ops) != 1:
        raise ValueError(f"assertion needs exactly one operator, got {ops or 'none'}: {a}")
    if ops[0] not in ALL_OPS:
        raise ValueError(f"unknown operator {ops[0]!r}; known: {', '.join(ALL_OPS)}")
    return ops[0]


def validate(a: Any) -> list[str]:
    """Static problems with one assertion (for ``doctor``)."""
    if not isinstance(a, dict):
        return [f"assertion must be a mapping, got {type(a).__name__}"]
    probs: list[str] = []
    if "that" not in a:
        probs.append(f"assertion missing 'that': {a}")
    try:
        op = operator_of(a)
    except ValueError as exc:
        return probs + [str(exc)]
    v = a[op]
    try:
        if op == "max_age":
            if not isinstance(v, dict) or not ({"warn", "crit"} & set(v)):
                probs.append("max_age needs {warn: <dur>} and/or {crit: <dur>}")
            else:
                for k in ("warn", "crit"):
                    if k in v:
                        parse_duration(v[k])
        if op == "max_drop_pct":
            if _num(v) is None:
                probs.append("max_drop_pct must be a number")
            parse_duration(a.get("window", "7d"))
        if op in TEXT_OPS[:2]:
            re.compile(str(v))
        if op in ("in", "not_in") and not isinstance(v, list):
            probs.append(f"{op} needs a list")
        if op in LEN_OPS and _num(v) is None:
            probs.append(f"{op} needs a number")
    except (ValueError, re.error) as exc:
        probs.append(str(exc))
    return probs


def describe(a: dict[str, Any]) -> str:
    if a.get("label"):
        return str(a["label"])
    op = operator_of(a)
    that = a.get("that", "?")
    v = a[op]
    sym = {"eq": "==", "ne": "!=", "gt": ">", "gte": "≥", "lt": "<", "lte": "≤"}
    if op in sym:
        return f"{that} {sym[op]} {v!r}"
    if op == "max_drop_pct":
        return f"{that} drops ≤{v}% vs median of last {a.get('window', '7d')}"
    if op == "max_age":
        parts = [f"{k} {v[k]}" for k in ("warn", "crit") if k in v]
        return f"age of {that} below " + ", ".join(parts)
    if op == "eq_path":
        return f"{that} == {v}"
    if op == "within_pct_of_path":
        return f"{that} within {v.get('pct')}% of {v.get('path')}"
    if op in ("exists", "absent", "monotonic"):
        return f"{that} {op}"
    return f"{that} {op} {v!r}"


def evaluate(
    a: dict[str, Any],
    values: dict[str, Any],
    now: dt.datetime,
    baseline: Baseline | None = None,
) -> Outcome:
    """Judge one assertion against observed ``values``. Never raises."""
    text = ""
    try:
        text = describe(a)
        op = operator_of(a)
        got = resolve(values, a["that"])
        warn_only = bool(a.get("warn"))

        def out(ok: bool, expected: str, found: Any, status: str | None = None) -> Outcome:
            st = "ok" if ok else (status or ("ok" if warn_only else "failed"))
            return Outcome(assertion=text, status=st, expected=expected,
                           found=_short(found), warn_only=(warn_only and not ok))

        if op == "exists":
            return out(got is not _MISSING and got is not None, "present", got)
        if op == "absent":
            return out(got is _MISSING or got is None or got == "", "absent", got)
        if got is _MISSING:
            return Outcome(assertion=text, status="ok" if warn_only else "failed",
                           expected="a value", found="missing", warn_only=warn_only)

        v = a[op]
        if op in COMPARE_OPS:
            # Ordering ops compare numerically when both sides parse as numbers.
            # eq/ne: a string in the catalogue means a string comparison (versions such
            # as "2026.11.07"); otherwise numbers compare as numbers ("200" == 200).
            gn, vn = _num(got), _num(v)
            if op in ("eq", "ne") and isinstance(v, str):
                lhs, rhs = str(got), v
            elif gn is not None and vn is not None:
                lhs, rhs = gn, vn
            else:
                lhs, rhs = got, v
            res = {
                "eq": lambda: lhs == rhs, "ne": lambda: lhs != rhs,
                "gt": lambda: lhs > rhs, "gte": lambda: lhs >= rhs,
                "lt": lambda: lhs < rhs, "lte": lambda: lhs <= rhs,
            }[op]()
            return out(bool(res), f"{op} {v!r}", got)
        if op == "in":
            return out(got in v, f"one of {v}", got)
        if op == "not_in":
            return out(got not in v, f"none of {v}", got)
        if op in ("has", "lacks"):  # exact membership in an observed list (san, answers)
            items = got if isinstance(got, list | tuple | set) else [got]
            present = v in items or str(v) in [str(i) for i in items]
            return out(present if op == "has" else not present,
                       f"{op} {v!r}", got)
        if op in TEXT_OPS:
            s = got if isinstance(got, str) else str(got)
            if op == "matches":
                return out(re.search(str(v), s, re.M) is not None, f"/{v}/", s[:200])
            if op == "not_matches":
                m = re.search(str(v), s, re.M)
                return out(m is None, f"not /{v}/", m.group(0) if m else s[:80])
            if op == "contains":
                return out(str(v) in s, f"contains {v!r}", s[:200])
            return out(str(v) not in s, f"lacks {v!r}", s[:200])
        if op in LEN_OPS:
            n = len(got) if hasattr(got, "__len__") else None
            if n is None:
                return out(False, f"{op} {v}", f"not a collection: {_short(got)}")
            res = {"len_eq": n == int(v), "len_gte": n >= int(v), "len_lte": n <= int(v)}[op]
            return out(res, f"{op} {v}", f"len {n}")
        if op == "eq_path":
            other = resolve(values, str(v))
            return out(got == other or (_num(got) is not None and _num(got) == _num(other)),
                       f"== {v} ({_short(other)})", got)
        if op == "within_pct_of_path":
            other = _num(resolve(values, str(v["path"])))
            g = _num(got)
            if other is None or g is None:
                return out(False, f"numeric {v['path']}", got)
            ok = abs(g - other) <= abs(other) * float(v["pct"]) / 100.0
            return out(ok, f"within {v['pct']}% of {other:g}", g)
        if op == "max_age":
            when = _as_datetime(got)
            if when is None:
                return out(False, "a date", got)
            age = (now - when).total_seconds()
            days = age / 86400
            if "crit" in v and age > parse_duration(v["crit"]):
                return out(False, f"younger than {v['crit']}", f"{days:.1f}d old ({when.date()})")
            if "warn" in v and age > parse_duration(v["warn"]):
                o = out(True, f"younger than {v['warn']}", f"{days:.1f}d old ({when.date()})")
                o.status = "ok"
                o.warn_only = True
                return o
            return out(True, "fresh", f"{days:.1f}d old ({when.date()})")
        if op in ("max_drop_pct", "monotonic"):
            g = _num(got)
            if g is None:
                return out(False, "a number", got)
            if baseline is None:
                return out(True, "no baseline yet", g)
            if op == "monotonic":
                prev = baseline(a["that"], 400 * 86400)
                if not prev:
                    return out(True, "no previous value", g)
                return out(g >= prev[-1] * 0.98, f"≥ 98% of previous {prev[-1]:g}", g)
            window = parse_duration(a.get("window", "7d"))
            prev = [p for p in baseline(a["that"], window) if p is not None]
            if len(prev) < 3:
                return out(True, f"baseline building ({len(prev)}/3)", g)
            med = statistics.median(prev)
            floor = med * (1 - float(v) / 100.0)
            return out(g >= floor, f"≥ {floor:g} (median {med:g})", g)
        return Outcome(assertion=text, status="unknown", found=f"unhandled operator {op}")
    except Exception as exc:  # noqa: BLE001 - a bad assertion must not take the run down
        return Outcome(assertion=text or str(a), status="unknown",
                       found=f"assertion error: {type(exc).__name__}: {exc}")


# Public names for kinds that reuse the parsing rules.
MISSING = _MISSING
num = _num
as_datetime = _as_datetime


def numeric_paths(assertions: list[dict[str, Any]], values: dict[str, Any]) -> dict[str, float]:
    """Numeric values addressed by any assertion: stored as metrics for baselines."""
    out: dict[str, float] = {}
    for a in assertions:
        p = a.get("that")
        if not p:
            continue
        n = _num(resolve(values, p))
        if n is not None:
            out[p] = n
    for k in ("latency_ms",):
        n = _num(values.get(k))
        if n is not None:
            out.setdefault(k, n)
    return out
