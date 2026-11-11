"""Data kinds: does what a service *holds* agree with where it came from, and do backups exist.

The web and SPARQL kinds answer "is it up". The incidents that hurt were quieter: a
reload that did not land, BridgeDb answering JSON instead of TSV, a batch call that
unioned every input, a Shiny app returning 200 with dead sessions, a backup directory
last written in May. Each kind here turns one of those into values the assertion
engine can judge, and nothing more: no kind decides what "fresh" means, the catalogue
says it with ``max_age``, ``eq_path`` and friends.

Two halves:

* Network kinds (``invariant``, ``compare``, ``roundtrip``, ``shiny``,
  ``browser_artifact``) share one *source resolver*, so "a value from somewhere" is
  written the same way in every check (see :func:`resolve_source`).
* File kinds (``file_age``, ``sqlite_backup``, ``restore_marker``) run in core only and
  read the read-only bind mounts named in ``ctx.mounts``. Every path is resolved and
  confirmed to sit inside its mount, every read is size-bounded, and backups are only
  ever opened as copies in a temp dir. Blocking file work runs in a thread so a slow
  Gluster mount cannot stall the scheduler.

Nothing raises across the kind boundary: problems come back as ``Observation.error``
(the target or roundtrip broke), ``Observation.unknown`` (we could not tell) or values
the assertions turn red.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import gzip
import json
import os
import random
import re
import sqlite3
import stat
import string
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit, urlunsplit

from .. import assertions as A
from ..catalogue import Check
from ..http import NODES, USER_AGENT, Fetched
from ..model import Call, Observation
from ..redact import redact_text
from .base import Context, Kind, register
from .sparql import _value as sparql_value

STEP_EXCERPT = 2000  # body characters kept per roundtrip step (``last`` keeps the full body)
MARKER_CAP = 1024 * 1024  # bytes read from a marker file
PAYLOAD_CAP = 8 * 1024 * 1024  # bytes read from a roundtrip payload file
EMPTY_CELLS = frozenset({"", "N/A", "NA", "null", "None", "-"})
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_DATEISH = re.compile(r"^(\d{4})[-.](\d{2})[-.](\d{2})(?:$|[T ])|^(\d{4})(\d{2})(\d{2})$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# ====================================================================== shared helpers
def _net_via(via: str) -> str:
    """Kinds that may run in core still make HTTP calls through public DNS."""
    return "public" if via in ("core", "", None) or via.startswith("agent:") else via


def _rate_limited(calls: list[Call]) -> bool:
    return any(c.status == 429 for c in calls)


def as_date(v: Any) -> dt.datetime | None:
    """A date in a value: ISO date/datetime, yyyymmdd, or a dotted version 2026.11.07.

    Deliberately narrower than the assertion engine's parser: an integer count must
    never be read as epoch seconds and given an age.
    """
    if isinstance(v, dt.datetime | dt.date):
        return A._as_datetime(v)
    if not isinstance(v, str):
        return None
    s = v.strip()
    m = _DATEISH.match(s)
    if not m:
        return None
    if m.group(1):
        if "." in s[:10]:
            s = s[:10].replace(".", "-")
        return A._as_datetime(s)
    return A._as_datetime(s[:8])


def age_days(v: Any, now: dt.datetime) -> float | None:
    d = as_date(v)
    return None if d is None else round((now - d).total_seconds() / 86400, 2)


def _same(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return False
    if a == b:
        return True
    na, nb = A._num(a), A._num(b)
    if na is not None and nb is not None:
        return na == nb
    return str(a).strip() == str(b).strip()


def relation(a: Any, b: Any) -> str:
    """equal | left_newer | right_newer | incomparable, by date, then number, then text."""
    if a is None or b is None:
        return "incomparable"
    if _same(a, b):
        return "equal"
    da, db = as_date(a), as_date(b)
    if da is not None and db is not None:
        return "equal" if da == db else ("left_newer" if da > db else "right_newer")
    na, nb = A._num(a), A._num(b)
    if na is not None and nb is not None:
        return "left_newer" if na > nb else "right_newer"
    if isinstance(a, str) and isinstance(b, str):
        return "left_newer" if _sort_key(a) > _sort_key(b) else "right_newer"
    return "incomparable"


def _sort_key(s: str) -> tuple[Any, ...]:
    """Natural order, so release 9 sorts before release 10 and 20230810 before 20261110."""
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p)
                 for p in re.split(r"(\d+)", s) if p)


def _group(m: re.Match[str]) -> str:
    return m.group(1) if m.re.groups else m.group(0)


# ====================================================================== source resolver
SOURCE_TYPES = ("sparql", "http_json", "http_regex", "http_list", "http_header", "const")


def source_type(spec: Any) -> str | None:
    if not isinstance(spec, dict):
        return None
    found = [k for k in SOURCE_TYPES if k in spec]
    return found[0] if len(found) == 1 else None


def normalise_source(raw: Any, request: dict[str, Any]) -> Any:
    """Accept the short forms the catalogue uses.

    ``q/name.rq`` (a string) is a SPARQL query file against the request's
    ``endpoint``; a ``sparql`` source without its own endpoint inherits it too.
    """
    if isinstance(raw, str):
        return {"sparql": {"endpoint": request.get("endpoint"), "file": raw}}
    if isinstance(raw, dict) and isinstance(raw.get("sparql"), str):
        raw = {**raw, "sparql": {"file": raw["sparql"]}}
    if isinstance(raw, dict) and isinstance(raw.get("sparql"), dict):
        sp = raw["sparql"]
        if "endpoint" not in sp and request.get("endpoint"):
            raw = {**raw, "sparql": {**sp, "endpoint": request["endpoint"]}}
    return raw


def validate_source(spec: Any, where: str) -> list[str]:
    t = source_type(spec)
    if t is None:
        return [f"{where}: needs exactly one of {', '.join(SOURCE_TYPES)}"]
    body = spec[t]
    if t == "const":
        return []
    if not isinstance(body, dict):
        return [f"{where}: {t} needs a mapping"]
    need = {"sparql": ("endpoint",), "http_json": ("url", "path"), "http_regex": ("url", "re"),
            "http_list": ("url", "re"), "http_header": ("url", "header")}[t]
    probs = [f"{where}: {t} missing {k!r}" for k in need if not body.get(k)]
    if t == "sparql" and sum(k in body for k in ("select", "ask", "file")) != 1:
        probs.append(f"{where}: sparql needs exactly one of select, ask, file")
    for k in ("re", "extract"):
        if k in body or k in spec:
            try:
                re.compile(str(body.get(k) or spec.get(k)))
            except re.error as exc:
                probs.append(f"{where}: bad regex {k}: {exc}")
    if t == "http_list" and body.get("pick", "newest") not in ("newest", "previous", "all"):
        probs.append(f"{where}: http_list pick must be newest, previous or all")
    return probs


async def _sparql_source(b: dict[str, Any], ctx: Context, via: str,
                         timeout: float) -> tuple[Any, list[Call], str | None]:
    query = ctx.catalogue.query_text(b["file"]) if "file" in b else (b.get("select")
                                                                     or b.get("ask"))
    headers = {"Accept": "application/sparql-results+json"}
    if str(b.get("method", "GET")).upper() == "POST":
        f = await ctx.http.fetch("POST", b["endpoint"], via=via, data={"query": query},
                                 headers={**headers, "Content-Type":
                                          "application/x-www-form-urlencoded"},
                                 timeout=timeout)
    else:
        f = await ctx.http.fetch("GET", b["endpoint"], via=via, params={"query": query},
                                 headers=headers, timeout=timeout)
    if not f.ok:
        return None, [f.call], f.error or f"HTTP {f.status}"
    try:
        doc = json.loads(f.text)
    except ValueError:
        return None, [f.call], "not SPARQL JSON results"
    if "boolean" in doc:
        return bool(doc["boolean"]), [f.call], None
    bindings = doc.get("results", {}).get("bindings", [])
    vars_ = doc.get("head", {}).get("vars", [])
    col = b.get("value") or (vars_[0] if len(vars_) == 1 else None)
    if col is None:
        return None, [f.call], f"several columns {vars_}: say which with value"
    if not bindings:
        return None, [f.call], "no rows"
    if col not in bindings[0]:
        return None, [f.call], f"column {col!r} not in first row"
    return sparql_value(bindings[0][col]), [f.call], None


async def _http_source(t: str, b: dict[str, Any], ctx: Context, via: str,
                       timeout: float) -> tuple[Any, list[Call], str | None]:
    method = str(b.get("method", "HEAD" if t == "http_header" else "GET")).upper()
    f = await ctx.http.fetch(method, b["url"], via=via, headers=b.get("headers"),
                             params=b.get("params"), timeout=timeout)
    calls = [f.call]
    if not f.ok:
        return None, calls, f.error or f"HTTP {f.status}"
    if t == "http_header":
        v = f.headers.get(str(b["header"]).lower())
        return v, calls, None if v is not None else f"no header {b['header']!r}"
    if t == "http_json":
        try:
            doc = json.loads(f.text)
        except ValueError:
            return None, calls, "body is not JSON"
        v = A.resolve(doc, str(b["path"]))
        return (None, calls, f"no {b['path']!r} in JSON") if v is A._MISSING else (v, calls,
                                                                                 None)
    rx = re.compile(str(b["re"]), re.M)
    if t == "http_regex":
        m = rx.search(f.text)
        return (_group(m), calls, None) if m else (None, calls, f"no match for /{b['re']}/")
    found = sorted({_group(m) for m in rx.finditer(f.text)}, key=_sort_key)
    pick = b.get("pick", "newest")
    if pick == "all":
        return found, calls, None
    idx = -1 if pick == "newest" else -2
    if len(found) < -idx:
        return None, calls, f"{len(found)} matches, cannot pick {pick}"
    return found[idx], calls, None


async def resolve_source(spec: Any, ctx: Context, via: str,
                         timeout: float = 30.0) -> tuple[Any, list[Call], str | None]:
    """One value from one source: ``(value, calls, error)``. Never raises.

    ``spec`` is ``{<type>: {...}}`` with type one of :data:`SOURCE_TYPES`. Any source may
    add ``extract: <regex>`` (group 1 of the first match in the value, e.g. ``(\\d{8})``
    to pull a release date out of a dataset IRI) and ``via`` (overrides the check's
    vantage point for this source only, e.g. ``public`` for an upstream on GitHub).
    """
    t = source_type(spec)
    if t is None:
        return None, [], f"not a source: needs exactly one of {', '.join(SOURCE_TYPES)}"
    if t == "const":
        return spec["const"], [], None
    b = spec[t]
    if not isinstance(b, dict):
        return None, [], f"{t} needs a mapping"
    net = _net_via(spec.get("via") or b.get("via") or via)
    try:
        if t == "sparql":
            value, calls, err = await _sparql_source(b, ctx, net, timeout)
        else:
            value, calls, err = await _http_source(t, b, ctx, net, timeout)
    except Exception as exc:  # noqa: BLE001 - a bad spec must read as a finding, not a crash
        return None, [], f"{t}: {type(exc).__name__}: {exc}"
    if err is None and spec.get("extract") and value is not None:
        m = re.search(str(spec["extract"]), str(value))
        value, err = (_group(m), None) if m else (None, f"extract /{spec['extract']}/ "
                                                        f"did not match {str(value)[:80]!r}")
    return value, calls, err


async def _resolve_named(named: dict[str, Any], request: dict[str, Any], ctx: Context,
                         via: str, timeout: float) -> tuple[dict[str, Any], list[Call],
                                                            dict[str, str], bool]:
    """Resolve several sources concurrently; returns values, calls, errors, all_soft."""
    specs = {k: normalise_source(v, request) for k, v in named.items()}
    res = await asyncio.gather(*(resolve_source(s, ctx, via, timeout) for s in specs.values()))
    values, calls, errors, soft = {}, [], {}, True
    for (name, spec), (v, c, e) in zip(specs.items(), res, strict=True):
        values[name] = v
        calls.extend(c)
        if e is not None:
            errors[name] = e
            if not (isinstance(spec, dict) and spec.get("on_error") == "unknown"):
                soft = False
    return values, calls, errors, soft


def _source_failure(obs: Observation, errors: dict[str, str], soft: bool) -> Observation:
    msg = "; ".join(f"{k}: {v}" for k, v in errors.items())
    for k, v in errors.items():
        obs.values[f"{k}_error"] = v
    if _rate_limited(obs.calls):
        obs.unknown = f"rate limited (HTTP 429): {msg}"
    elif soft:
        obs.unknown = f"source unavailable: {msg}"
    else:
        obs.error = msg
    obs.evidence = redact_text(msg)
    return obs


class _SourceKind(Kind):
    sides: tuple[str, ...] = ("left", "right")

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        named = {s: request.get(s) for s in cls.sides}
        named.update(request.get("sources") or {})
        for name, raw in named.items():
            if raw is None:
                continue  # reported by the required-keys check
            probs += validate_source(normalise_source(raw, request), name)
        return probs


@register
class InvariantKind(_SourceKind):
    """Two values that must agree, e.g. COUNT(DISTINCT ?s) vs void:distinctSubjects.

    request: ``left``, ``right`` (sources), optional ``endpoint`` (default for the
    short ``q/file.rq`` form). values: ``left right equal`` (+ ``diff`` = right - left
    when both are numbers).
    """

    name = "invariant"
    required = ("left", "right")
    vias = ("public", "tgx1", "tgx2", "core")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        vals, calls, errs, soft = await _resolve_named(
            {"left": r["left"], "right": r["right"]}, r, ctx, via, check.timeout_s)
        obs = Observation(values=dict(vals), calls=calls)
        if errs:
            return _source_failure(obs, errs, soft)
        obs.values["equal"] = _same(vals["left"], vals["right"])
        nl, nr = A._num(vals["left"]), A._num(vals["right"])
        if nl is not None and nr is not None and not isinstance(vals["left"], bool):
            obs.values["diff"] = nr - nl
        if not obs.values["equal"]:
            obs.evidence = f"left={vals['left']!r} right={vals['right']!r}"
        return obs


@register
class CompareKind(_SourceKind):
    """Freshness against upstream: the endpoint's release vs the newest one published.

    request: ``left``, ``right``, optional ``sources: {name: <source>}`` and
    ``endpoint``. values: ``left right`` and each named source, ``equal``,
    ``relation`` (equal | left_newer | right_newer | incomparable), and for every value
    that reads as a date (ISO, yyyymmdd, 2026.11.07) ``<name>_date`` (ISO, for
    ``max_age``) and ``<name>_age_days``.
    A source with ``on_error: unknown`` (an upstream we do not own) makes the check
    unknown rather than failed when it cannot be read.
    """

    name = "compare"
    required = ("left", "right")
    vias = ("public", "tgx1", "tgx2", "core")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        named = {"left": r["left"], "right": r["right"], **(r.get("sources") or {})}
        vals, calls, errs, soft = await _resolve_named(named, r, ctx, via, check.timeout_s)
        obs = Observation(values=dict(vals), calls=calls)
        now = ctx.now()
        for k, v in vals.items():
            d = as_date(v)
            if d is not None:  # ISO form too, so max_age works on 2026.11.07-style versions
                obs.values[f"{k}_date"] = d.isoformat(timespec="seconds")
                obs.values[f"{k}_age_days"] = age_days(v, now)
        if errs:
            return _source_failure(obs, errs, soft)
        obs.values["equal"] = _same(vals["left"], vals["right"])
        obs.values["relation"] = relation(vals["left"], vals["right"])
        obs.evidence = ", ".join(f"{k}={v!r}"[:200] for k, v in vals.items())
        return obs


# ====================================================================== roundtrip
def _fill(text: Any, caps: dict[str, Any]) -> tuple[Any, list[str]]:
    """Replace ``{name}`` with earlier captures; returns the names it could not fill."""
    if not isinstance(text, str):
        return text, []
    missing: list[str] = []

    def sub(m: re.Match[str]) -> str:
        if m.group(1) in caps and caps[m.group(1)] is not None:
            return str(caps[m.group(1)])
        missing.append(m.group(1))
        return m.group(0)

    return _PLACEHOLDER.sub(sub, text), missing


def _text_values(text: str) -> dict[str, Any]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    tsv = [ln.split("\t") for ln in lines]
    out: dict[str, Any] = {"lines": len(lines), "first_line": lines[0] if lines else "",
                           "tsv": tsv, "tsv_cols": len(tsv[0]) if tsv else 0}
    if text.lstrip()[:1] in ("{", "["):  # only parse what looks like JSON
        with contextlib.suppress(ValueError):
            out["json"] = json.loads(text)
    return out


def _cells(rows: list[list[str]], col: int) -> list[str]:
    return [r[col].strip() if len(r) > col else "" for r in rows]


def _set_of(cell: str, sep: str) -> frozenset[str]:
    return frozenset(x.strip() for x in cell.split(sep)
                     if x.strip() and x.strip() not in EMPTY_CELLS)


def derive(spec: dict[str, Any], rows: list[list[str]]) -> Any:
    """One derived number or list from TSV rows. Columns are 0-based, like ``tsv.0.2``.

    ``tsv_nonempty_col: N`` with ``of_rows: all | <int>``: share of rows whose column N
    is filled (``N/A``, ``-`` and blanks count as empty); an int denominator is the
    number of inputs sent, for services that drop unmapped rows.
    ``tsv_distinct: N``: sorted distinct values of column N.
    ``tsv_col: N``: column N in row order.
    ``tsv_by_key: {key: K, value: V}``: {column K: column V}.
    ``tsv_count_by_key: {key: K, value: V, sep: ","}``: {column K: items in column V}.
    ``tsv_distinct_sets: {col: N, sep: ","}``: how many different item sets column N
    holds (a batch call that unions its inputs gives 1 for every row).
    """
    if "tsv_nonempty_col" in spec:
        col = int(spec["tsv_nonempty_col"])
        filled = sum(1 for c in _cells(rows, col) if c not in EMPTY_CELLS)
        of = spec.get("of_rows", "all")
        denom = len(rows) if of in ("all", None) else int(of)
        return round(filled / denom, 6) if denom else None
    if "tsv_distinct" in spec:
        return sorted(set(_cells(rows, int(spec["tsv_distinct"]))), key=_sort_key)
    if "tsv_col" in spec:
        return _cells(rows, int(spec["tsv_col"]))
    if "tsv_by_key" in spec:
        s = spec["tsv_by_key"]
        return dict(zip(_cells(rows, int(s["key"])), _cells(rows, int(s["value"])),
                        strict=True))
    if "tsv_count_by_key" in spec:
        s = spec["tsv_count_by_key"]
        sep = s.get("sep", ",")
        return {k: len(_set_of(v, sep)) for k, v in zip(
            _cells(rows, int(s["key"])), _cells(rows, int(s["value"])), strict=True)}
    if "tsv_distinct_sets" in spec:
        s = spec["tsv_distinct_sets"]
        return len({_set_of(c, s.get("sep", ",")) for c in _cells(rows, int(s["col"]))})
    raise ValueError(f"unknown derive {sorted(spec)}")


def _capture(spec: dict[str, Any], f: Fetched, parsed: Any) -> Any:
    if "regex" in spec:
        m = re.search(str(spec["regex"]), f.text, re.M)
        return _group(m) if m else None
    if "json_path" in spec:
        v = A.resolve(parsed, str(spec["json_path"])) if parsed is not None else A._MISSING
        return None if v is A._MISSING else v
    if "header" in spec:
        return f.headers.get(str(spec["header"]).lower())
    return None


@register
class RoundtripKind(Kind):
    """Ordered requests with captured values, for features rather than presence.

    request: ``base`` (optional; relative step urls join it), ``steps`` (list). Each
    step: ``method`` (GET), ``url`` (may hold ``{name}`` from earlier captures; also
    filled in headers, params and data), ``headers``, ``params``, one of ``data`` /
    ``json`` / ``payload`` (a file under catalogue/payloads), and ``capture: {name:
    {regex} | {json_path} | {header}}``. Optional ``derive: {name: <op>}`` on the
    request computes values from the last step's TSV (see :func:`derive`).

    values: ``steps`` (status, latency_ms, body excerpt, content_type, json), ``captures``,
    ``last`` (status latency_ms body headers json lines first_line tsv tsv_cols size),
    ``derived``, ``completed``.
    """

    name = "roundtrip"
    required = ("steps",)
    vias = ("public", "tgx1", "tgx2", "core")

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        steps = request.get("steps")
        if not isinstance(steps, list) or not steps:
            return probs + ["steps must be a non-empty list"]
        for i, s in enumerate(steps):
            if not isinstance(s, dict) or not s.get("url"):
                probs.append(f"step {i}: needs url")
                continue
            if sum(k in s for k in ("data", "json", "payload")) > 1:
                probs.append(f"step {i}: use one of data, json, payload")
            for name, cap in (s.get("capture") or {}).items():
                if not isinstance(cap, dict) or len(
                        {"regex", "json_path", "header"} & set(cap)) != 1:
                    probs.append(f"step {i}: capture {name} needs one of regex, json_path, "
                                 "header")
        for name, d in (request.get("derive") or {}).items():
            try:
                if not isinstance(d, dict):
                    raise ValueError("needs a mapping")
                derive(d, [])
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                probs.append(f"derive {name}: {exc}")
        return probs

    @staticmethod
    def _payload(ctx: Context, ref: str) -> str:
        root = (ctx.catalogue.root / "payloads").resolve()
        p = (root / str(ref).removeprefix("payloads/")).resolve()
        if root not in p.parents:
            raise ValueError(f"payload path escapes catalogue/payloads: {ref}")
        with p.open("rb") as fh:
            return fh.read(PAYLOAD_CAP).decode("utf-8", "replace")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        net = _net_via(via)
        caps: dict[str, Any] = {}
        steps: list[dict[str, Any]] = []
        obs = Observation(values={"steps": steps, "captures": caps, "completed": False})
        last: Fetched | None = None
        last_vals: dict[str, Any] = {}
        for i, s in enumerate(r["steps"]):
            url, miss = _fill(s["url"], caps)
            if r.get("base") and not urlsplit(url).scheme:
                url = str(r["base"]).rstrip("/") + "/" + url.lstrip("/")
            headers = {k: _fill(v, caps)[0] for k, v in (s.get("headers") or {}).items()}
            params = {k: _fill(v, caps)[0] for k, v in (s.get("params") or {}).items()} \
                if s.get("params") else None
            data: Any = s.get("data")
            if isinstance(data, str):
                data, m2 = _fill(data, caps)
                miss += m2
            if s.get("payload"):  # sent verbatim: a payload file is data, not a template
                try:
                    data = await asyncio.to_thread(self._payload, ctx, s["payload"])
                except (OSError, ValueError) as exc:
                    obs.error = f"step {i}: payload {s['payload']}: {exc}"
                    return obs
            if miss:
                obs.error = f"step {i}: no captured value for {', '.join(sorted(set(miss)))}"
                break
            f = await ctx.http.fetch(s.get("method", "GET"), url, via=net, params=params,
                                     headers=headers or None, data=data,
                                     json_body=s.get("json"), follow=s.get("follow", True),
                                     timeout=check.timeout_s)
            obs.calls.append(f.call)
            if f.error:
                obs.error = f"step {i}: {f.error}"
                break
            tv = _text_values(f.text)
            steps.append({"status": f.status, "latency_ms": f.ms,
                          "content_type": f.headers.get("content-type", ""),
                          "body": f.text[:STEP_EXCERPT], "json": tv.get("json")})
            for name, cap in (s.get("capture") or {}).items():
                caps[name] = _capture(cap, f, tv.get("json"))
            last, last_vals = f, tv
        else:
            obs.values["completed"] = True
        if _rate_limited(obs.calls):
            obs.unknown, obs.error = "rate limited (HTTP 429)", None
        if last is not None:
            obs.values["last"] = {"status": last.status, "latency_ms": last.ms,
                                  "body": last.text, "headers": last.headers,
                                  "size": len(last.text), **last_vals}
            obs.values["status"] = last.status
            obs.evidence = redact_text(last.text[:4000])
            derived: dict[str, Any] = {}
            for name, d in (r.get("derive") or {}).items():
                try:
                    derived[name] = derive(d, last_vals["tsv"])
                except (ValueError, TypeError, KeyError) as exc:
                    derived[f"{name}_error"] = str(exc)
            obs.values["derived"] = derived
        if obs.error and not obs.evidence:
            obs.evidence = obs.error
        return obs


# ====================================================================== shiny
def _base(url: str) -> str:
    p = urlsplit(url)
    path = p.path if p.path.endswith("/") else p.path.rsplit("/", 1)[0] + "/"
    return urlunsplit((p.scheme, p.netloc, path or "/", "", ""))


def sockjs_ws_url(base: str, robust: bool = False) -> str:
    """``wss://host/app/__sockjs__/<3 digits>/<8 chars>/websocket`` (SockJS raw session).

    ``robust`` adds the ``n=<18 chars>`` reconnect id Shiny Server's robust transport uses.
    """
    p = urlsplit(base)
    rnd = random.SystemRandom()
    sess = "".join(rnd.choices(string.ascii_lowercase + string.digits, k=8))
    server = f"{rnd.randrange(1000):03d}"
    prefix = ("n=" + "".join(rnd.choices(string.ascii_letters + string.digits, k=18)) + "/"
              if robust else "")
    scheme = "wss" if p.scheme == "https" else "ws"
    return urlunsplit((scheme, p.netloc, f"{p.path}__sockjs__/{prefix}{server}/{sess}/websocket",
                       "", ""))


async def open_sockjs(ws_url: str, via: str, wait_s: float) -> tuple[bool, float, str]:
    """Open one SockJS websocket, wait for the ``o`` frame, close. (opened, ms, note)."""
    from websockets.asyncio.client import connect  # imported late: only shiny needs it

    kw: dict[str, Any] = {"open_timeout": wait_s, "close_timeout": 2, "proxy": None,
                          "user_agent_header": USER_AGENT, "max_size": 1 << 20}
    host = urlsplit(ws_url).hostname or ""
    if via in NODES:  # connect to the node, keep the real name for Host and SNI
        kw.update(host=NODES[via], port=urlsplit(ws_url).port
                  or (443 if ws_url.startswith("wss") else 80))
        if ws_url.startswith("wss"):
            kw["server_hostname"] = host
    t0 = time.perf_counter()
    try:
        async with connect(ws_url, **kw) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=wait_s)
            ms = round((time.perf_counter() - t0) * 1000, 1)
            text = msg if isinstance(msg, str) else msg.decode("utf-8", "replace")
            return text.startswith("o"), ms, f"first frame {text[:40]!r}"
    except TimeoutError:
        return False, round((time.perf_counter() - t0) * 1000, 1), f"no frame in {wait_s:g}s"
    except Exception as exc:  # noqa: BLE001 - every failure to open is the measurement
        return False, round((time.perf_counter() - t0) * 1000, 1), \
            f"{type(exc).__name__}: {exc}"[:300]


@register
class ShinyKind(Kind):
    """A Shiny app whose page answers 200 can still have dead sessions: open one.

    request: ``url``, ``ws_wait`` (seconds, default 10), ``robust`` (false), ``session``
    (true; false skips the websocket). values: ``page_status page_has_shiny sockjs
    websocket ws_open ws_ms ws_note``. Each session costs the server an R process, so
    the socket is closed as soon as the open frame arrives; keep these at 15 min or slower.
    """

    name = "shiny"
    required = ("url",)
    vias = ("public", "tgx1", "tgx2")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        base = _base(str(r["url"]))
        page = await ctx.http.get(str(r["url"]), via=via, timeout=check.timeout_s)
        obs = self.from_fetch(page)
        if obs.error or obs.unknown:
            return obs
        obs.values.pop("body", None)
        obs.values.update({"page_status": page.status,
                           "page_has_shiny": "shiny" in page.text.lower()})
        info = await ctx.http.get(base + "__sockjs__/info", via=via, timeout=check.timeout_s)
        obs.calls.append(info.call)
        sock: dict[str, Any] = {}
        if info.ok:
            try:
                sock = json.loads(info.text)
            except ValueError:
                obs.values["sockjs_error"] = "info is not JSON"
        else:
            obs.values["sockjs_error"] = info.error or f"HTTP {info.status}"
        obs.values.update({"sockjs": sock, "sockjs_status": info.status,
                           "websocket": bool(sock.get("websocket"))})
        if r.get("session", True) and sock.get("websocket"):
            ws_url = sockjs_ws_url(base, bool(r.get("robust")))
            opened, ms, note = await open_sockjs(ws_url, via, float(r.get("ws_wait", 10)))
            obs.calls.append(Call("WS", ws_url.rsplit("/__sockjs__/", 1)[0] + "/__sockjs__/…",
                                  via=via, ok=opened, ms=ms, note=note))
            obs.values.update({"ws_open": opened, "ws_ms": ms, "ws_note": note})
        else:
            obs.values.update({"ws_open": False, "ws_note": "not attempted"})
        return obs


# ====================================================================== browser artifact
def _find_page(doc: Any, page_id: str) -> dict[str, Any] | None:
    pages = doc.get("pages") if isinstance(doc, dict) else None
    if isinstance(pages, dict):
        p = pages.get(page_id)
        return p if isinstance(p, dict) else None
    if isinstance(pages, list):
        for p in pages:
            if isinstance(p, dict) and p.get("id") == page_id:
                return p
    return None


@register
class BrowserArtifactKind(Kind):
    """Reads the JSON the 6-hourly Playwright run commits; Chromium never runs on the cluster.

    request: ``url`` (raw JSON, e.g. on the repo's history branch), ``page`` (id).
    The artifact is ``{generated_at, pages: {id: {...}}}`` or ``pages: [{id, ...}]``.
    values: ``generated_at age_h page`` (that page's dict: ok, title, console_errors,
    checks...), ``page_found``, ``pages`` (ids present).
    """

    name = "browser_artifact"
    required = ("url", "page")
    vias = ("public", "core")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        f = await ctx.http.get(str(r["url"]), via="public", timeout=check.timeout_s,
                               headers={"Accept": "application/json"})
        obs = self.from_fetch(f, parse_json=True)
        if obs.error or obs.unknown:
            return obs
        if f.status == 404 or "json" not in obs.values:
            # Not published yet (first browser.yml run pending) or not JSON: we cannot
            # tell how the page renders, which is unknown, not a broken page.
            obs.unknown = f"browser artifact not available (HTTP {f.status})"
            return obs
        doc = obs.values.pop("json")
        obs.values.pop("body", None)
        page = _find_page(doc, str(r["page"]))
        gen = doc.get("generated_at") if isinstance(doc, dict) else None
        when = A._as_datetime(gen) if isinstance(gen, str) else None
        pages = doc.get("pages") if isinstance(doc, dict) else None
        obs.values.update({
            "generated_at": gen, "page": page or {}, "page_found": page is not None,
            "age_h": round((ctx.now() - when).total_seconds() / 3600, 2) if when else None,
            "pages": sorted(pages) if isinstance(pages, dict) else
            [p.get("id") for p in pages or [] if isinstance(p, dict)],
        })
        if page is not None:
            obs.evidence = redact_text(json.dumps(page, indent=1)[:4000])
        return obs


# ====================================================================== file kinds
def _mount_root(ctx: Context, alias: Any) -> Path | None:
    p = ctx.mounts.get(str(alias))
    if p is None:
        return None
    p = Path(p)
    return p.resolve() if p.is_dir() else None


def _safe_pattern(pattern: str) -> str:
    if not pattern or pattern.startswith("/") or ".." in Path(pattern).parts:
        raise ValueError(f"glob {pattern!r} must be relative and stay inside the mount")
    return pattern


def list_entries(root: Path, pattern: str, recursive: bool = False,
                 want: str = "file") -> list[tuple[Path, float, int]]:
    """(path, mtime, size) of matches inside ``root``, oldest first.

    Symlinks that resolve outside the mount are dropped, so a stray link cannot make
    the monitor read the rest of the host.
    """
    pattern = _safe_pattern(pattern)
    out = []
    for p in root.rglob(pattern) if recursive else root.glob(pattern):
        try:
            rp = p.resolve()
            if root not in rp.parents:
                continue
            st = rp.stat()
        except OSError:
            continue
        if (want == "file" and not rp.is_file()) or (want == "dir" and not rp.is_dir()):
            continue
        out.append((p, st.st_mtime, st.st_size if rp.is_file() else 0))
    out.sort(key=lambda e: (e[1], e[0].name))
    return out


def open_inside(root: Path, path: Path) -> BinaryIO:
    """Open ``path`` for reading only if what was opened is a regular file inside ``root``.

    Checked on the open descriptor, not the name: a file swapped for a symlink after
    :func:`list_entries` looked at it (other services write these directories) cannot
    redirect the read to /run/secrets or anywhere else, and a FIFO cannot hang the worker.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path.name} is not a regular file")
        try:
            real = Path(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:  # no /proc: fall back to the name
            real = Path(path).resolve()
        if root not in real.parents:
            raise ValueError(f"{path.name} resolves outside the mount")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def scan_gzip(path: Path, max_bytes: int, grep: str | None = None,
              tail: int = 0, root: Path | None = None) -> dict[str, Any]:
    """Stream-decompress to prove the archive is whole (``gzip -t``), optionally grep it."""
    rx = re.compile(grep.encode()) if grep else None
    out: dict[str, Any] = {"gzip_ok": None, "gzip_bytes": 0}
    hits, keep, n = 0, [], 0
    want_lines = rx is not None or tail > 0
    try:
        raw = open_inside(root, path) if root is not None else open(path, "rb")  # noqa: SIM115
        with raw, gzip.GzipFile(fileobj=raw, mode="rb") as fh:
            if want_lines:
                while line := fh.readline(1 << 16):
                    n += len(line)
                    if n > max_bytes:
                        out["gzip_note"] = f"stopped after {max_bytes} bytes"
                        return out
                    if rx is not None and rx.search(line):
                        hits += 1
                    if tail:
                        keep = (keep + [line[:300]])[-tail:]
            else:
                while chunk := fh.read(1 << 20):
                    n += len(chunk)
                    if n > max_bytes:
                        out["gzip_note"] = f"stopped after {max_bytes} bytes"
                        return out
        out["gzip_ok"] = True
    except (OSError, EOFError, zlib.error) as exc:
        out.update(gzip_ok=False, gzip_note=f"{type(exc).__name__}: {exc}"[:200])
    out["gzip_bytes"] = n
    if rx is not None:
        out["grep_count"] = hits
    if tail:
        out["tail"] = [b.decode("utf-8", "replace").rstrip("\n") for b in keep]
    return out


def file_age_values(root: Path, r: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    entries = list_entries(root, str(r.get("glob", "*")), bool(r.get("recursive")),
                           str(r.get("type", "file")))
    small = int(r.get("small_bytes", 1))
    v: dict[str, Any] = {
        "exists": True, "count": len(entries), "total_size": sum(e[2] for e in entries),
        "names": [str(e[0].relative_to(root)) for e in reversed(entries[-5:])],
        "small_count": sum(1 for e in entries if e[2] < small and r.get("type") != "dir"),
    }
    if not entries:
        return v
    newest, mtime, size = entries[-1]
    when = dt.datetime.fromtimestamp(mtime, tz=dt.UTC)
    v.update({"newest_name": str(newest.relative_to(root)), "newest_mtime":
              when.isoformat(timespec="seconds"), "newest_size": size,
              "newest_age_h": round((now - when).total_seconds() / 3600, 2)})
    if len(entries) > 1:
        prev = entries[-2][2]
        v["prev_size"] = prev
        v["size_change_pct"] = round((size - prev) / prev * 100, 2) if prev else None
    if newest.name.endswith(".gz") and r.get("verify_gzip", True):
        scan = r.get("scan") or {}
        v.update(scan_gzip(newest.resolve(), int(r.get("max_bytes", 4 << 30)),
                           scan.get("grep"), int(scan.get("tail", 0)), root=root))
    return v


def _check_sqlite(newest: Path, tables: list[str], max_bytes: int, tmp_root: str | None,
                  quick: bool, root: Path | None = None) -> dict[str, Any]:
    """Copy (decompressing .gz) into a temp dir, then integrity_check and count rows."""
    out: dict[str, Any] = {"tables": {}}
    with tempfile.TemporaryDirectory(prefix="tgxmon-sqlite-", dir=tmp_root) as td:
        copy = Path(td) / "copy.db"
        n = 0
        try:
            raw = open_inside(root, newest) if root is not None else open(newest, "rb")  # noqa: SIM115
            src = gzip.GzipFile(fileobj=raw, mode="rb") if newest.name.endswith(".gz") else raw
            with raw, src, copy.open("wb") as dst:
                while chunk := src.read(1 << 20):
                    n += len(chunk)
                    if n > max_bytes:
                        out["integrity"] = f"not checked: larger than {max_bytes} bytes"
                        return out
                    dst.write(chunk)
        except (OSError, EOFError, zlib.error) as exc:
            out["integrity"] = f"copy failed: {type(exc).__name__}: {exc}"[:300]
            return out
        out["copied_bytes"] = n
        con = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        try:
            rows = con.execute("PRAGMA quick_check" if quick else
                               "PRAGMA integrity_check").fetchall()
            out["integrity"] = "ok" if rows == [("ok",)] else "; ".join(
                str(x[0]) for x in rows[:5])
            names = {x[0] for x in con.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
            for t in tables:
                if _IDENT.match(t) and t in names:
                    out["tables"][t] = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                else:
                    out["tables"][t] = None
                    out.setdefault("missing_tables", []).append(t)
        except sqlite3.DatabaseError as exc:
            out["integrity"] = f"{type(exc).__name__}: {exc}"[:300]
        finally:
            con.close()
    return out


class _FileKind(Kind):
    vias = ("core",)

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        root = _mount_root(ctx, r.get("mount"))
        if root is None:
            return Observation(values={"exists": False},
                               unknown=f"mount not available: {r.get('mount')}")
        try:
            values = await asyncio.to_thread(self.read, root, r, ctx)
        except (OSError, ValueError, sqlite3.Error) as exc:
            return Observation(values={"exists": True},
                               unknown=f"{type(exc).__name__}: {exc}"[:500])
        call = Call("READ", f"mount:{r.get('mount')}/{r.get('glob') or r.get('file', '')}",
                    via="file", ok=True, note=str(values.get("newest_name", ""))[:200])
        return Observation(values=values, calls=[call],
                           evidence=redact_text(json.dumps(values, default=str)[:4000]))

    def read(self, root: Path, r: dict[str, Any], ctx: Context) -> dict[str, Any]:
        raise NotImplementedError


@register
class FileAgeKind(_FileKind):
    """Does a backup exist, is it recent, is it the usual size, does it decompress.

    request: ``mount`` (alias in ctx.mounts), ``glob`` ("*"; may hold directories,
    e.g. ``*/dump.sql.gz``), ``recursive`` (false), ``type`` (file | dir),
    ``small_bytes`` (1: files below this count as ``small_count``, e.g. a 20 B empty
    gzip), ``verify_gzip`` (true), ``scan: {grep: <regex>, tail: <n>}`` over the
    decompressed newest .gz, ``max_bytes`` (4 GiB decompression cap).

    values: ``exists count newest_name newest_mtime newest_age_h newest_size prev_size
    size_change_pct total_size small_count names`` (newest 5), plus ``gzip_ok
    gzip_bytes [grep_count tail]`` when the newest ends in .gz. No match is ``count:
    0``, so ``{that: count, gte: 1, label: a backup exists}`` shows a missing backup.
    """

    name = "file_age"
    required = ("mount",)

    def read(self, root: Path, r: dict[str, Any], ctx: Context) -> dict[str, Any]:
        return file_age_values(root, r, ctx.now())


@register
class SqliteBackupKind(_FileKind):
    """The newest SQLite backup opens, passes integrity_check and has its rows.

    request: ``mount``, ``glob``, ``tables`` (names to count), ``quick`` (false: use
    quick_check), ``max_bytes`` (2 GiB copy cap). values: ``integrity`` ("ok" or the
    first problems), ``tables.<name>`` (row count, None if absent), ``missing_tables``,
    plus every file_age value. The copy goes to a temp dir and is deleted afterwards;
    the backup itself is never opened by SQLite.
    """

    name = "sqlite_backup"
    required = ("mount", "glob")

    def read(self, root: Path, r: dict[str, Any], ctx: Context) -> dict[str, Any]:
        v = file_age_values(root, {**r, "verify_gzip": False}, ctx.now())
        if not v["count"]:
            v.update(integrity="no backup", tables={})
            return v
        newest = (root / v["newest_name"]).resolve()
        v.update(_check_sqlite(newest, [str(t) for t in r.get("tables") or []],
                               int(r.get("max_bytes", 2 << 30)),
                               ctx.env.get("TGXMON_TMP"), bool(r.get("quick")), root=root))
        return v


def parse_marker(text: str, fmt: str) -> dict[str, Any]:
    if fmt == "json":
        doc = json.loads(text)
        return doc if isinstance(doc, dict) else {"value": doc}
    if fmt == "kv":  # key=value or key: value per line (manifest.txt, .manifest)
        out: dict[str, Any] = {}
        for ln in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*[=:]\s*(.*?)\s*$", ln)
            if m:
                raw = m.group(2)
                n = A._num(raw)
                out[m.group(1)] = (int(raw) if re.fullmatch(r"-?\d+", raw)
                                   else n if n is not None else raw)
        return out
    return {"text": text.strip(), "fields": text.split()}


@register
class RestoreMarkerKind(_FileKind):
    """A restore-verify job proved the backup restores; read what it wrote.

    request: ``mount``, ``file`` (a path or glob; the newest match is read),
    ``format`` (json | kv | text). values: the marker's keys (``text`` and ``fields``
    for text), ``exists``, ``marker_name``, ``mtime_age_h``, and ``age_h``: from the
    marker's own ``verified_at``/``finished_at``/``timestamp``/``generated_at`` when it
    has one, else the file's mtime.
    """

    name = "restore_marker"
    required = ("mount", "file")

    def read(self, root: Path, r: dict[str, Any], ctx: Context) -> dict[str, Any]:
        entries = list_entries(root, str(r["file"]))
        if not entries:
            return {"exists": False}
        path, mtime, size = entries[-1]
        with open_inside(root, path) as fh:
            text = fh.read(MARKER_CAP).decode("utf-8", "replace")
        fmt = str(r.get("format", "json"))
        try:
            doc = parse_marker(text, fmt)
        except ValueError as exc:
            return {"exists": True, "parse_error": f"not {fmt}: {exc}"[:200]}
        now = ctx.now()
        m_age = round((now - dt.datetime.fromtimestamp(mtime, tz=dt.UTC)).total_seconds()
                      / 3600, 2)
        age = m_age
        for k in ("verified_at", "finished_at", "timestamp", "generated_at"):
            when = A._as_datetime(doc.get(k)) if isinstance(doc.get(k), str) else None
            if when is not None:
                age = round((now - when).total_seconds() / 3600, 2)
                break
        return {**doc, "exists": True, "marker_name": str(path.relative_to(root)),
                "marker_size": size, "mtime_age_h": m_age, "age_h": age}


__all__ = ["resolve_source", "derive", "relation", "as_date", "list_entries", "scan_gzip",
           "open_inside", "sockjs_ws_url", "open_sockjs"]
