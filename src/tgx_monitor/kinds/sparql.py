"""SPARQL checks: the ``sparql`` kind.

request keys::

    endpoint   (required) the /sparql URL
    ask        an ASK query (inline), or
    select     a SELECT query (inline), or
    file       q/<name>.rq  (a query file under catalogue/queries)
    method     GET (default) | POST  (POST sends application/x-www-form-urlencoded)
    pivot      {key: <col>, value: <col>}: expose ``by.<local name of key>`` = value
    max_rows   the endpoint's ResultSetMaxRows (default 10000), for ``truncated``

Observation values:

* ASK:    ``boolean``
* SELECT: ``rows`` (list of {var: value}, values as plain strings with numbers
          converted), ``count`` (number of rows), ``first`` (rows[0] or {}),
          ``vars``, ``truncated`` (count == max_rows: probably cut off silently),
          ``by`` (when pivot is given; IRIs shortened to their local name).
* always: ``status latency_ms``

Uses ``application/sparql-results+json`` (every Virtuoso and QLever endpoint here
answers it) and keeps parsing in the standard library.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..catalogue import Check
from ..model import Observation
from .base import Context, Kind, register

_LOCAL = re.compile(r"[#/:]([^#/:]+)$")


def local_name(iri: str) -> str:
    m = _LOCAL.search(iri)
    return m.group(1) if m else iri


def _value(cell: dict[str, Any]) -> Any:
    v = cell.get("value")
    dtp = cell.get("datatype", "")
    if dtp.endswith(("#integer", "#int", "#long", "#nonNegativeInteger", "#decimal",
                     "#double", "#float", "#short")):
        try:
            f = float(v)
            return int(f) if f.is_integer() else f
        except (TypeError, ValueError):
            return v
    if dtp.endswith("#boolean"):
        return v in ("true", "1")
    return v


@register
class SparqlKind(Kind):
    name = "sparql"
    required = ("endpoint",)
    vias = ("public", "tgx1", "tgx2", "core")

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        n = sum(k in request for k in ("ask", "select", "file"))
        if n != 1:
            probs.append("sparql needs exactly one of ask, select, file")
        return probs

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        if "file" in r:
            query = ctx.catalogue.query_text(r["file"])
        else:
            query = r.get("ask") or r.get("select")
        headers = {"Accept": "application/sparql-results+json"}
        net_via = "public" if via == "core" else via
        if r.get("method", "GET").upper() == "POST":
            f = await ctx.http.fetch("POST", r["endpoint"], via=net_via, headers={
                **headers, "Content-Type": "application/x-www-form-urlencoded"},
                data={"query": query}, timeout=check.timeout_s)
        else:
            f = await ctx.http.fetch("GET", r["endpoint"], via=net_via,
                                     params={"query": query}, headers=headers,
                                     timeout=check.timeout_s)
        obs = self.from_fetch(f)
        if obs.error or obs.unknown:
            return obs
        if f.status and f.status >= 400:
            obs.values["error_body"] = f.text[:500]
            return obs
        try:
            doc = json.loads(f.text)
        except ValueError:
            obs.values["parse_error"] = "not SPARQL JSON results"
            return obs
        obs.values.pop("body", None)  # large and already parsed; evidence keeps an excerpt
        if "boolean" in doc:
            obs.values["boolean"] = bool(doc["boolean"])
            return obs
        vars_ = doc.get("head", {}).get("vars", [])
        rows = [{k: _value(c) for k, c in b.items()}
                for b in doc.get("results", {}).get("bindings", [])]
        max_rows = int(r.get("max_rows", 10000))
        obs.values.update({
            "vars": vars_, "rows": rows, "count": len(rows),
            "first": rows[0] if rows else {}, "truncated": len(rows) >= max_rows,
        })
        if "pivot" in r:
            k, v = r["pivot"]["key"], r["pivot"]["value"]
            obs.values["by"] = {local_name(str(row.get(k, ""))): row.get(v) for row in rows}
        return obs
