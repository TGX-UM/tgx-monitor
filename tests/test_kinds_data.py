"""Data and file kinds: source resolver, invariant/compare, roundtrip, shiny, browser
artifacts, backups. Offline: HTTP is a fake, the websocket server is on loopback, the
mounts are temp dirs. The one live test is marked and deselected by default."""

from __future__ import annotations

import datetime as dt
import gzip
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tgx_monitor.catalogue import Catalogue, Check, Target
from tgx_monitor.http import Fetched, Http
from tgx_monitor.kinds import KINDS
from tgx_monitor.kinds.base import Context, run_probe
from tgx_monitor.kinds.data import (
    as_date,
    derive,
    list_entries,
    open_inside,
    relation,
    resolve_source,
    sockjs_ws_url,
)
from tgx_monitor.model import Call

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.UTC)
EP = "https://ep.example/sparql"


class FakeHttp:
    """Answers from a table keyed by (METHOD, url); records every request."""

    def __init__(self, routes: dict[tuple[str, str], tuple[int, str] | tuple[int, str, dict]]):
        self.routes = routes
        self.seen: list[dict[str, Any]] = []

    async def fetch(self, method: str, url: str, **kw: Any) -> Fetched:
        method = method.upper()
        self.seen.append({"method": method, "url": url, **kw})
        call = Call(method=method, url=url, via=kw.get("via", "public"))
        hit = self.routes.get((method, url))
        if hit is None:
            call.note = "connection refused"
            return Fetched(call=call, error="ConnectError: connection refused")
        status, text, *rest = hit
        headers = rest[0] if rest else {}
        call.status, call.ok = status, status < 400
        return Fetched(call=call, status=status, text=text, headers=headers, final_url=url,
                       rate_limited=status == 429, ms=12.0)

    async def get(self, url: str, **kw: Any) -> Fetched:
        return await self.fetch("GET", url, **kw)


def sparql_json(var: str, value: str, datatype: str | None = None) -> str:
    cell: dict[str, str] = {"type": "literal", "value": value}
    if datatype:
        cell["datatype"] = datatype
    return json.dumps({"head": {"vars": [var]}, "results": {"bindings": [{var: cell}]}})


@pytest.fixture
def cat(tmp_path: Path) -> Catalogue:
    root = tmp_path / "catalogue"
    (root / "queries").mkdir(parents=True)
    (root / "payloads").mkdir()
    (root / "queries" / "n.rq").write_text("SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }")
    (root / "payloads" / "genes.tsv").write_text("7157\n999999999\n672\n")
    return Catalogue(root)


def mkctx(cat: Catalogue, routes: dict | None = None, mounts: dict | None = None) -> Context:
    return Context(http=FakeHttp(routes or {}), catalogue=cat, mounts=mounts or {},
                   now=lambda: NOW)


def mkcheck(kind: str, request: dict, asserts: list | None = None, **kw: Any) -> Check:
    return Check.model_validate({"id": "c-1", "kind": kind, "request": request,
                                 "assert": asserts or [{"that": "x", "exists": True}], **kw})


async def observe(kind: str, request: dict, ctx: Context, via: str = "public"):
    return await KINDS[kind]().observe(mkcheck(kind, request), via, ctx)


# ====================================================================== resolver
async def test_resolve_sparql_select_first_row_and_type(cat):
    ctx = mkctx(cat, {("GET", EP): (200, sparql_json(
        "n", "35184", "http://www.w3.org/2001/XMLSchema#integer"))})
    v, calls, err = await resolve_source({"sparql": {"endpoint": EP, "select": "SELECT ?n {}",
                                                     "value": "n"}}, ctx, "public")
    assert (v, err, len(calls)) == (35184, None, 1)
    assert ctx.http.seen[0]["params"]["query"] == "SELECT ?n {}"


async def test_resolve_sparql_file_ask_and_errors(cat):
    ctx = mkctx(cat, {("GET", EP): (200, json.dumps({"head": {}, "boolean": True}))})
    v, _, err = await resolve_source({"sparql": {"endpoint": EP, "file": "q/n.rq"}}, ctx,
                                     "core")
    assert v is True and err is None
    assert "COUNT(*)" in ctx.http.seen[0]["params"]["query"]
    assert ctx.http.seen[0]["via"] == "public"  # core makes its HTTP calls publicly
    empty = json.dumps({"head": {"vars": ["n"]}, "results": {"bindings": []}})
    ctx = mkctx(cat, {("GET", EP): (200, empty)})
    assert (await resolve_source({"sparql": {"endpoint": EP, "select": "x"}}, ctx,
                                 "public"))[2] == "no rows"
    ctx = mkctx(cat, {("GET", EP): (500, "boom")})
    assert (await resolve_source({"sparql": {"endpoint": EP, "select": "x"}}, ctx,
                                 "public"))[2] == "HTTP 500"


async def test_resolve_http_kinds(cat):
    u = "https://x.example/"
    routes = {
        ("GET", u + "j"): (200, json.dumps({"data": {"version": "2026.11.07"}})),
        ("GET", u + "void"): (200, 'pav:version "2026.11.07" ;\npav:createdOn "2026-11-07"'),
        ("HEAD", u + "h"): (200, "", {"last-modified": "Sat, 07 Nov 2026 06:00:00 GMT"}),
    }
    ctx = mkctx(cat, routes)
    assert (await resolve_source({"http_json": {"url": u + "j", "path": "data.version"}},
                                 ctx, "public"))[0] == "2026.11.07"
    assert (await resolve_source({"http_regex": {"url": u + "void",
                                                 "re": 'pav:version "([^"]+)"'}},
                                 ctx, "public"))[0] == "2026.11.07"
    assert (await resolve_source({"http_regex": {"url": u + "void", "re": r"\d{4}-\d\d-\d\d"}},
                                 ctx, "public"))[0] == "2026-11-07"  # no group: group 0
    assert (await resolve_source({"http_header": {"url": u + "h", "header": "Last-Modified"}},
                                 ctx, "public"))[0].startswith("Sat, 07 Nov")
    _, _, err = await resolve_source({"http_json": {"url": u + "j", "path": "data.nope"}},
                                     ctx, "public")
    assert "no 'data.nope'" in err
    _, _, err = await resolve_source({"http_regex": {"url": u + "void", "re": "zzz"}}, ctx,
                                     "public")
    assert "no match" in err


async def test_resolve_http_list_picks_sorted_releases(cat):
    # The real listing is not in date order (20230810 comes last).
    html = ('<a href="pfocr">pfocr</a><a href="current">current</a><a href="20261110">x</a>'
            '<a href="20261010">x</a><a href="20260910">x</a><a href="20230810">x</a>')
    u = "https://data.example/"
    ctx = mkctx(cat, {("GET", u): (200, html)})
    spec = {"url": u, "re": r'href="(\d{8})/?"'}
    assert (await resolve_source({"http_list": {**spec, "pick": "newest"}}, ctx, "p"))[0] \
        == "20261110"
    assert (await resolve_source({"http_list": {**spec, "pick": "previous"}}, ctx, "p"))[0] \
        == "20261010"
    allv = (await resolve_source({"http_list": {**spec, "pick": "all"}}, ctx, "p"))[0]
    assert allv == ["20230810", "20260910", "20261010", "20261110"]
    ctx = mkctx(cat, {("GET", u): (200, '<a href="20261110">')})
    assert "cannot pick previous" in (await resolve_source(
        {"http_list": {**spec, "pick": "previous"}}, ctx, "p"))[2]


async def test_resolve_const_extract_and_bad_specs(cat):
    ctx = mkctx(cat, {("GET", EP): (200, sparql_json(
        "d", "https://data.wikipathways.org/20261010/rdf/"))})
    v, _, err = await resolve_source({"sparql": {"endpoint": EP, "select": "x"},
                                      "extract": r"/(\d{8})/"}, ctx, "public")
    assert (v, err) == ("20261010", None)
    assert await resolve_source({"const": 42}, ctx, "public") == (42, [], None)
    assert "not a source" in (await resolve_source({"bogus": 1}, ctx, "public"))[2]
    assert "not a source" in (await resolve_source({"const": 1, "http_json": {}}, ctx,
                                                   "public"))[2]
    v, calls, err = await resolve_source({"http_json": {"url": "https://down.example/",
                                                        "path": "a"}}, ctx, "public")
    assert v is None and "refused" in err and len(calls) == 1


def test_dates_and_relation():
    assert as_date("20261110") == dt.datetime(2026, 11, 10, tzinfo=dt.UTC)
    assert as_date("2026.11.07") == dt.datetime(2026, 11, 7, tzinfo=dt.UTC)
    assert as_date("2026-11-07T06:00:00Z").hour == 6
    assert as_date("340667") is None and as_date(340667) is None  # counts are not dates
    assert relation("20261110", "20261010") == "left_newer"
    assert relation("2026.11.07", "2026-11-07") == "equal"
    assert relation(35184, "35184") == "equal"
    assert relation("3.0.9", "3.0.31") == "right_newer"  # natural order, not lexicographic
    assert relation(None, 1) == "incomparable"


# ====================================================================== invariant / compare
async def test_invariant_equal_and_short_form(cat):
    ctx = mkctx(cat, {("GET", EP): (200, sparql_json("n", "35184"))})
    obs = await observe("invariant", {"endpoint": EP, "left": "q/n.rq",
                                      "right": {"const": "35184"}}, ctx)
    assert obs.error is None and obs.values["equal"] is True
    assert obs.values["diff"] == 0
    obs = await observe("invariant", {"left": {"const": 1}, "right": {"const": 2}}, ctx)
    assert obs.values["equal"] is False and obs.values["diff"] == 1


async def test_invariant_source_failure_modes(cat):
    ctx = mkctx(cat, {("GET", EP): (429, "slow down")})
    req = {"left": {"sparql": {"endpoint": EP, "select": "x"}}, "right": {"const": 1}}
    assert (await observe("invariant", req, ctx)).unknown.startswith("rate limited")
    ctx = mkctx(cat, {})
    obs = await observe("invariant", req, ctx)
    assert obs.error and "left:" in obs.error and obs.values["left_error"]
    req["left"]["on_error"] = "unknown"
    obs = await observe("invariant", req, ctx)
    assert obs.error is None and obs.unknown.startswith("source unavailable")


async def test_compare_freshness_end_to_end(cat):
    void = "https://raw.example/AOPWikiRDF-Void.ttl"
    listing = "https://data.example/"
    ctx = mkctx(cat, {
        ("GET", EP): (200, sparql_json("v", "2026.11.07")),
        ("GET", void): (200, 'pav:version "2026.11.07" .'),
        ("GET", listing): (200, '<a href="20261110"><a href="20261010">'),
    })
    check = mkcheck("compare", {
        "endpoint": EP,
        "left": {"sparql": {"select": "SELECT ?v {}"}},
        "right": {"http_regex": {"url": void, "re": 'pav:version "([^"]+)"'}, "via": "public"},
        "sources": {"upstream": {"http_list": {"url": listing, "re": r'href="(\d{8})"'}}},
    }, [{"that": "left", "eq_path": "right"},
        {"that": "left_date", "max_age": {"warn": "8d", "crit": "15d"}},
        {"that": "relation", "in": ["equal", "left_newer"]},
        {"that": "upstream_age_days", "lt": 3}])
    target = Target.model_validate({"id": "t-1", "name": "t", "class": "data"})
    res = await run_probe(target, check, "c-1", "tgx1", ctx)
    assert res.status == "ok", res.summary
    assert ctx.http.seen[1]["via"] == "public"  # per-source via override
    assert ctx.http.seen[0]["via"] == "tgx1"
    obs = await KINDS["compare"]().observe(check, "tgx1", ctx)
    assert obs.values["left_age_days"] == 4.5 and obs.values["upstream"] == "20261110"
    assert obs.values["upstream_age_days"] == 1.5
    assert obs.values["left_date"] == "2026-11-07T00:00:00+00:00"


async def test_compare_standby_holds_previous_release(cat):
    listing = "https://data.example/"
    ctx = mkctx(cat, {("GET", EP): (200, sparql_json(
        "d", "https://data.wikipathways.org/20261010/rdf/")),
        ("GET", listing): (200, '<a href="20261110"><a href="20261010">')})
    obs = await observe("compare", {
        "left": {"sparql": {"endpoint": EP, "select": "x"}, "extract": r"(\d{8})"},
        "right": {"http_list": {"url": listing, "re": r'href="(\d{8})"', "pick": "previous"}},
    }, ctx, "core")
    assert obs.values["equal"] is True and obs.values["relation"] == "equal"


def test_source_kind_validation():
    v = KINDS["compare"].validate_request
    assert v({"left": {"const": 1}, "right": {"const": 2}}, ["public"]) == []
    probs = v({"left": {"http_regex": {"url": "u", "re": "("}}, "right": {"x": 1},
               "sources": {"up": {"http_list": {"url": "u", "re": "a", "pick": "last"}}}},
              ["agent:tgx1"])
    text = " | ".join(probs)
    assert "bad regex" in text and "right: needs exactly one" in text
    assert "pick must be" in text and "via 'agent:tgx1'" in text
    assert "request missing 'right'" in " ".join(
        KINDS["invariant"].validate_request({"left": "q/a.rq"}, ["core"]))


# ====================================================================== roundtrip
BDB = "https://webservice.example"
BATCH = ("7157\tEntrez Gene\tH:TP53,Pd:1OLG,X:1\n999999999\tEntrez Gene\tN/A\n"
         "672\tEntrez Gene\tH:BRCA1,X:2\n")


async def test_roundtrip_tsv_wire_format_and_derive(cat):
    ctx = mkctx(cat, {
        ("GET", BDB + "/Human/xrefs/H/TP53"): (200, "1OLG\tPDB\n3D09\tPDB\n7157\tWikiGenes\n",
                                              {"content-type": "text/plain; charset=UTF-8"}),
        ("POST", BDB + "/Human/xrefsBatch/L"): (200, BATCH),
    })
    obs = await observe("roundtrip", {"base": BDB, "steps": [
        {"url": "/Human/xrefs/H/TP53"},
        {"method": "POST", "url": "Human/xrefsBatch/L", "payload": "genes.tsv",
         "headers": {"Content-Type": "text/plain"}},
    ], "derive": {
        "mapped_ratio": {"tsv_nonempty_col": 2, "of_rows": "all"},
        "keys": {"tsv_distinct": 0}, "systems": {"tsv_distinct": 1},
        "sets": {"tsv_distinct_sets": {"col": 2}},
        "n": {"tsv_count_by_key": {"key": 0, "value": 2}},
        "by": {"tsv_by_key": {"key": 0, "value": 2}},
        "of_inputs": {"tsv_nonempty_col": 2, "of_rows": 4},
    }}, ctx)
    assert obs.error is None and obs.values["completed"] is True
    s0 = obs.values["steps"][0]
    assert s0["status"] == 200 and s0["content_type"].startswith("text/plain")
    last = obs.values["last"]
    assert last["lines"] == 3 and last["tsv_cols"] == 3 and last["first_line"].startswith("7157")
    assert "json" not in last
    d = obs.values["derived"]
    assert d["mapped_ratio"] == pytest.approx(2 / 3) and d["of_inputs"] == 0.5
    assert d["keys"] == ["672", "7157", "999999999"] and d["systems"] == ["Entrez Gene"]
    assert d["sets"] == 3 and d["n"] == {"7157": 3, "999999999": 0, "672": 2}
    assert "H:TP53" in d["by"]["7157"]
    assert ctx.http.seen[1]["data"] == "7157\n999999999\n672\n"


async def test_roundtrip_union_bug_is_visible(cat):
    union = "TP53\tHGNC\tA:1,B:2\nBRCA1\tHGNC\tB:2,A:1\nEGFR\tHGNC\tA:1,B:2\n"
    ctx = mkctx(cat, {("POST", BDB + "/Human/xrefsBatch/H"): (200, union)})
    obs = await observe("roundtrip", {"steps": [
        {"method": "POST", "url": BDB + "/Human/xrefsBatch/H", "data": "TP53\nBRCA1\nEGFR\n"}],
        "derive": {"sets": {"tsv_distinct_sets": {"col": 2}}}}, ctx)
    assert obs.values["derived"]["sets"] == 1  # assert {that: derived.sets, eq: 3} -> red


async def test_roundtrip_captures_and_placeholders(cat):
    u = "https://app.example"
    ctx = mkctx(cat, {
        ("GET", u + "/start"): (200, json.dumps({"session": {"id": "abc"}}),
                                {"set-cookie": "sid=xyz; Path=/"}),
        ("GET", u + "/item/abc"): (200, '{"ok": true, "n": 7}'),
    })
    obs = await observe("roundtrip", {"steps": [
        {"url": u + "/start", "capture": {"sid": {"json_path": "session.id"},
                                          "cookie": {"header": "set-cookie"},
                                          "first": {"regex": r'"id": "(\w+)"'}}},
        {"url": u + "/item/{sid}", "headers": {"Cookie": "{cookie}"}},
    ]}, ctx)
    assert obs.values["captures"] == {"sid": "abc", "cookie": "sid=xyz; Path=/",
                                      "first": "abc"}
    assert ctx.http.seen[1]["headers"] == {"Cookie": "sid=xyz; Path=/"}
    assert obs.values["last"]["json"] == {"ok": True, "n": 7}


async def test_roundtrip_failures(cat):
    u = "https://app.example"
    ctx = mkctx(cat, {("GET", u + "/a"): (200, "nothing")})
    obs = await observe("roundtrip", {"steps": [
        {"url": u + "/a", "capture": {"id": {"regex": "id=(\\d+)"}}},
        {"url": u + "/b/{id}"}]}, ctx)
    assert obs.error == "step 1: no captured value for id"
    assert obs.values["completed"] is False and obs.values["last"]["body"] == "nothing"
    obs = await observe("roundtrip", {"steps": [{"url": u + "/down"}]}, ctx)
    assert obs.error.startswith("step 0: ConnectError") and "last" not in obs.values
    obs = await observe("roundtrip", {"steps": [{"url": u + "/a",
                                                 "payload": "../queries/n.rq"}]}, ctx)
    assert "escapes" in obs.error
    ctx = mkctx(cat, {("GET", u + "/a"): (429, "slow")})
    obs = await observe("roundtrip", {"steps": [{"url": u + "/a"}]}, ctx)
    assert obs.unknown and obs.error is None


def test_roundtrip_validation_and_derive_errors():
    v = KINDS["roundtrip"].validate_request
    assert v({"steps": [{"url": "u"}], "derive": {"r": {"tsv_nonempty_col": 2}}},
             ["public"]) == []
    probs = " | ".join(v({"steps": [{"url": "u", "data": "a", "json": {},
                                     "capture": {"x": {"regex": "a", "header": "b"}}}, {}],
                          "derive": {"bad": {"nope": 1}, "worse": 3}}, ["public"]))
    assert "one of data, json, payload" in probs and "capture x" in probs
    assert "step 1: needs url" in probs and "derive bad" in probs and "derive worse" in probs
    assert v({"steps": []}, ["public"])[-1] == "steps must be a non-empty list"
    with pytest.raises(ValueError):
        derive({"nope": 1}, [])
    assert derive({"tsv_nonempty_col": 1}, []) is None


# ====================================================================== shiny
def test_sockjs_url_shape():
    url = sockjs_ws_url("https://r-odaf.example/app/")
    assert url.startswith("wss://r-odaf.example/app/__sockjs__/")
    server, sess, tail = url.rsplit("/", 3)[1:]
    assert len(server) == 3 and server.isdigit() and len(sess) == 8 and tail == "websocket"
    assert "/__sockjs__/n=" in sockjs_ws_url("http://h/", robust=True)
    assert sockjs_ws_url("http://h/").startswith("ws://h/__sockjs__/")


@pytest.fixture
async def ws_server():
    from websockets.asyncio.server import serve

    paths: list[str] = []

    async def handler(ws):
        paths.append(ws.request.path)
        if "silent" not in ws.request.path:
            await ws.send("o")
        await ws.wait_closed()

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}", paths


async def test_shiny_session_opens(cat, ws_server):
    base, paths = ws_server
    ctx = mkctx(cat, {
        ("GET", base + "/app/"): (200, '<script src="shiny-javascript-1.13.0/shiny.min.js">'),
        ("GET", base + "/app/__sockjs__/info"): (200, '{"websocket":true,"cookie_needed":false}'),
    })
    obs = await observe("shiny", {"url": base + "/app/", "ws_wait": 3}, ctx)
    assert obs.error is None
    v = obs.values
    assert v["page_status"] == 200 and v["page_has_shiny"] and v["websocket"] is True
    assert v["ws_open"] is True and v["ws_ms"] < 3000 and "body" not in v
    assert paths[0].startswith("/app/__sockjs__/") and paths[0].endswith("/websocket")
    assert obs.calls[-1].method == "WS" and obs.calls[-1].ok


async def test_shiny_dead_session_and_no_websocket(cat, ws_server):
    base, _ = ws_server
    ctx = mkctx(cat, {
        ("GET", base + "/silent/"): (200, "shiny"),
        ("GET", base + "/silent/__sockjs__/info"): (200, '{"websocket":true}'),
        ("GET", base + "/nows/"): (200, "shiny"),
        ("GET", base + "/nows/__sockjs__/info"): (200, '{"websocket":false}'),
    })
    obs = await observe("shiny", {"url": base + "/silent/", "ws_wait": 0.5}, ctx)
    assert obs.values["ws_open"] is False and "no frame" in obs.values["ws_note"]
    obs = await observe("shiny", {"url": base + "/nows/"}, ctx)
    assert obs.values["websocket"] is False and obs.values["ws_note"] == "not attempted"
    obs = await observe("shiny", {"url": "https://gone.example/"}, ctx)
    assert obs.error


@pytest.mark.live
async def test_shiny_live_rodaf(cat):
    ctx = Context(http=Http(mode="live"), catalogue=cat)
    try:
        obs = await observe("shiny", {"url": "https://r-odaf.nl/"}, ctx)
    finally:
        await ctx.http.aclose()
    assert obs.values["page_status"] == 200 and obs.values["websocket"] is True
    assert obs.values["ws_open"] is True, obs.values["ws_note"]


# ====================================================================== browser artifact
async def test_browser_artifact_dict_and_list(cat):
    u = "https://raw.example/history/browser.json"
    doc = {"generated_at": "2026-11-11T06:00:00Z",
           "pages": {"oppbk": {"ok": True, "title": "OP PBK model", "console_errors": []}}}
    ctx = mkctx(cat, {("GET", u): (200, json.dumps(doc)),
                      ("GET", u + "2"): (200, json.dumps({"generated_at": "2026-11-10T00:00:00Z",
                                                          "pages": [{"id": "a", "ok": False}]}))})
    obs = await observe("browser_artifact", {"url": u, "page": "oppbk"}, ctx, "core")
    assert obs.values["age_h"] == 6.0 and obs.values["page"]["title"] == "OP PBK model"
    assert obs.values["page_found"] and obs.values["pages"] == ["oppbk"]
    obs = await observe("browser_artifact", {"url": u + "2", "page": "a"}, ctx)
    assert obs.values["page"] == {"id": "a", "ok": False} and obs.values["age_h"] == 36.0
    obs = await observe("browser_artifact", {"url": u, "page": "zzz"}, ctx)
    assert obs.values["page_found"] is False and obs.values["page"] == {}


# ====================================================================== file kinds
def touch(p: Path, data: bytes, when: dt.datetime) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    os.utime(p, (when.timestamp(), when.timestamp()))
    return p


async def test_file_age_newest_sizes_and_gzip(cat, tmp_path):
    m = tmp_path / "bk"
    touch(m / "db_20261109.sql.gz", gzip.compress(b"CREATE TABLE a;\n" * 100),
          NOW - dt.timedelta(hours=34))
    touch(m / "db_20261110.sql.gz", gzip.compress(b"CREATE TABLE a;\nCREATE TABLE b;\n-- end\n"),
          NOW - dt.timedelta(hours=10))
    touch(m / "notes.txt", b"x", NOW)
    ctx = mkctx(cat, mounts={"backups-x": m})
    obs = await observe("file_age", {"mount": "backups-x", "glob": "*.sql.gz",
                                     "scan": {"grep": "^CREATE TABLE", "tail": 1}}, ctx, "core")
    v = obs.values
    assert obs.unknown is None and v["exists"] and v["count"] == 2
    assert v["newest_name"] == "db_20261110.sql.gz" and v["newest_age_h"] == 10.0
    assert v["newest_mtime"].startswith("2026-11-11T02:00")
    assert v["prev_size"] > v["newest_size"] and v["size_change_pct"] < 0
    assert v["gzip_ok"] is True and v["grep_count"] == 2 and v["tail"] == ["-- end"]
    assert v["names"][0] == "db_20261110.sql.gz" and v["small_count"] == 0
    assert obs.calls[0].via == "file"


async def test_file_age_broken_gzip_empty_and_missing(cat, tmp_path):
    m = tmp_path / "bk"
    touch(m / "2026-11-03_020000" / "dump.sql.gz", b"", NOW - dt.timedelta(days=8))
    good = gzip.compress(b"x" * 5000)
    touch(m / "2026-11-10_020000" / "dump.sql.gz", good[: len(good) // 2], NOW)
    ctx = mkctx(cat, mounts={"bk": m, "gone": tmp_path / "nope"})
    obs = await observe("file_age", {"mount": "bk", "glob": "*/dump.sql.gz",
                                     "small_bytes": 1000}, ctx, "core")
    v = obs.values
    assert v["gzip_ok"] is False and v["small_count"] == 2 and v["prev_size"] == 0
    assert v["size_change_pct"] is None and v["newest_name"].startswith("2026-11-10")
    obs = await observe("file_age", {"mount": "bk", "glob": "*.db"}, ctx, "core")
    assert obs.unknown is None and obs.values["count"] == 0 and "newest_name" not in obs.values
    obs = await observe("file_age", {"mount": "gone", "glob": "*"}, ctx, "core")
    assert obs.unknown == "mount not available: gone"
    obs = await observe("file_age", {"mount": "unlisted"}, ctx, "core")
    assert obs.unknown.startswith("mount not available")
    obs = await observe("file_age", {"mount": "bk", "type": "dir"}, ctx, "core")
    assert obs.values["count"] == 2 and "gzip_ok" not in obs.values


async def test_file_age_missing_backup_reads_as_missing(cat, tmp_path):
    (tmp_path / "bk").mkdir()
    ctx = mkctx(cat, mounts={"bk": tmp_path / "bk"})
    check = mkcheck("file_age", {"mount": "bk", "glob": "*.gz"},
                    [{"that": "count", "gte": 1, "label": "a backup exists"},
                     {"that": "newest_age_h", "lt": 26}], via=["core"])
    target = Target.model_validate({"id": "t-1", "name": "t", "class": "backup"})
    res = await run_probe(target, check, "c-1", "core", ctx)
    assert res.status == "failed" and res.outcomes[0].assertion == "a backup exists"


def test_paths_stay_inside_the_mount(tmp_path):
    m = tmp_path / "bk"
    touch(m / "a.db", b"1", NOW)
    touch(tmp_path / "secret.db", b"s", NOW)
    (m / "link.db").symlink_to(tmp_path / "secret.db")
    names = [e[0].name for e in list_entries(m.resolve(), "*.db")]
    assert names == ["a.db"]
    for bad in ("../*.db", "/etc/*", "a/../../x"):
        with pytest.raises(ValueError):
            list_entries(m.resolve(), bad)


def test_open_inside_checks_the_opened_file(tmp_path):
    m = (tmp_path / "bk")
    touch(m / "a.db", b"1", NOW)
    touch(tmp_path / "secret", b"s3cret", NOW)
    (m / "link.db").symlink_to(tmp_path / "secret")
    os.mkfifo(m / "pipe.db")
    root = m.resolve()
    with open_inside(root, m / "a.db") as fh:
        assert fh.read() == b"1"
    for bad in ("link.db", "pipe.db"):
        with pytest.raises(ValueError):
            open_inside(root, m / bad)


async def test_marker_swapped_for_a_symlink_after_listing_is_not_read(cat, tmp_path,
                                                                      monkeypatch):
    """The race: list_entries saw a plain file, then it became a link to a secret."""
    import tgx_monitor.kinds.data as data

    m = tmp_path / "bk"
    touch(m / "restore-ok.json", b"{}", NOW)
    touch(tmp_path / "tgxmon_gh_token", b'{"token": "SECRET-CANARY"}', NOW)
    real = data.list_entries

    def racy(root, pattern, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202
        out = real(root, pattern, *a, **kw)
        (m / "restore-ok.json").unlink()
        (m / "restore-ok.json").symlink_to(tmp_path / "tgxmon_gh_token")
        return out

    monkeypatch.setattr(data, "list_entries", racy)
    obs = await observe("restore_marker", {"mount": "bk", "file": "restore-ok.json"},
                        mkctx(cat, mounts={"bk": m}), "core")
    assert obs.unknown and "outside the mount" in obs.unknown
    assert "SECRET-CANARY" not in json.dumps(obs.values) + (obs.evidence or "")


async def test_file_glob_escape_is_unknown(cat, tmp_path):
    (tmp_path / "bk").mkdir()
    ctx = mkctx(cat, mounts={"bk": tmp_path / "bk"})
    obs = await observe("file_age", {"mount": "bk", "glob": "../*"}, ctx, "core")
    assert obs.unknown and "inside the mount" in obs.unknown


def make_db(path: Path, rows: int) -> bytes:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE mapping (id INTEGER PRIMARY KEY, ke TEXT)")
    con.executemany("INSERT INTO mapping (ke) VALUES (?)", [(f"KE{i}",) for i in range(rows)])
    con.commit()
    con.close()
    return path.read_bytes()


async def test_sqlite_backup_integrity_and_counts(cat, tmp_path):
    raw = make_db(tmp_path / "src.db", 447)
    m = tmp_path / "bk"
    touch(m / "ke_wp_mapping_20261109.db", raw, NOW - dt.timedelta(hours=30))
    touch(m / "ke_wp_mapping_20261110.db.gz", gzip.compress(raw), NOW - dt.timedelta(hours=9))
    ctx = mkctx(cat, mounts={"bk": m})
    obs = await observe("sqlite_backup", {"mount": "bk", "glob": "ke_wp_mapping_*",
                                          "tables": ["mapping", "nope", "x; DROP"]}, ctx, "core")
    v = obs.values
    assert v["integrity"] == "ok" and v["tables"]["mapping"] == 447
    assert v["tables"]["nope"] is None and v["missing_tables"] == ["nope", "x; DROP"]
    assert v["newest_name"].endswith(".gz") and v["copied_bytes"] == len(raw)
    assert v["newest_age_h"] == 9.0 and "gzip_ok" not in v
    assert (await observe("sqlite_backup", {"mount": "bk", "glob": "*.db", "quick": True},
                          ctx, "core")).values["integrity"] == "ok"


async def test_sqlite_backup_broken_files(cat, tmp_path):
    m = tmp_path / "bk"
    touch(m / "a.db", b"this is not sqlite at all" * 100, NOW)
    touch(m / "b.db.gz", gzip.compress(b"x" * 100)[:20], NOW + dt.timedelta(seconds=1))
    ctx = mkctx(cat, mounts={"bk": m})
    v = (await observe("sqlite_backup", {"mount": "bk", "glob": "a.db"}, ctx, "core")).values
    assert v["integrity"] != "ok" and "DatabaseError" in v["integrity"]
    v = (await observe("sqlite_backup", {"mount": "bk", "glob": "b.db.gz"}, ctx, "core")).values
    assert v["integrity"].startswith("copy failed")
    v = (await observe("sqlite_backup", {"mount": "bk", "glob": "*.none"}, ctx, "core")).values
    assert v["count"] == 0 and v["integrity"] == "no backup"
    v = (await observe("sqlite_backup", {"mount": "bk", "glob": "a.db", "max_bytes": 10},
                       ctx, "core")).values
    assert v["integrity"].startswith("not checked")


async def test_restore_marker_formats(cat, tmp_path):
    m = tmp_path / "bk"
    touch(m / "verify" / "restore-ok.json",
          json.dumps({"verified_at": "2026-11-08T02:30:00Z", "graphs": 38,
                      "triples": 5892342, "ok": True}).encode(), NOW)
    touch(m / "virtuoso-20261109.manifest", b"graphs: 30\n", NOW - dt.timedelta(days=2))
    touch(m / "virtuoso-20261110.manifest", b"graphs: 38\ntriples: 5892342\nsize: 21M\n",
          NOW - dt.timedelta(hours=11))
    touch(m / ".load-ok", b"20261010\t2026-10-12T03:10:00Z\n", NOW)
    touch(m / "bad.json", b"{nope", NOW)
    ctx = mkctx(cat, mounts={"bk": m})
    v = (await observe("restore_marker", {"mount": "bk", "file": "verify/restore-ok.json"},
                       ctx, "core")).values
    assert v["ok"] is True and v["graphs"] == 38 and v["age_h"] == 81.5
    assert v["mtime_age_h"] == 0.0 and v["exists"]
    v = (await observe("restore_marker", {"mount": "bk", "file": "virtuoso-*.manifest",
                                          "format": "kv"}, ctx, "core")).values
    assert v["graphs"] == 38 and v["triples"] == 5892342 and v["size"] == "21M"
    assert v["age_h"] == 11.0 and v["marker_name"] == "virtuoso-20261110.manifest"
    v = (await observe("restore_marker", {"mount": "bk", "file": ".load-ok", "format": "text"},
                       ctx, "core")).values
    assert v["fields"] == ["20261010", "2026-10-12T03:10:00Z"]
    v = (await observe("restore_marker", {"mount": "bk", "file": "bad.json"}, ctx,
                       "core")).values
    assert "parse_error" in v
    v = (await observe("restore_marker", {"mount": "bk", "file": "none.json"}, ctx,
                       "core")).values
    assert v == {"exists": False}


def test_file_kinds_only_run_in_core():
    for k in ("file_age", "sqlite_backup", "restore_marker"):
        assert "via 'public' not supported" in " ".join(
            KINDS[k].validate_request({"mount": "m", "glob": "*", "file": "f"}, ["public"]))
        assert KINDS[k].validate_request({"mount": "m", "glob": "*", "file": "f"},
                                         ["core"]) == []
