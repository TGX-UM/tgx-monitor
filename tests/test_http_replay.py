"""The HTTP client offline: replay fixtures, record mode, redirects and per-node pinning.

Live mode is exercised against ``httpx.MockTransport`` so the hand-followed redirect
chain and the node pinning (IP in the URL, real name in ``Host`` and SNI) are checked
without a network. ``make offline`` relies on replay mode being exactly this strict:
no fixture, no answer.
"""

from __future__ import annotations

import json

import httpx
import pytest

from tgx_monitor import http as H
from tgx_monitor.http import Http, _fixture_name, _pin, classify

URL = "https://aopwiki.rdf.bigcat-bioinformatics.org/sparql"


def write_fixture(d, method, url, via="public", params=None, body=None, **resp):
    blob = {"method": method, "url": url, "via": via, "params": params, "body": body,
            "status": 200, "headers": {"content-type": "application/json"}, "text": "{}",
            "final_url": url, "redirects": [], "error": None, **resp}
    d.mkdir(parents=True, exist_ok=True)
    (d / _fixture_name(method, url, via, params, body)).write_text(json.dumps(blob))


# ---------------------------------------------------------------- replay
async def test_replay_returns_the_fixture(tmp_path):
    q = {"query": "ASK { ?s ?p ?o }"}
    write_fixture(tmp_path, "GET", URL, params=q, text='{"boolean": true}')
    f = await Http(mode="replay", fixture_dir=tmp_path).get(URL, params=q)
    assert f.ok and f.status == 200 and f.json() == {"boolean": True}
    assert f.headers["content-type"] == "application/json"
    assert f.call.status == 200 and f.call.ok and f.call.via == "public"


async def test_replay_without_fixture_is_an_error_never_the_network(tmp_path):
    f = await Http(mode="replay", fixture_dir=tmp_path).get(URL, params={"query": "x"})
    assert not f.ok and f.status is None
    assert f.error.startswith("replay: no fixture for GET")
    assert f.call.note.startswith("no fixture ")
    assert classify(f) == (f.error, None)


async def test_replay_key_includes_via_params_and_body(tmp_path):
    write_fixture(tmp_path, "GET", URL, via="tgx1", text="node one")
    write_fixture(tmp_path, "POST", URL, body={"query": "ASK {}"}, text="posted")
    http = Http(mode="replay", fixture_dir=tmp_path)
    assert (await http.get(URL, via="tgx1")).text == "node one"
    assert (await http.get(URL, via="tgx2")).error  # other node: other fixture
    assert (await http.get(URL)).error
    f = await http.fetch("POST", URL, data={"query": "ASK {}"})
    assert f.text == "posted"
    assert (await http.fetch("POST", URL, data={"query": "ASK { }"})).error


async def test_replay_bytes_body_matches_text_key(tmp_path):
    write_fixture(tmp_path, "POST", URL, body="TP53\nBRCA1\n", text="rows")
    f = await Http(mode="replay", fixture_dir=tmp_path).fetch("POST", URL, data=b"TP53\nBRCA1\n")
    assert f.text == "rows"


async def test_replay_429_is_unknown_and_recorded_errors_replay(tmp_path):
    write_fixture(tmp_path, "GET", URL, status=429, text="slow down")
    write_fixture(tmp_path, "GET", URL + "?x", status=None, error="ConnectError: refused")
    http = Http(mode="replay", fixture_dir=tmp_path)
    f = await http.get(URL)
    assert f.rate_limited and classify(f) == (None, "rate limited (HTTP 429)")
    f = await http.get(URL + "?x")
    assert classify(f) == ("ConnectError: refused", None) and not f.call.ok


async def test_replay_mode_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("TGXMON_HTTP_MODE", "replay")
    monkeypatch.setenv("TGXMON_FIXTURES", str(tmp_path))
    http = Http()
    assert http.mode == "replay" and http.fixture_dir == tmp_path
    assert (await http.get(URL)).error.startswith("replay:")


# ---------------------------------------------------------------- pinning
def test_pin_public_is_untouched():
    assert _pin(URL, "public") == (URL, {}, {})
    assert _pin(URL, "") == (URL, {}, {})


def test_pin_https_keeps_host_and_sni():
    url, headers, ext = _pin(URL + "?query=ASK", "tgx1")
    assert url == "https://81.169.246.233/sparql?query=ASK"
    assert headers == {"Host": "aopwiki.rdf.bigcat-bioinformatics.org"}
    assert ext == {"sni_hostname": "aopwiki.rdf.bigcat-bioinformatics.org"}


def test_pin_http_with_port_has_no_sni():
    url, headers, ext = _pin("http://example.org:8080/a#frag", "tgx2")
    assert url == "http://85.214.252.63:8080/a#frag"
    assert headers == {"Host": "example.org:8080"} and ext == {}


def test_pin_unknown_node_raises():
    with pytest.raises(ValueError, match="unknown via 'tgx3'"):
        _pin(URL, "tgx3")


# ---------------------------------------------------------------- live logic, mocked
def mocked(handler, mode="live", tmp_path=None) -> Http:
    http = Http(mode=mode, fixture_dir=tmp_path)
    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                     follow_redirects=False)
    return http


async def test_pinned_request_reaches_node_with_real_host():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    http = mocked(handler)
    f = await http.get(URL, via="tgx2", params={"query": "ASK {}"})
    await http.aclose()
    assert f.ok and f.call.via == "tgx2" and f.call.url == URL
    r = seen[0]
    assert r.url.host == "85.214.252.63" and r.url.params["query"] == "ASK {}"
    assert r.headers["host"] == "aopwiki.rdf.bigcat-bioinformatics.org"
    assert r.extensions["sni_hostname"] == "aopwiki.rdf.bigcat-bioinformatics.org"


async def test_redirects_are_followed_by_hand_and_recorded():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "https://example.org/next"})
        if request.url.path == "/next":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, text="landed")

    http = mocked(handler)
    f = await http.get("https://example.org/")
    assert f.text == "landed" and f.final_url == "https://example.org/final"
    assert f.redirects == ["https://example.org/next", "https://example.org/final"]
    assert f.call.note == "redirected 2x to https://example.org/final"
    f = await http.get("https://example.org/", follow=False)
    assert f.status == 301 and f.redirects == [] and f.headers["location"]


async def test_redirect_loop_is_an_error():
    http = mocked(lambda r: httpx.Response(302, headers={"location": "https://example.org/"}))
    f = await http.get("https://example.org/")
    assert f.error == f"more than {H.MAX_REDIRECTS} redirects" and not f.ok


async def test_transport_errors_never_raise():
    def boom(request):
        raise httpx.ConnectError("connection refused", request=request)

    def slow(request):
        raise httpx.ReadTimeout("read timed out", request=request)

    f = await mocked(boom).get(URL)
    assert f.error.startswith("ConnectError") and f.call.note == f.error
    f = await mocked(slow).get(URL)
    assert f.timed_out and f.error.startswith("timeout")


async def test_body_cap_stops_reading(monkeypatch):
    monkeypatch.setattr(H, "BODY_CAP", 10)

    async def chunks():
        for _ in range(20):
            yield b"xxxxx"

    f = await mocked(lambda r: httpx.Response(200, content=chunks())).get(URL)
    assert f.text == "x" * 10  # the cap is checked per chunk: may overshoot by one chunk


async def test_record_then_replay_round_trip(tmp_path):
    http = mocked(lambda r: httpx.Response(200, json={"boolean": True}), mode="record",
                  tmp_path=tmp_path)
    live = await http.get(URL, params={"query": "ASK {}"}, via="tgx1")
    assert live.ok
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1 and json.loads(files[0].read_text())["via"] == "tgx1"
    again = await Http(mode="replay", fixture_dir=tmp_path).get(
        URL, params={"query": "ASK {}"}, via="tgx1")
    assert again.json() == {"boolean": True} and again.status == 200


async def test_per_host_concurrency_bound():
    import asyncio

    active = peak = 0

    async def handler(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return httpx.Response(200)

    http = mocked(handler)
    http.per_host = 2
    await asyncio.gather(*(http.get(URL) for _ in range(6)))
    assert peak == 2


async def test_307_308_keep_method_and_body():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.content))
        if request.url.path == "/batch":
            return httpx.Response(308, headers={"location": "/batch/"})
        return httpx.Response(200, text="ok")

    await mocked(handler).fetch("POST", "https://example.org/batch", data="TP53\n")
    assert seen[1] == ("POST", b"TP53\n")


async def test_cross_host_redirect_drops_authorization():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers.get("authorization")))
        if request.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://elsewhere.example/x"})
        return httpx.Response(200, text="ok")

    await mocked(handler).fetch("GET", "https://api.github.com/repos/a/b",
                                headers={"Authorization": "Bearer secret"})
    assert seen == [("api.github.com", "Bearer secret"), ("elsewhere.example", None)]
