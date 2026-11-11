"""The one HTTP client, adapted from tgx-outputs ``http.py``.

What carried over: timeouts live on the client so no check can forget one; a 429 is
never retried into silence; ``record``/``replay`` modes so the whole test suite and
``make offline`` run with no network at all.

What changed, because in a monitor the failure is the measurement:

* Nothing raises. :meth:`Http.fetch` returns a :class:`Fetched` with either a response
  or an error string, plus the :class:`~tgx_monitor.model.Call` to show on the page.
* Redirects are followed by hand and recorded. A domain that quietly starts redirecting
  to a parking page must be visible, not absorbed by ``follow_redirects=True``.
* ``via`` pins a request to one swarm node: the URL's host is replaced by the node IP,
  the ``Host`` header and TLS SNI keep the real name (httpx ``sni_hostname``
  extension), so certificate verification still runs against the real hostname.
* Concurrency is bounded per host, because ten Virtuoso endpoints share two nodes and
  a monitor must not become the load it is measuring.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from http.cookiejar import CookieJar, DefaultCookiePolicy
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .model import Call

USER_AGENT = "tgx-monitor/0.1 (+https://github.com/TGX-UM/tgx-monitor)"
TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=15.0)
BODY_CAP = 8 * 1024 * 1024  # bytes kept from any response body (O'FAIRe JSON is ~6 MB)
MAX_REDIRECTS = 6

# Node aliases usable in a check's ``via``. Public IPs, already public via DNS.
NODES: dict[str, str] = {
    "tgx1": os.environ.get("TGXMON_NODE_TGX1", "81.169.246.233"),
    "tgx2": os.environ.get("TGXMON_NODE_TGX2", "85.214.252.63"),
}


@dataclass(slots=True)
class Fetched:
    """Outcome of one logical request (after redirects)."""

    call: Call
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    final_url: str = ""
    redirects: list[str] = field(default_factory=list)
    error: str | None = None  # no usable answer at all (DNS, connect, TLS, timeout)
    rate_limited: bool = False
    timed_out: bool = False
    ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and self.status < 400

    def json(self) -> Any:
        return json.loads(self.text)


def _fixture_name(method: str, url: str, via: str, params: Any, body: Any) -> str:
    blob = json.dumps([method, url, via, params, body], sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16] + ".json"


def _pin(url: str, via: str) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Rewrite ``url`` so it connects to node ``via`` but speaks to the real host."""
    if via in ("public", "", None):
        return url, {}, {}
    if via not in NODES:
        raise ValueError(f"unknown via {via!r}; expected public or one of {sorted(NODES)}")
    parts = urlsplit(url)
    host = parts.hostname or ""
    netloc = NODES[via] + (f":{parts.port}" if parts.port else "")
    pinned = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    ext = {"sni_hostname": host} if parts.scheme == "https" else {}
    return pinned, {"Host": parts.netloc}, ext


class Http:
    """Async HTTP for checks. One instance per process; safe to share."""

    def __init__(
        self,
        mode: str | None = None,
        fixture_dir: Path | None = None,
        per_host: int = 2,
        per_host_overrides: dict[str, int] | None = None,
    ) -> None:
        self.mode = mode or os.environ.get("TGXMON_HTTP_MODE", "live")
        default_fixtures = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
        self.fixture_dir = fixture_dir or Path(os.environ.get("TGXMON_FIXTURES", default_fixtures))
        self.per_host = per_host
        self.per_host_overrides = per_host_overrides or {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._client: httpx.AsyncClient | None = None
        self._insecure: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------ plumbing
    def _sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._sems:
            self._sems[host] = asyncio.Semaphore(self.per_host_overrides.get(host, self.per_host))
        return self._sems[host]

    def _ensure(self, verify: bool) -> httpx.AsyncClient:
        # A jar that refuses every cookie: one check's Set-Cookie must never ride along
        # on another check's request, and no session may outlive a single probe.
        def jar() -> httpx.Cookies:
            return httpx.Cookies(CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])))

        if verify:
            if self._client is None:
                self._client = httpx.AsyncClient(
                    timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
                    follow_redirects=False, cookies=jar())
            return self._client
        if self._insecure is None:
            self._insecure = httpx.AsyncClient(
                timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
                follow_redirects=False, verify=False, cookies=jar())
        return self._insecure

    async def aclose(self) -> None:
        for c in (self._client, self._insecure):
            if c is not None:
                await c.aclose()
        self._client = self._insecure = None

    # ------------------------------------------------------------------ main entry
    async def fetch(
        self,
        method: str,
        url: str,
        *,
        via: str = "public",
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | str | bytes | None = None,
        json_body: Any = None,
        follow: bool = True,
        verify: bool = True,
        timeout: float | None = None,
    ) -> Fetched:
        """Make one request, following redirects by hand. Never raises."""
        method = method.upper()
        body_key = json_body if json_body is not None else data
        if isinstance(body_key, bytes):
            body_key = body_key.decode("utf-8", "replace")
        call = Call(method=method, url=url, via=via or "public")

        if self.mode == "replay":
            return self._replay(method, url, via, params, body_key, call)

        t0 = time.perf_counter()
        current = url
        cur_method = method
        keep_body = True  # 307/308 repeat method and body; 301/302/303 become a bodiless GET
        redirects: list[str] = []
        host = urlsplit(url).hostname or url
        out = Fetched(call=call)
        try:
            async with self._sem(f"{host}|{via}"):
                for _hop in range(MAX_REDIRECTS + 1):
                    target, extra_headers, ext = _pin(current, via)
                    h = {**(headers or {}), **extra_headers}
                    if (urlsplit(current).hostname or "") != host:
                        # Never carry credentials to another host on a redirect.
                        h = {k: v for k, v in h.items()
                             if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
                    req_kw: dict[str, Any] = {"params": params if current == url else None,
                                              "headers": h, "extensions": ext}
                    if timeout is not None:
                        req_kw["timeout"] = httpx.Timeout(timeout, connect=min(10.0, timeout))
                    if json_body is not None and keep_body:
                        req_kw["json"] = json_body
                    elif data is not None and keep_body:
                        if isinstance(data, dict):
                            req_kw["data"] = data
                        else:
                            req_kw["content"] = data
                    client = self._ensure(verify)
                    async with client.stream(cur_method, target, **req_kw) as resp:
                        raw = b""
                        async for chunk in resp.aiter_bytes():
                            raw += chunk
                            if len(raw) >= BODY_CAP:
                                break
                        status = resp.status_code
                        hdrs = {k.lower(): v for k, v in resp.headers.items()}
                        enc = resp.encoding or "utf-8"
                    if follow and status in (301, 302, 303, 307, 308) and "location" in hdrs:
                        nxt = urljoin(current, hdrs["location"])
                        redirects.append(nxt)
                        current = nxt
                        if status in (301, 302, 303):
                            cur_method, keep_body = "GET", False
                        continue
                    break
                else:
                    out.error = f"more than {MAX_REDIRECTS} redirects"
        except httpx.TimeoutException as exc:
            out.error = f"timeout: {type(exc).__name__}"
            out.timed_out = True
        except httpx.HTTPError as exc:
            out.error = f"{type(exc).__name__}: {exc}"[:500]
        except (OSError, ValueError) as exc:
            out.error = f"{type(exc).__name__}: {exc}"[:500]
        out.ms = round((time.perf_counter() - t0) * 1000, 1)
        call.ms = out.ms
        if out.error is None:
            out.status = status
            out.headers = hdrs
            out.text = raw.decode(enc, "replace")
            out.final_url = current
            out.redirects = redirects
            out.rate_limited = status == 429
            call.status = status
            call.ok = status < 400
            if redirects:
                call.note = f"redirected {len(redirects)}x to {current}"
        else:
            call.note = out.error
        if self.mode == "record":
            self._record(method, url, via, params, body_key, out)
        return out

    async def get(self, url: str, **kw: Any) -> Fetched:
        return await self.fetch("GET", url, **kw)

    # ------------------------------------------------------------------ fixtures
    def _record(self, method: str, url: str, via: str, params: Any, body: Any,
                out: Fetched) -> None:
        path = self.fixture_dir / _fixture_name(method, url, via, params, body)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "method": method, "url": url, "via": via, "params": params, "body": body,
            "status": out.status, "headers": out.headers, "text": out.text[:200_000],
            "final_url": out.final_url, "redirects": out.redirects, "error": out.error,
        }, indent=1))

    def _replay(self, method: str, url: str, via: str, params: Any, body: Any,
                call: Call) -> Fetched:
        path = self.fixture_dir / _fixture_name(method, url, via, params, body)
        if not path.exists():
            call.note = f"no fixture {path.name}"
            return Fetched(call=call, error=f"replay: no fixture for {method} {url} via {via}")
        blob = json.loads(path.read_text())
        call.status = blob["status"]
        call.ok = blob["status"] is not None and blob["status"] < 400
        return Fetched(
            call=call, status=blob["status"], headers=blob.get("headers") or {},
            text=blob.get("text") or "", final_url=blob.get("final_url") or url,
            redirects=blob.get("redirects") or [], error=blob.get("error"),
            rate_limited=blob["status"] == 429,
        )


def classify(f: Fetched) -> tuple[str | None, str | None]:
    """Map a fetch to (error, unknown) the way every kind should.

    A 429 is *unknown*, never down. A client-side timeout is a failure only if the
    check says so; by default an endpoint that is slow is still answering, so the
    kind decides. Connection refused, DNS and TLS errors are failures.
    """
    if f.rate_limited:
        return None, "rate limited (HTTP 429)"
    if f.error:
        return f.error, None
    return None, None
