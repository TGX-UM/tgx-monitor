"""Read-only Docker Engine API client, through the GET-only socket proxy.

Why a proxy and not the socket: whoever can talk to ``docker.sock`` is root on the node.
Core never mounts it. Each node runs ``wollomatic/socket-proxy`` (global mode) on the
private ``tgxmon_dockerapi`` overlay, with an anchored GET allowlist (``ALLOWED_PATHS``)
that leaves out every endpoint able to leak a secret or a file: container inspect,
archive, export, ``/secrets``, ``/configs``, image export, exec. That same constant is
what ``deploy/socket-proxy.md`` puts on the command line and what
``tests/test_proxy_contract.py`` checks against every path this module requests.

Why one proxy per node: swarm-wide objects (services, tasks, nodes, task logs) are
answered by any manager, but images, containers and events are local to the engine that
is asked. ``tasks.docker-proxy`` lists one IP per node; ``/info`` on each tells which
node it is. Swarm-wide calls go to tgx1 first and fall over to tgx2, so one dead engine
does not blind the monitor (the 2026-11-02 tgx1 dockerd hang).

Why redaction here: ``/services`` and ``/tasks`` carry ``ContainerSpec.Env`` in plain
text, passwords included. Every JSON answer passes :func:`redact.redact_spec` and every
log line :func:`redact.redact_text` before a caller sees it, so nothing downstream can
forget to.

Nothing here retries or caches beyond the endpoint map; errors surface as
:class:`DockerError` for the kind to turn into an observation.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import inspect
import json
import os
import re
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .model import Call
from .redact import redact_spec, redact_text

API_VERSION = os.environ.get("TGXMON_DOCKER_API", "v1.47")
PROXY_DNS = os.environ.get("TGXMON_DOCKER_PROXY", "tasks.docker-proxy")
PROXY_PORT = 2375

# Node hostname prefix -> alias used everywhere else (``via``, pages, alerts).
NODE_ALIASES = {"h3068544": "tgx1", "h2973005": "tgx2"}

# The proxy's -allowGET pattern. socket-proxy anchors it (^...$) itself and matches the
# path only, never the query string; the outer group keeps the anchors on every branch.
# Extend it only together with a DockerAPI method and the contract test.
ALLOWED_PATHS = (r"/v1\.(4[4-9]|5[0-3])/(info|nodes|services|tasks|events|images/json"
                 r"|containers/json|tasks/[a-z0-9]+/logs)")

TERMINAL_STATES = frozenset({"complete", "failed", "rejected", "shutdown", "orphaned",
                             "remove"})
BODY_CAP = 32 * 1024 * 1024
EVENTS_CAP = 4 * 1024 * 1024
MAX_EVENTS = 5000
_TASK_ID = re.compile(r"^[a-z0-9]{1,64}$")

BaseUrls = list[str] | Callable[[], list[str] | Awaitable[list[str]]] | None


class DockerError(Exception):
    """The Docker API did not give a usable answer. ``status`` is the HTTP status, if any."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(slots=True)
class Endpoint:
    base_url: str
    alias: str
    hostname: str
    node_id: str


def node_alias(hostname: str) -> str:
    short = (hostname or "").split(".")[0]
    return NODE_ALIASES.get(short, short)


def parse_ts(text: str | None) -> dt.datetime | None:
    """Docker timestamps carry nanoseconds; ``0001-01-01`` means unset."""
    if not text or text.startswith("0001-"):
        return None
    m = re.match(r"^(.*?T[\d:]+)(\.\d+)?(Z|[+-]\d\d:?\d\d)?$", text.strip())
    if not m:
        return None
    frac = (m.group(2) or "")[:7]
    tz = m.group(3) or "Z"
    try:
        ts = dt.datetime.fromisoformat(m.group(1) + frac + ("+00:00" if tz == "Z" else tz))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.UTC)


def demux(raw: bytes) -> str:
    """Decode a log body: Docker's 8-byte-framed multiplexed stream, or raw TTY output."""
    if len(raw) >= 8 and raw[0] in (0, 1, 2) and raw[1:4] == b"\0\0\0":
        out, i = [], 0
        while i + 8 <= len(raw):
            size = int.from_bytes(raw[i + 4:i + 8], "big")
            out.append(raw[i + 8:i + 8 + size])
            i += 8 + size
        return b"".join(out).decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


async def resolve_proxy(dns: str = PROXY_DNS, port: int = PROXY_PORT) -> list[str]:
    """One base URL per proxy task, via the swarm's internal DNS."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(dns, port, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({f"http://{i[4][0]}:{port}" for i in infos})


class DockerAPI:
    """Async, GET-only. ``calls`` (optional on every method) collects a Call per request."""

    def __init__(self, base_urls: BaseUrls = None, timeout: float = 15.0, *,
                 api_version: str = API_VERSION, transport: httpx.AsyncBaseTransport | None = None,
                 endpoint_ttl: float = 60.0) -> None:
        self.base_urls = base_urls
        self.timeout = timeout
        self.prefix = "/" + api_version.strip("/")
        self.transport = transport
        self.endpoint_ttl = endpoint_ttl
        self._client: httpx.AsyncClient | None = None
        self._eps: dict[str, Endpoint] = {}
        self._eps_at = 0.0

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------ plumbing
    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, transport=self.transport,
                                             follow_redirects=False)
        return self._client

    async def _raw(self, base: str, path: str, params: dict[str, Any] | None,
                   calls: list[Call] | None, label: str, cap: int = BODY_CAP) -> bytes:
        url = base.rstrip("/") + self.prefix + path
        call = Call(method="GET", url=f"docker://{label}{self.prefix}{path}", via="docker")
        if calls is not None:
            calls.append(call)
        t0 = time.perf_counter()
        try:
            async with self._http().stream("GET", url, params=params) as resp:
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) >= cap:
                        break
                status = resp.status_code
        except httpx.HTTPError as exc:
            call.ms = round((time.perf_counter() - t0) * 1000, 1)
            call.note = f"{type(exc).__name__}: {exc}"[:300]
            raise DockerError(f"docker {label}{path}: {call.note}") from exc
        call.ms = round((time.perf_counter() - t0) * 1000, 1)
        call.status, call.ok = status, status < 400
        if status >= 400:
            try:
                msg = json.loads(body).get("message", "")
            except (ValueError, AttributeError):
                msg = body[:300].decode("utf-8", "replace")
            call.note = redact_text(str(msg))[:300]
            raise DockerError(f"docker {label}{path}: HTTP {status} {call.note}", status)
        return body

    async def _json(self, base: str, path: str, params: dict[str, Any] | None,
                    calls: list[Call] | None, label: str) -> Any:
        body = await self._raw(base, path, params, calls, label)
        try:
            return json.loads(body)
        except ValueError as exc:
            raise DockerError(f"docker {label}{path}: answer is not JSON") from exc

    async def _base_urls(self) -> list[str]:
        src = self.base_urls
        if src is None:
            return await resolve_proxy()
        if callable(src):
            got = src()
            return list(await got) if inspect.isawaitable(got) else list(got)
        return list(src)

    async def endpoints(self, calls: list[Call] | None = None,
                        refresh: bool = False) -> dict[str, Endpoint]:
        """alias -> Endpoint for every proxy that answers ``/info`` (cached briefly)."""
        if self._eps and not refresh and time.monotonic() - self._eps_at < self.endpoint_ttl:
            return dict(self._eps)

        async def probe(base: str) -> Endpoint | None:
            try:
                info = await self._json(base, "/info", None, calls, base.split("//")[-1])
            except DockerError:
                return None
            name = info.get("Name", "")
            node_id = (info.get("Swarm") or {}).get("NodeID", "")
            return Endpoint(base, node_alias(name), name, node_id)

        found = await asyncio.gather(*(probe(b) for b in await self._base_urls()))
        self._eps = {e.alias: e for e in sorted((e for e in found if e), key=lambda e: e.alias)}
        self._eps_at = time.monotonic()
        return dict(self._eps)

    async def _node(self, node: str, calls: list[Call] | None) -> Endpoint:
        eps = await self.endpoints(calls)
        if node not in eps:
            eps = await self.endpoints(calls, refresh=True)
        if node not in eps:
            have = sorted(eps) or "none"
            raise DockerError(f"no docker-proxy answering on {node} (have: {have})")
        return eps[node]

    async def _any(self, path: str, params: dict[str, Any] | None,
                   calls: list[Call] | None, raw: bool = False) -> Any:
        """Swarm-wide call: first manager that answers; 4xx is final, else try the next."""
        eps = await self.endpoints(calls)
        if not eps:
            eps = await self.endpoints(calls, refresh=True)
        if not eps:
            raise DockerError("no docker-proxy endpoint answered /info")
        last: DockerError | None = None
        for ep in eps.values():
            try:
                if raw:
                    return await self._raw(ep.base_url, path, params, calls, ep.alias)
                return await self._json(ep.base_url, path, params, calls, ep.alias)
            except DockerError as exc:
                last = exc
                if exc.status is not None and 400 <= exc.status < 500:
                    raise
        self._eps_at = 0.0  # re-resolve next time
        assert last is not None
        raise last

    # ------------------------------------------------------------------ swarm-wide
    async def services(self, filters: dict[str, list[str]] | None = None,
                       calls: list[Call] | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"status": "true"}
        if filters:
            params["filters"] = json.dumps(filters)
        return redact_spec(await self._any("/services", params, calls))

    async def tasks(self, service: str | None = None, desired_state: str | None = None,
                    calls: list[Call] | None = None) -> list[dict[str, Any]]:
        f: dict[str, list[str]] = {}
        if service:
            f["service"] = [service]
        if desired_state:
            f["desired-state"] = [desired_state]
        params = {"filters": json.dumps(f)} if f else None
        return redact_spec(await self._any("/tasks", params, calls))

    async def nodes(self, calls: list[Call] | None = None) -> list[dict[str, Any]]:
        """Nodes, each with ``NodeHostname`` and ``Alias`` lifted out before redaction
        (redact_spec drops every ``Hostname`` key, the node's included)."""
        out = await self._any("/nodes", None, calls)
        for n in out:
            host = (n.get("Description") or {}).get("Hostname", "")
            n["NodeHostname"], n["Alias"] = host, node_alias(host)
        return redact_spec(out)

    async def task_logs(self, task_id: str, tail: int = 200,
                        calls: list[Call] | None = None) -> list[str]:
        if not _TASK_ID.match(task_id or ""):
            raise DockerError(f"not a task id: {task_id!r}")
        raw = await self._any(f"/tasks/{task_id}/logs",
                              {"stdout": 1, "stderr": 1, "tail": int(tail)}, calls, raw=True)
        return [redact_text(line, cap=4000) for line in demux(raw).splitlines()][-int(tail):]

    # ------------------------------------------------------------------ node-local
    async def info(self, node: str | None = None,
                   calls: list[Call] | None = None) -> dict[str, Any]:
        if node is None:
            return redact_spec(await self._any("/info", None, calls))
        ep = await self._node(node, calls)
        return redact_spec(await self._json(ep.base_url, "/info", None, calls, ep.alias))

    async def images(self, node: str, calls: list[Call] | None = None) -> list[dict[str, Any]]:
        ep = await self._node(node, calls)
        return redact_spec(await self._json(ep.base_url, "/images/json", None, calls, ep.alias))

    async def containers(self, node: str, all: bool = False,  # noqa: A002 - Docker's name
                         calls: list[Call] | None = None) -> list[dict[str, Any]]:
        ep = await self._node(node, calls)
        params = {"all": "true"} if all else None
        return redact_spec(await self._json(ep.base_url, "/containers/json", params, calls,
                                            ep.alias))

    async def events(self, since: dt.datetime | int, until: dt.datetime | int,
                     filters: dict[str, list[str]] | None = None, node: str | None = None,
                     calls: list[Call] | None = None) -> list[dict[str, Any]]:
        """Events in [since, until] from one node, or all nodes (each tagged ``_node``).

        ``until`` is mandatory: without it the engine streams forever.
        """
        def epoch(t: dt.datetime | int) -> int:
            return int(t.timestamp()) if isinstance(t, dt.datetime) else int(t)

        params: dict[str, Any] = {"since": epoch(since), "until": epoch(until)}
        if filters:
            params["filters"] = json.dumps(filters)
        if node:
            eps = [await self._node(node, calls)]
        else:
            eps = list((await self.endpoints(calls)).values())
        out: list[dict[str, Any]] = []
        for ep in eps:
            body = await self._raw(ep.base_url, "/events", params, calls, ep.alias, cap=EVENTS_CAP)
            lines = body.decode("utf-8", "replace").splitlines()
            if len(body) >= EVENTS_CAP:
                lines = lines[:-1]  # the last line may be cut in half
            for line in lines[:MAX_EVENTS]:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                ev["_node"] = ep.alias
                for k in ("Action", "status"):  # exec_* events carry the command line
                    if isinstance(ev.get(k), str):
                        ev[k] = redact_text(ev[k], cap=1000)
                out.append(redact_spec(ev))
        return out
