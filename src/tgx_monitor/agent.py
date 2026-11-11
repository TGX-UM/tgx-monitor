"""The per-node host agent: ``tgx-monitor agent``.

Why a separate process at all: core runs as one replica somewhere in the swarm and can
see neither the other node's kernel (RAID, memory, load, boot time) nor whether the two
nodes can still reach each other. Both freezes this autumn (2026-10-22, 2026-11-02)
were one node's Docker dying while the host stayed up, and TGX1's root array has been
degraded unnoticed. So one agent runs per node (global mode, non-root, ``cap_drop:
ALL``, on the private overlay ``tgxmon_int``) and does three things every 30 s:

1. **Gathers host signals** from what an unprivileged container may read: ``/proc``
   (host-global for mdstat, meminfo, loadavg, stat), ``statvfs`` of read-only binds,
   the root status JSON that Egon's cron writes (``host/tgx-monitor-status.sh``: Gluster
   heal, mdadm, SMART, which need root), a capped listing of the HiDrive backup dirs,
   and TCP reachability of the peer node's swarm, Gluster and Traefik ports.
2. **Serves them** as ``GET /signals`` on port 8001 for core (the ``host`` kind reads
   them through :class:`AgentClient`). Nothing here judges; core's assertions do.
3. **Is a dead-man switch for core and the peer.** It writes ``<node>.json`` into a
   shared Gluster dir and reads the peer's file and ``core.json`` from the same dir.
   Core must write ``core.json`` there (``{"node": "core", "ts": "<ISO UTC>"}``, at least
   once a minute, atomically; :func:`write_heartbeat` does it). The agent then pings its
   own healthchecks.io check (``agent-<node>``): success when both are fresh, ``/fail``
   with the reason when either is older than 5 min. That alert path survives core
   being down, and a stalled Gluster replica shows up as a stale peer file.

Every blocking read runs in a thread with a timeout, and a read that is still stuck
(a hung CIFS mount) is not started again, so the loop and ``/signals`` keep answering.

Environment::

    TGXMON_NODE            node hostname ({{.Node.Hostname}}), mapped to tgx1/tgx2
    TGXMON_NODE_ALIASES    optional override, e.g. "h3068544=tgx1,h2973005=tgx2"
    TGXMON_AGENT_PATHS     statvfs targets: "rootfs=/hostfs/rootfs-probe,..."
    TGXMON_AGENT_HIDRIVE   backup dirs to list: "name=/hostfs/hidrive/docker/x,..."
    TGXMON_AGENT_STATUS    root status file (default /hostfs/root-status/{host}.json)
    TGXMON_AGENT_HB_DIR    shared heartbeat dir on Gluster (rw)
    TGXMON_AGENT_PROC      /proc (tests point it at a fixture dir)
    TGXMON_AGENT_PORT      8001
    TGXMON_DRY_RUN=1       never ping healthchecks; the would-be ping is shown in /signals
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import json
import logging
import os
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .docker import NODE_ALIASES
from .http import NODES, USER_AGENT
from .model import iso
from .secrets import read_secret_json

log = logging.getLogger("tgx_monitor.agent")

PORT = 8001
INTERVAL_S = 30.0
STALE_S = 300.0  # a heartbeat older than this fails the agent's healthchecks ping
STARTUP_GRACE_S = 300.0  # no /fail while everything is still coming up after a deploy
PING_EVERY_S = 60.0
PEER_EVERY_S = 60.0  # peer port probes: each one is a log line on the peer's glusterd
HIDRIVE_EVERY_S = 300.0  # CIFS listings are slow and backups change daily at most
READ_TIMEOUT_S = 10.0
PEER_PORTS = (2377, 7946, 24007, 443)
LIST_CAP = 200
STATUS_CAP = 256 * 1024

_MD_HEAD = re.compile(r"^(md\w+)\s*:\s*(\S+)\s*(.*)$")
_MD_COUNT = re.compile(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]")
_MD_LEVEL = re.compile(r"^(raid\d+|linear|multipath|faulty)$")
_MD_PROGRESS = re.compile(r"(recovery|resync|reshape|check)\s*=\s*([\d.]+%)")


# ---------------------------------------------------------------------- naming
def parse_pairs(text: str | None) -> dict[str, str]:
    """``"a=/x, b=/y"`` -> {"a": "/x", "b": "/y"}. A bare path is named by its last part."""
    out: dict[str, str] = {}
    for item in (text or "").split(","):
        item = item.strip()
        if not item:
            continue
        name, sep, value = item.partition("=")
        if not sep:
            name, value = Path(item).name or item, item
        out[name.strip()] = value.strip()
    return out


def node_alias(hostname: str, aliases: dict[str, str] | None = None) -> str:
    """Map a swarm node hostname (``h3068544.stratoserver.net``) to tgx1/tgx2."""
    short = hostname.strip().split(".")[0]
    if short in NODES:
        return short
    return (aliases or NODE_ALIASES).get(short, short)


def peer_of(node: str) -> str | None:
    others = [n for n in NODES if n != node]
    return others[0] if len(others) == 1 else None


# ---------------------------------------------------------------------- parsers (pure)
def parse_mdstat(text: str) -> dict[str, Any]:
    """Arrays from /proc/mdstat. Degraded means an underscore in ``[UU]``."""
    arrays: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        m = _MD_HEAD.match(line)
        if m:
            name, state, rest = m.groups()
            parts = rest.split()
            level = next((x for x in parts if _MD_LEVEL.match(x)), None)
            devices = [re.sub(r"\[\d+\].*$", "", p) for p in parts if "[" in p]
            failed = [re.sub(r"\[\d+\].*$", "", p) for p in parts if "(F)" in p]
            current = arrays[name] = {
                "state": state, "level": level, "devices": devices, "failed_devices": failed,
                "total": None, "active": None, "status": None, "degraded": False,
                "progress": None,
            }
            continue
        if current is None:
            continue
        c = _MD_COUNT.search(line)
        if c:
            current["total"], current["active"] = int(c.group(1)), int(c.group(2))
            current["status"] = c.group(3)
            current["degraded"] = "_" in c.group(3) or current["active"] < current["total"]
        p = _MD_PROGRESS.search(line)
        if p:
            current["progress"] = f"{p.group(1)} {p.group(2)}"
    for a in arrays.values():
        # An inactive array or one with a member marked (F) is degraded whatever [UU] says.
        a["degraded"] = a["degraded"] or a["state"] != "active" or bool(a["failed_devices"])
    degraded = sorted(n for n, a in arrays.items() if a["degraded"])
    return {"arrays": arrays, "degraded_arrays": degraded,
            "degraded_count": len(degraded), "array_count": len(arrays)}


def parse_meminfo(text: str) -> dict[str, Any]:
    kb: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        val = rest.split()
        if val and val[0].isdigit():
            kb[key.strip()] = int(val[0])
    gib = 1024 * 1024
    total, avail = kb.get("MemTotal", 0), kb.get("MemAvailable", 0)
    st, sf = kb.get("SwapTotal", 0), kb.get("SwapFree", 0)
    return {
        "total_gb": round(total / gib, 2), "available_gb": round(avail / gib, 2),
        "available_pct": round(100 * avail / total, 1) if total else None,
        "swap_total_gb": round(st / gib, 2), "swap_used_gb": round((st - sf) / gib, 2),
        "swap_free_pct": round(100 * sf / st, 1) if st else 100.0,
    }


def parse_loadavg(text: str, cpus: int | None) -> dict[str, Any]:
    f = text.split()
    l1, l5, l15 = (float(x) for x in f[:3])
    n = cpus or 1
    return {"load1": l1, "load5": l5, "load15": l15, "cpus": cpus,
            "per_cpu1": round(l1 / n, 2), "per_cpu15": round(l15 / n, 2)}


def parse_btime(text: str) -> int | None:
    for line in text.splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return None


def mount_fstype(path: str, mountinfo: str) -> tuple[str | None, bool]:
    """(fstype of the mount holding ``path``, whether ``path`` is itself a mount point)."""
    best, fstype = "", None
    for line in mountinfo.splitlines():
        pre, sep, post = line.partition(" - ")
        f = pre.split()
        if not sep or len(f) < 5:
            continue
        mp = f[4].replace("\\040", " ")
        if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) >= len(best):
            best, fstype = mp, (post.split() or [None])[0]
    return fstype, best == path


# ---------------------------------------------------------------------- blocking readers
def disk_usage(path: str, mountinfo: str = "") -> dict[str, Any]:
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = total - st.f_bfree * st.f_frsize
    fstype, is_mount = mount_fstype(path, mountinfo) if mountinfo else (None, None)
    return {
        "total_gb": round(total / 1e9, 2), "free_gb": round(free / 1e9, 2),
        "used_pct": round(100 * used / (used + free), 1) if used + free else None,
        "inodes_used_pct": round(100 * (st.f_files - st.f_ffree) / st.f_files, 1)
        if st.f_files else None,
        "fstype": fstype, "mounted": is_mount,
    }


def read_root_status(path: str, now: float) -> dict[str, Any]:
    p = Path(path)
    try:
        st = p.stat()
    except FileNotFoundError:
        return {"present": False, "error": f"{p.name} not found (root cron not installed?)"}
    out: dict[str, Any] = {"present": True, "mtime": st.st_mtime,
                           "age_s": round(now - st.st_mtime, 1),
                           "age_h": round((now - st.st_mtime) / 3600, 3)}
    if st.st_size > STATUS_CAP:
        out["error"] = f"status file larger than {STATUS_CAP} bytes"
        return out
    try:
        out["content"] = json.loads(p.read_text())
    except ValueError as exc:
        out["error"] = f"status file is not JSON: {exc}"
    return out


def list_dir(path: str, now: float, cap: int = LIST_CAP) -> dict[str, Any]:
    """Names, mtimes and sizes of up to ``cap`` entries, newest first."""
    entries = []
    truncated = False
    with os.scandir(path) as it:
        for i, e in enumerate(it):
            if i >= cap:
                truncated = True
                break
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            entries.append({"name": e.name, "mtime": st.st_mtime, "size": st.st_size,
                            "dir": e.is_dir(follow_symlinks=False)})
    entries.sort(key=lambda x: x["mtime"], reverse=True)
    newest = entries[0] if entries else None
    return {
        "count": len(entries), "truncated": truncated, "entries": entries,
        "newest_name": newest["name"] if newest else None,
        "newest_mtime": newest["mtime"] if newest else None,
        "newest_size": newest["size"] if newest else None,
        "newest_age_h": round((now - newest["mtime"]) / 3600, 3) if newest else None,
        "total_size": sum(x["size"] for x in entries),
    }


def read_heartbeat(hb_dir: str | Path, name: str, now: float) -> dict[str, Any]:
    """Age of ``<name>.json`` from the ``ts`` it carries (Gluster mtimes can lag)."""
    p = Path(hb_dir) / f"{name}.json"
    try:
        doc = json.loads(p.read_text())
        ts = doc.get("ts")
        epoch = _epoch(ts) if ts else p.stat().st_mtime
    except FileNotFoundError:
        return {"present": False, "age_s": None}
    except (OSError, ValueError, AttributeError) as exc:
        return {"present": False, "age_s": None, "error": f"{type(exc).__name__}: {exc}"}
    return {"present": True, "ts": ts, "age_s": round(now - epoch, 1)}


def write_heartbeat(hb_dir: str | Path, name: str, extra: dict[str, Any] | None = None) -> None:
    """Atomically write ``<hb_dir>/<name>.json``. Core calls this with name ``core``."""
    d = Path(hb_dir)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f".{name}.json.tmp"
    tmp.write_text(json.dumps({"node": name, "ts": iso(), **(extra or {})}))
    tmp.replace(d / f"{name}.json")


def _epoch(ts: str) -> float:
    d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.UTC)
    return d.timestamp()


async def tcp_probe(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError) as exc:
        return {"ok": False, "ms": None, "error": f"{type(exc).__name__}: {exc}"[:200]}
    w.close()
    with contextlib.suppress(OSError):
        await w.wait_closed()
    return {"ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)}


# ---------------------------------------------------------------------- the agent
@dataclass
class AgentConfig:
    node: str
    hostname: str = ""
    proc: str = "/proc"
    paths: dict[str, str] = field(default_factory=dict)
    hidrive: dict[str, str] = field(default_factory=dict)
    status_file: str = "/hostfs/root-status/{host}.json"
    hb_dir: str = "/hb"
    port: int = PORT
    interval: float = INTERVAL_S
    dry_run: bool = False

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> AgentConfig:
        e = os.environ if env is None else env
        host = e.get("TGXMON_NODE") or socket.gethostname()
        aliases = parse_pairs(e.get("TGXMON_NODE_ALIASES")) or None
        return cls(
            node=node_alias(host, aliases), hostname=host,
            proc=e.get("TGXMON_AGENT_PROC", "/proc"),
            paths=parse_pairs(e.get("TGXMON_AGENT_PATHS")),
            hidrive=parse_pairs(e.get("TGXMON_AGENT_HIDRIVE")),
            # "{host}" -> this node's short hostname: the root status files of both
            # nodes live side by side on Gluster.
            status_file=e.get("TGXMON_AGENT_STATUS", cls.status_file).replace(
                "{host}", host.split(".")[0]),
            hb_dir=e.get("TGXMON_AGENT_HB_DIR", cls.hb_dir),
            port=int(e.get("TGXMON_AGENT_PORT", PORT)),
            interval=float(e.get("TGXMON_AGENT_INTERVAL", INTERVAL_S)),
            dry_run=e.get("TGXMON_DRY_RUN", "") in ("1", "true", "yes"),
        )


class Agent:
    def __init__(self, cfg: AgentConfig, *, hc_urls: dict[str, str] | None = None,
                 client: httpx.AsyncClient | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.hc_urls = hc_urls if hc_urls is not None else (
            read_secret_json("tgxmon_hc_urls") or {})
        self.client = client
        self.clock = clock
        self.started = clock()
        self.snapshot: dict[str, Any] = {}
        self._inflight: dict[str, asyncio.Future[Any]] = {}
        self._last: dict[str, float] = {}
        self._kept: dict[str, Any] = {}  # slower signals carried between cycles
        self._ping: dict[str, Any] = {}

    # ------------------------------------------------------------------ helpers
    async def _blocking(self, key: str, fn: Callable[..., Any], *args: Any) -> Any:
        prev = self._inflight.get(key)
        if prev is not None and not prev.done():
            raise TimeoutError(f"previous read of {key} is still blocked")
        fut = asyncio.ensure_future(asyncio.to_thread(fn, *args))
        self._inflight[key] = fut
        return await asyncio.wait_for(asyncio.shield(fut), READ_TIMEOUT_S)

    def _proc(self, name: str) -> str:
        return (Path(self.cfg.proc) / name).read_text()

    def _due(self, key: str, every: float, now: float) -> bool:
        if now - self._last.get(key, -1e18) >= every:
            self._last[key] = now
            return True
        return False

    # ------------------------------------------------------------------ collection
    async def collect(self) -> dict[str, Any]:
        now = self.clock()
        snap: dict[str, Any] = {"node": self.cfg.node, "hostname": self.cfg.hostname,
                                "collected_at": iso(), "collected_epoch": now,
                                "interval_s": self.cfg.interval, "errors": {}}
        errs = snap["errors"]

        async def section(name: str, coro: Any) -> None:
            try:
                snap[name] = await coro
            except Exception as exc:  # noqa: BLE001 - one bad signal never stops the rest
                errs[name] = f"{type(exc).__name__}: {exc}"[:300]

        async def proc_signals() -> None:
            await section("mdstat", self._blocking("mdstat", lambda: parse_mdstat(
                self._proc("mdstat"))))
            await section("memory", self._blocking("meminfo", lambda: parse_meminfo(
                self._proc("meminfo"))))
            await section("load", self._blocking("loadavg", lambda: parse_loadavg(
                self._proc("loadavg"), os.cpu_count())))
            await section("boot", self._blocking("stat", self._boot, now))

        await asyncio.gather(
            proc_signals(),
            section("disk", self._disks()),
            section("root_status", self._blocking(
                "root_status", read_root_status, self.cfg.status_file, now)),
            self._slow("peer", PEER_EVERY_S, now, self._peer, snap),
            self._slow("hidrive", HIDRIVE_EVERY_S, now, self._hidrive, snap),
        )
        return snap

    async def _slow(self, name: str, every: float, now: float, fn: Callable[[], Any],
                    snap: dict[str, Any]) -> None:
        if self._due(name, every, now):
            try:
                self._kept[name] = await fn()
                self._kept.pop(f"{name}!err", None)
            except Exception as exc:  # noqa: BLE001
                self._kept[f"{name}!err"] = f"{type(exc).__name__}: {exc}"[:300]
        if name in self._kept:
            snap[name] = self._kept[name]
        if f"{name}!err" in self._kept:
            snap["errors"][name] = self._kept[f"{name}!err"]

    def _boot(self, now: float) -> dict[str, Any]:
        bt = parse_btime(self._proc("stat"))
        return {"btime": bt, "boot_at": iso(_from_epoch(bt)) if bt else None,
                "uptime_h": round((now - bt) / 3600, 2) if bt else None}

    async def _disks(self) -> dict[str, Any]:
        try:
            mi = await self._blocking("mountinfo", lambda: self._proc("self/mountinfo"))
        except (OSError, TimeoutError):
            mi = ""
        out: dict[str, Any] = {}
        for name, path in self.cfg.paths.items():
            try:
                out[name] = await self._blocking(f"statvfs:{name}", disk_usage, path, mi)
            except Exception as exc:  # noqa: BLE001
                out[name] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
        return out

    async def _hidrive(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        now = self.clock()
        for name, path in self.cfg.hidrive.items():
            try:
                out[name] = await self._blocking(f"list:{name}", list_dir, path, now)
            except Exception as exc:  # noqa: BLE001
                out[name] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
        return out

    async def _peer(self) -> dict[str, Any]:
        peer = peer_of(self.cfg.node)
        if peer is None:
            return {"node": None, "error": f"no peer known for {self.cfg.node}"}
        ip = NODES[peer]
        res = await asyncio.gather(*(tcp_probe(ip, p) for p in PEER_PORTS))
        ports = {str(p): r for p, r in zip(PEER_PORTS, res, strict=True)}
        failed = [p for p, r in ports.items() if not r["ok"]]
        return {"node": peer, "ip": ip, "ports": ports, "all_ok": not failed, "failed": failed,
                "checked_at": iso()}

    # ------------------------------------------------------------------ dead-man
    def heartbeats(self, now: float) -> dict[str, Any]:
        out = {"core": read_heartbeat(self.cfg.hb_dir, "core", now)}
        peer = peer_of(self.cfg.node)
        if peer:
            out[peer] = read_heartbeat(self.cfg.hb_dir, peer, now)
        return out

    @staticmethod
    def verdict(hbs: dict[str, Any]) -> str | None:
        """None when every heartbeat is fresh, else the reason for /fail."""
        bad = []
        for name, hb in hbs.items():
            if not hb.get("present"):
                bad.append(f"{name} heartbeat missing")
            elif hb["age_s"] > STALE_S:
                bad.append(f"{name} heartbeat {int(hb['age_s'])}s old")
        return "; ".join(bad) or None

    async def ping(self, reason: str | None, now: float) -> None:
        """Ping healthchecks: success, or /fail with the reason. Once a minute, or on change."""
        if now - self.started < STARTUP_GRACE_S and reason is not None:
            self._ping = {"state": "grace", "reason": reason}
            return
        changed = reason != self._ping.get("reason")
        if not changed and now - self._ping.get("at", -1e18) < PING_EVERY_S:
            return
        kind = "fail" if reason else "success"
        url = self.hc_urls.get(f"agent-{self.cfg.node}")
        rec: dict[str, Any] = {"at": now, "at_iso": iso(), "kind": kind, "reason": reason}
        if not url:
            rec["state"] = "no url (secret tgxmon_hc_urls)"
        elif self.cfg.dry_run:
            rec["state"] = "dry-run"
        else:
            body = (reason or "ok")[:1000]
            try:
                client = self.client or httpx.AsyncClient(timeout=10.0,
                                                          headers={"User-Agent": USER_AGENT})
                self.client = client
                r = await client.post(url + ("/fail" if reason else ""), content=body)
                rec["status"] = r.status_code
                rec["state"] = "sent" if r.status_code < 400 else "error"
            except httpx.HTTPError as exc:
                rec["state"] = f"error: {type(exc).__name__}"
        self._ping = rec

    # ------------------------------------------------------------------ loop
    async def cycle(self) -> dict[str, Any]:
        snap = await self.collect()
        now = self.clock()
        try:
            await self._blocking("hb-write", write_heartbeat, self.cfg.hb_dir, self.cfg.node,
                                 {"hostname": self.cfg.hostname})
        except Exception as exc:  # noqa: BLE001
            snap["errors"]["heartbeat_write"] = f"{type(exc).__name__}: {exc}"[:200]
        try:
            hbs = await self._blocking("hb-read", self.heartbeats, now)
        except Exception as exc:  # noqa: BLE001
            hbs = {"core": {"present": False, "age_s": None, "error": str(exc)[:200]}}
        snap["heartbeats"] = hbs
        await self.ping(self.verdict(hbs), now)
        snap["hc"] = {k: v for k, v in self._ping.items() if k != "at"}
        self.snapshot = snap
        return snap

    async def run_forever(self) -> None:
        while True:
            t0 = self.clock()
            try:
                await self.cycle()
            except Exception:  # noqa: BLE001 - the loop must outlive any single cycle
                log.exception("agent cycle failed")
            await asyncio.sleep(max(1.0, self.cfg.interval - (self.clock() - t0)))

    def app(self) -> Any:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse, PlainTextResponse
        from starlette.routing import Route

        async def signals(_request: Any) -> JSONResponse:
            if not self.snapshot:
                return JSONResponse({"node": self.cfg.node, "error": "not collected yet"},
                                    status_code=503)
            return JSONResponse(self.snapshot)

        async def livez(_request: Any) -> PlainTextResponse:
            age = self.clock() - self.snapshot.get("collected_epoch", self.started)
            ok = age < 4 * self.cfg.interval
            return PlainTextResponse(f"{'ok' if ok else 'stale'} {age:.0f}s",
                                     status_code=200 if ok else 503)

        return Starlette(routes=[Route("/signals", signals), Route("/livez", livez)])


def _from_epoch(epoch: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(epoch, dt.UTC)


async def serve(cfg: AgentConfig) -> None:
    import uvicorn

    agent = Agent(cfg)
    server = uvicorn.Server(uvicorn.Config(agent.app(), host="0.0.0.0", port=cfg.port,
                                           log_level="warning", access_log=False))
    loop_task = asyncio.create_task(agent.run_forever())
    try:
        await server.serve()
    finally:
        loop_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await loop_task
        if agent.client is not None:
            await agent.client.aclose()


# ---------------------------------------------------------------------- core's side
class AgentClient:
    """Core's view of the agents: ``await signals()`` -> {"tgx1": {...}, "tgx2": {...}}.

    Resolves ``tasks.agent`` (one A record per running agent task on the shared overlay)
    and asks each for ``/signals``. A node with no answering agent gets
    ``{"error": "..."}``. Results are cached for ``ttl`` seconds so a cycle of host
    checks costs one request per agent.
    """

    def __init__(self, base_dns: str = "tasks.agent", port: int = PORT, *,
                 timeout: float = 5.0, ttl: float = 20.0,
                 transport: httpx.AsyncBaseTransport | None = None,
                 resolve: Callable[[str, int], Any] | None = None) -> None:
        self.base_dns, self.port, self.timeout, self.ttl = base_dns, port, timeout, ttl
        self._transport = transport
        self._resolve = resolve
        self._cache: tuple[float, dict[str, Any]] | None = None
        self._lock = asyncio.Lock()

    async def _addresses(self) -> list[str]:
        if self._resolve is not None:
            res = self._resolve(self.base_dns, self.port)
            return list(await res if asyncio.iscoroutine(res) else res)
        infos = await asyncio.get_running_loop().getaddrinfo(
            self.base_dns, self.port, type=socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})

    async def signals(self) -> dict[str, Any]:
        async with self._lock:
            if self._cache and time.monotonic() - self._cache[0] < self.ttl:
                return self._cache[1]
            out = await self._fetch_all()
            self._cache = (time.monotonic(), out)
            return out

    async def _fetch_all(self) -> dict[str, Any]:
        try:
            ips = await self._addresses()
        except (OSError, socket.gaierror) as exc:
            return {n: {"error": f"cannot resolve {self.base_dns}: {exc}"} for n in NODES}
        out: dict[str, Any] = {}
        problems: list[str] = []
        async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as c:
            async def one(ip: str) -> None:
                host = f"[{ip}]" if ":" in ip else ip
                try:
                    r = await c.get(f"http://{host}:{self.port}/signals")
                    doc = r.json()
                except (httpx.HTTPError, ValueError) as exc:
                    problems.append(f"{ip}: {type(exc).__name__}: {exc}"[:200])
                    return
                node = doc.get("node") if isinstance(doc, dict) else None
                if not node:
                    problems.append(f"{ip}: answer without a node name (HTTP {r.status_code})")
                    return
                if r.status_code >= 400 and "error" not in doc:
                    doc["error"] = f"HTTP {r.status_code}"
                doc["_addr"] = ip
                out[node] = doc
            await asyncio.gather(*(one(ip) for ip in ips))
        for n in NODES:
            if n not in out:
                why = "; ".join(problems) or f"{len(ips)} agent task(s) resolved, none is {n}"
                out[n] = {"error": f"no agent answered for {n} ({why})"}
        return out


# ---------------------------------------------------------------------- cli
def cmd_agent(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = AgentConfig.from_env()
    if args.port:
        cfg.port = args.port
    if args.once:
        cfg.dry_run = True  # a one-off look must never ping healthchecks
        snap = asyncio.run(Agent(cfg).cycle())
        print(json.dumps(snap, indent=1, default=str))
        return 0
    log.info("agent for %s (%s) on :%d, dry_run=%s", cfg.node, cfg.hostname, cfg.port,
             cfg.dry_run)
    asyncio.run(serve(cfg))
    return 0


def add_commands(sub: Any) -> None:
    p = sub.add_parser("agent", help="the per-node host agent (GET /signals on :8001)")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--once", action="store_true", help="collect once, print, exit")
    p.set_defaults(fn=cmd_agent)
