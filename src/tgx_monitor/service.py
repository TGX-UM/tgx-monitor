"""``tgx-monitor run``: the core service, everything in one process and one event loop.

One process on purpose. The alert path then depends on exactly one service; SQLite has
exactly one writer; and "is the monitor alive" has one answer, the scheduler tick.

Wired here:

* the scheduler runs every probe and hands each result to the alert engine;
* periodic hooks, each isolated so one failing hook cannot stop the others:
  every 15 s  liveness (store meta ``last_tick``) and the agents' core heartbeat file,
  every 60 s  alert engine tick (holds, windows, reminders, digests, watchdog) and the
              outbox dispatcher, the job-run recorder, the public snapshot,
  every 5 min GitHub reconcile,
  nightly     rollups + retention, then an online backup into ``TGXMON_BACKUP_DIR``;
* the private web app (uvicorn) on port 8000, in the same loop;
* catalogue hot reload when any file under the catalogue changes (rejected, keeping the
  old one, if it does not validate -- a typo must never close every incident).

Configuration is environment only (see stack.yml); secrets are files under
/run/secrets. ``TGXMON_DRY_RUN=1`` (the default) is shadow mode: everything runs and is
recorded, nothing is sent except the dead-man pings.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from . import catalogue as catmod
from .http import Http
from .kinds import IMPORT_ERRORS, KINDS, Context
from .model import iso, utcnow
from .scheduler import Scheduler
from .secrets import read_secret, secret_reader
from .store import Store

log = logging.getLogger("tgx_monitor.service")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _mounts(root: Path) -> dict[str, Path]:
    """Every directory under TGXMON_MOUNTS_DIR is a read-only alias for the file kinds."""
    if not root.is_dir():
        return {}
    return {p.name: p for p in sorted(root.iterdir()) if p.is_dir()}


def _catalogue_mtime(root: Path) -> float:
    try:
        return max((p.stat().st_mtime for p in root.rglob("*") if p.is_file()), default=0.0)
    except OSError:
        return 0.0


class Service:
    def __init__(self) -> None:
        self.cat_root = Path(env("TGXMON_CATALOGUE", "/app/catalogue"))
        self.private_yaml = read_secret("tgxmon_private_checks")
        self.catalogue = catmod.load(self.cat_root, self.private_yaml)
        self.cat_mtime = _catalogue_mtime(self.cat_root)
        self.store = Store(env("TGXMON_DB", "/data/monitor.db"))
        self.dry_run = env("TGXMON_DRY_RUN", "1") != "0"
        self.public_dir = Path(env("TGXMON_PUBLIC_DIR", "/public"))
        self.hb_dir = Path(env("TGXMON_HB_DIR", "/hb"))
        self.backup_dir = Path(env("TGXMON_BACKUP_DIR", "/data/backups"))
        self.http = Http()
        self.docker = self.agents = None
        if env("TGXMON_DOCKER_PROXY"):
            from .docker import DockerAPI

            self.docker = DockerAPI()
        if env("TGXMON_AGENTS"):
            from .agent import AgentClient

            self.agents = AgentClient(base_dns=env("TGXMON_AGENTS"))
        self.ctx = Context(http=self.http, catalogue=self.catalogue, store=self.store,
                           secrets=secret_reader(), docker=self.docker, agents=self.agents,
                           mounts=_mounts(Path(env("TGXMON_MOUNTS_DIR", "/mounts"))))
        from .alerts.dispatcher import Dispatcher, build_channels
        from .alerts.engine import AlertEngine

        self.channels = build_channels(secret_reader())
        gh = self.channels.get("github")
        if gh is not None and getattr(gh, "app", None):
            self.ctx.gh_app_token = _app_token_provider(gh)
        self.engine = AlertEngine(self.store, self.catalogue, dry_run=self.dry_run,
                                  private_base_url=env("TGXMON_PRIVATE_URL"),
                                  public_base_url=env("TGXMON_PUBLIC_URL"),
                                  watchdog="hc" in self.channels)
        admins = self.catalogue.owners.admins if self.catalogue.owners else []
        self.dispatcher = Dispatcher(self.store, self.channels, admins=admins)
        self.scheduler = Scheduler(ctx=self.ctx, catalogue=self.catalogue,
                                   on_result=self._on_result, on_tick=self._on_tick,
                                   max_concurrency=int(env("TGXMON_CONCURRENCY", "20")))
        self._last: dict[str, float] = {}
        self._tick_written = 0.0

    # ------------------------------------------------------------------ callbacks
    def _on_result(self, probe_id: str, via: str, target: Any, check: Any, result: Any,
                   rid: int) -> None:
        self.engine.ingest(probe_id, via, target, check, result, rid)

    def _on_tick(self) -> None:
        loop = asyncio.get_running_loop().time()
        if loop - self._tick_written >= 15:
            self._tick_written = loop
            self.store.set_meta("last_tick", iso())

    def _due(self, name: str, every: float) -> bool:
        now = asyncio.get_running_loop().time()
        if now - self._last.get(name, -1e9) >= every:
            self._last[name] = now
            return True
        return False

    # ------------------------------------------------------------------ hooks
    async def hooks(self) -> None:
        jobs: list[tuple[str, float, Any]] = [
            ("heartbeat", 15, self._heartbeat),
            ("reload", 30, self._maybe_reload),
            ("engine", 60, self._engine_tick),
            ("dispatch", 30, self.dispatcher.run_once),
            ("jobruns", 60, self._record_job_runs),
            ("snapshot", 60, self._snapshot),
            ("reconcile", 300, self._reconcile),
            ("nightly", 3600, self._nightly),
            ("hc-cycle", 120, self._hc_cycle),
        ]
        # Hooks that only read the store and write files run in a worker thread: on the
        # Gluster mount they can take long enough to stall the event loop, which made every
        # probe in flight time out and let /livez miss the container health check.
        threaded = {"heartbeat", "snapshot"}
        for name, every, fn in jobs:
            if not self._due(name, every):
                continue
            started = time.monotonic()
            try:
                if name in threaded:
                    out = asyncio.wait_for(asyncio.to_thread(fn), timeout=120)
                else:
                    out = fn()
                if asyncio.iscoroutine(out):
                    await asyncio.wait_for(out, timeout=120)
            except Exception as exc:  # noqa: BLE001 - one hook must never stop the others
                from .docker import DockerError

                if isinstance(exc, DockerError):  # the proxy is often still starting
                    log.warning("hook %s: docker-proxy not ready (%s); next try in %ds",
                                name, exc, every)
                else:
                    log.exception("hook %s failed", name)
            took = time.monotonic() - started
            if took > 2:
                log.warning("hook %s took %.1fs%s", name, took,
                            "" if name in threaded else " on the event loop")

    def _heartbeat(self) -> None:
        from .agent import write_heartbeat

        if self.hb_dir.is_dir():
            write_heartbeat(self.hb_dir, "core", {"probes": len(self.scheduler.slots),
                                                  "catalogue": self.catalogue.sha})

    def _engine_tick(self) -> None:
        self.engine.tick()

    async def _record_job_runs(self) -> None:
        if self.docker is None:
            return
        from .kinds.infra import record_job_runs

        await record_job_runs(self.store, self.docker)

    def _snapshot(self) -> None:
        from .snapshot import build_public

        if self.public_dir.is_dir():
            build_public(self.store, self.catalogue, self.public_dir, utcnow())

    async def _reconcile(self) -> None:
        from .alerts import reconcile

        await reconcile.run(self.engine, self.channels.get("github"))

    async def _hc_cycle(self) -> None:
        """healthchecks.io core-cycle: success while the scheduler completes its cycles,
        /fail with the age when it has stalled. Sent directly, not through the outbox, so
        a stuck outbox cannot hide a stuck scheduler (delivery-watchdog covers the outbox)."""
        hc = self.channels.get("hc")
        if hc is None:
            return
        from .snapshot import parse_ts

        last = parse_ts(self.store.get_meta("last_tick"))
        age = (utcnow() - last).total_seconds() if last else None
        if age is not None and age < 180:
            await hc.ping("core-cycle", "success", f"tick {age:.0f}s ago")
        else:
            await hc.ping("core-cycle", "fail", f"scheduler tick {age}s old")

    async def _nightly(self) -> None:
        """Once a day, after 01:00 UTC: rollups + retention, then a backup."""
        now = utcnow()
        day = now.date().isoformat()
        if now.hour < 1 or self.store.get_meta("nightly_done") == day:
            return
        stats = self.store.rollup_and_prune(now)
        log.info("rollup and prune: %s", stats)
        from .backup import backup

        hc = self.channels.get("hc")
        try:
            manifest = backup(self.store, self.backup_dir)
        except Exception as exc:
            if hc is not None:
                await hc.ping("monitor-backup", "fail", f"{type(exc).__name__}: {exc}")
            raise
        log.info("backup: %s", manifest)
        if hc is not None:
            await hc.ping("monitor-backup", "success" if manifest.get("ok") else "fail",
                          f"{manifest.get('file')} {manifest.get('bytes')} bytes "
                          f"integrity {manifest.get('integrity')}")
        self.store.set_meta("nightly_done", day)

    def _maybe_reload(self) -> None:
        m = _catalogue_mtime(self.cat_root)
        if m <= self.cat_mtime:
            return
        self.cat_mtime = m
        new = catmod.load(self.cat_root, self.private_yaml)
        problems = new.validate(known_kinds=set(KINDS))
        if problems or not self.engine.reload(new):
            log.error("catalogue change rejected (%d problems): %s", len(problems),
                      "; ".join(problems[:5]))
            return
        self.catalogue = new
        self.scheduler.load(new)
        log.info("catalogue reloaded: %s, %d probes", new.sha, len(self.scheduler.slots))

    # ------------------------------------------------------------------ run
    async def run(self) -> None:
        import uvicorn

        from .web.app import WebSettings, create_private_app

        problems = self.catalogue.validate(known_kinds=set(KINDS))
        for p in problems:
            log.error("catalogue: %s", p)
        for m, e in IMPORT_ERRORS.items():
            log.error("kind module %s failed to import: %s", m, e)
        log.info("starting: catalogue %s, %d targets, %d probes, dry_run=%s, channels=%s",
                 self.catalogue.sha, len(self.catalogue.targets), len(self.catalogue.probes()),
                 self.dry_run, sorted(self.channels))
        self.store.set_meta("started_at", iso())
        self.store.set_meta("last_tick", iso())
        app = create_private_app(self.store, self.catalogue, settings=WebSettings(
            secure_cookies=env("TGXMON_INSECURE_COOKIES") != "1",
            base_url=env("TGXMON_PRIVATE_URL"),
            gh_client_id=env("TGXMON_GH_CLIENT_ID"),
            password_login=env("TGXMON_GITHUB_ONLY") != "1"))
        server = uvicorn.Server(uvicorn.Config(
            app, host="0.0.0.0", port=int(env("TGXMON_PORT", "8000")), log_level="warning",
            proxy_headers=False, access_log=False, lifespan="off"))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop, server)
        web = asyncio.create_task(server.serve())
        try:
            await self.scheduler.run_forever(hooks=[self.hooks], hook_every=5.0)
        finally:
            server.should_exit = True
            with contextlib.suppress(Exception):
                await asyncio.wait_for(web, timeout=10)
            # Last chance to flush what is due, then close cleanly (stop-first).
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.dispatcher.run_once(), timeout=15)
            await self.http.aclose()
            if self.docker is not None:
                await self.docker.aclose()
            self.store.close()
            log.info("stopped")

    def _stop(self, server: Any) -> None:
        log.info("signal received, stopping")
        server.should_exit = True
        self.scheduler.stop()


def cmd_run(args: argparse.Namespace) -> int:
    logging.basicConfig(level=env("TGXMON_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if args.catalogue and args.catalogue != "catalogue":
        os.environ["TGXMON_CATALOGUE"] = args.catalogue
    elif not os.environ.get("TGXMON_CATALOGUE") and Path("catalogue").is_dir():
        os.environ["TGXMON_CATALOGUE"] = str(Path("catalogue").resolve())
    asyncio.run(Service().run())
    return 0


def add_commands(sub: Any) -> None:
    p = sub.add_parser("run", help="the long-running core service")
    p.set_defaults(fn=cmd_run)


__all__ = ["Service", "add_commands", "cmd_run"]


def _app_token_provider(channel: Any) -> Callable[[], Awaitable[str | None]]:
    """The GitHub App's installation token for read-only API checks. The channel caches it
    until five minutes before it expires; the lock keeps parallel checks from minting
    several at once."""
    import httpx

    lock = asyncio.Lock()

    async def get() -> str | None:
        async with lock, httpx.AsyncClient(transport=channel.transport, timeout=20) as http:
            tok = await channel.token(http)
        return tok if tok and tok != channel.pat else None

    return get
