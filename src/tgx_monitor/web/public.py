"""``tgx-monitor serve-public``: the public status page, read-only.

This process has no secrets, no database and no Docker access. It serves whatever the
core last wrote with :func:`tgx_monitor.snapshot.build_public`, following the
``current`` symlink on every request so a new snapshot appears without a restart and a
core outage leaves the last one in place.

Only GET and HEAD exist (StaticFiles answers anything else with 405). The same strict
headers as the private UI go on every response, and a per-address rate limit sits in
front as a second line behind Traefik's.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from .auth import RateLimiter, SecurityHeaders, client_ip

DEFAULT_DIR = os.environ.get("TGXMON_PUBLIC_DIR", "public")


class RateLimit:
    def __init__(self, app: ASGIApp, *, limit: int = 120, per: float = 60.0) -> None:
        self.app, self.limiter = app, RateLimiter(limit, per)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not self.limiter.hit(client_ip(scope)):
            await PlainTextResponse("too many requests", status_code=429,
                                    headers={"retry-after": "60"})(scope, receive, send)
            return
        await self.app(scope, receive, send)


def create_public_app(directory: Path | str, *, limit: int = 120) -> Starlette:
    """Serve ``directory/current`` (or ``directory`` itself before the first snapshot)."""
    d = Path(directory)
    root = d / "current" if (d / "current").exists() or not (d / "index.html").exists() else d
    static = StaticFiles(directory=root, html=True, check_dir=False, follow_symlink=False)
    return Starlette(routes=[Mount("/", static)], middleware=[
        Middleware(SecurityHeaders, cache="public, max-age=30", static_prefix="/static/"),
        Middleware(RateLimit, limit=limit)])


def cmd_serve_public(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(create_public_app(args.dir, limit=args.rate), host=args.host, port=args.port,
                server_header=False, proxy_headers=False, access_log=False)
    return 0


def add_commands(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("serve-public", help="serve the static public status snapshot")
    p.add_argument("--dir", default=DEFAULT_DIR, help="snapshot directory (holds current/)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--rate", type=int, default=120, help="requests per minute per address")
    p.set_defaults(fn=cmd_serve_public)
