"""healthchecks.io pings: the dead-man switches that alert when *we* go quiet.

``tgxmon_hc_urls`` maps a check name (``delivery-watchdog``, ``core-cycle``,
``monitor-backup``, ...) to its ping URL; the URL is the credential. ``status`` is
``success`` (plain ping), ``fail`` (``/fail``) or ``start`` (``/start``); a short body
travels with the ping so the healthchecks.io log says why.
"""

from __future__ import annotations

from typing import Any

import httpx

from .base import Message, client, failure

SUFFIX = {"success": "", "fail": "/fail", "start": "/start"}


class HcChannel:
    name = "hc"

    def __init__(self, urls: dict[str, str],
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.urls = urls
        self.transport = transport

    async def ping(self, check: str, status: str = "success",
                   body: str = "") -> tuple[bool, dict[str, Any]]:
        url = self.urls.get(check)
        if not url:
            return False, {"error": f"no ping URL for {check!r}"}
        try:
            async with client(self.transport) as http:
                r = await http.post(url.rstrip("/") + SUFFIX.get(status, ""),
                                    content=body[:10000].encode())
        except Exception as exc:  # noqa: BLE001
            return failure(exc)
        return r.status_code == 200, {"status": r.status_code}

    async def send(self, msg: Message) -> tuple[bool, dict[str, Any]]:
        p = msg.payload
        return await self.ping(p.get("check", ""), p.get("status", "success"), p.get("body", ""))
