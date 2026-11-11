"""The channel contract: one ``async def send(msg) -> (ok, reply)``.

A channel is the only code that talks to a provider, and it never raises: a refused
request is ``(False, reply)`` so the dispatcher can retry it, back off, and finally
dead-letter it. ``reply`` is a small dict (status code, issue number, provider message)
that is stored on the outbox row; it must never carry a credential or an address.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Protocol

import httpx

TIMEOUT = 20.0
UA = "tgx-monitor (+https://github.com/TGX-UM/tgx-monitor)"


@dataclasses.dataclass
class Message:
    id: int
    channel: str
    event: str
    recipients: list[str]
    payload: dict[str, Any]
    issue_number: int | None = None  # github: resolved from the incident at send time


class Channel(Protocol):
    name: str

    async def send(self, msg: Message) -> tuple[bool, dict[str, Any]]: ...


def client(transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=transport, timeout=TIMEOUT,
                             headers={"User-Agent": UA}, follow_redirects=False)


def failure(exc: BaseException) -> tuple[bool, dict[str, Any]]:
    return False, {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
