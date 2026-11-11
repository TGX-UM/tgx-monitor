"""E-mail through aiosmtplib.

Recipients arrive as handles (``marvinm2``, ``cc:egonw``) and are resolved here, at send
time, from the ``tgxmon_contacts`` secret, so addresses exist only in that secret and in
the SMTP conversation. ``tgxmon_smtp`` is JSON: ``host, port, user, password, from`` and
either ``starttls: true`` (587) or ``tls: true`` (465). The reply stored on the outbox
row holds the server's response line and how many recipients were refused, never the
addresses.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from email.message import EmailMessage
from typing import Any

import aiosmtplib

from .base import Message, failure

Sender = Callable[..., Awaitable[Any]]


def _one_line(s: str) -> str:
    return " ".join(str(s).split())[:200]


class SmtpChannel:
    name = "smtp"

    def __init__(self, conf: dict[str, Any], contacts: dict[str, str], *,
                 sender: Sender = aiosmtplib.send) -> None:
        self.conf = conf
        self.contacts = contacts
        self.sender = sender

    def addresses(self, handles: list[str]) -> tuple[list[str], list[str], list[str]]:
        """(to, cc, handles without an address)."""
        to, cc, missing = [], [], []
        for h in handles:
            is_cc = h.startswith("cc:")
            name = h.removeprefix("cc:")
            addr = self.contacts.get(name)
            if not addr:
                missing.append(name)
            elif addr not in to and addr not in cc:
                (cc if is_cc else to).append(addr)
        return to, cc, missing

    def build(self, msg: Message, to: list[str], cc: list[str]) -> EmailMessage:
        em = EmailMessage()
        em["From"] = self.conf["from"]
        em["To"] = ", ".join(to or cc)
        if cc and to:
            em["Cc"] = ", ".join(cc)
        em["Subject"] = _one_line(msg.payload.get("subject", "[tgx-monitor]"))
        em["Auto-Submitted"] = "auto-generated"
        em.set_content(msg.payload.get("text", ""))
        return em

    async def send(self, msg: Message) -> tuple[bool, dict[str, Any]]:
        to, cc, missing = self.addresses(msg.recipients)
        if not to and not cc:
            return False, {"error": "no address for: " + ", ".join(missing or ["(nobody)"])}
        c = self.conf
        try:
            errors, response = await self.sender(
                self.build(msg, to, cc), hostname=c["host"], port=int(c.get("port", 587)),
                username=c.get("user"), password=c.get("password"),
                use_tls=bool(c.get("tls")), start_tls=True if c.get("starttls") else None,
                timeout=30)
        except Exception as exc:  # noqa: BLE001
            return failure(exc)
        reply: dict[str, Any] = {"status": 250, "response": _one_line(response),
                                 "refused": len(errors or {})}
        if missing:
            reply["no_address"] = missing
        return True, reply
