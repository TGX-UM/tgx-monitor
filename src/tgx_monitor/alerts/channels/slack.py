"""Slack: one Block Kit line per event to ``#monitoring_alerts`` via an incoming webhook.

The webhook URL is a credential (anyone holding it can post), so it lives only in the
``tgxmon_slack_webhook`` secret and is masked by ``redact`` wherever it might be echoed.
"""

from __future__ import annotations

from typing import Any

import httpx

from .base import Message, client, failure


def escape(text: str) -> str:
    """Slack mrkdwn control characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def blocks(payload: dict[str, Any]) -> dict[str, Any]:
    text = escape(payload.get("text", ""))
    link = payload.get("link")
    if link and link.startswith("https://"):
        text += f" <{link}|details>"
    return {"text": payload.get("line") or payload.get("text", ""),
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}]}


class SlackChannel:
    name = "slack"

    def __init__(self, webhook: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.webhook = webhook
        self.transport = transport

    async def send(self, msg: Message) -> tuple[bool, dict[str, Any]]:
        try:
            async with client(self.transport) as http:
                r = await http.post(self.webhook, json=blocks(msg.payload))
        except Exception as exc:  # noqa: BLE001 - a channel never raises
            return failure(exc)
        return r.status_code == 200, {"status": r.status_code, "body": r.text[:200]}
