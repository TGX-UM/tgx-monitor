"""HTTP presence and content: the ``http`` kind.

request keys::

    url        (required)
    method     GET (default) | HEAD | POST
    headers    mapping
    params     mapping (query string)
    data       mapping or string (POST form/body)
    json       any (POST JSON body)
    follow     true (default): follow redirects by hand and record the chain
    verify     true (default): TLS verification
    parse_json false (default): also expose ``json`` in the observation
    github_token false (default): send the tgxmon_gh_token secret as a bearer token.
               Only ever to api.github.com, whatever the URL says, so a catalogue
               typo cannot hand the token to another host.

Observation values: ``status latency_ms body headers final_url redirects
redirect_count size`` (+ ``json`` when parse_json).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..catalogue import Check
from ..model import Observation
from .base import Context, Kind, register


@register
class HttpKind(Kind):
    name = "http"
    required = ("url",)
    vias = ("public", "tgx1", "tgx2")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        headers = dict(r.get("headers") or {})
        if r.get("github_token") and urlsplit(str(r["url"])).hostname == "api.github.com":
            token = ctx.secrets("tgxmon_gh_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        f = await ctx.http.fetch(
            r.get("method", "GET"), r["url"], via=via, params=r.get("params"),
            headers=headers, data=r.get("data"), json_body=r.get("json"),
            follow=r.get("follow", True), verify=r.get("verify", True),
            timeout=check.timeout_s,
        )
        return self.from_fetch(f, parse_json=bool(r.get("parse_json")))
