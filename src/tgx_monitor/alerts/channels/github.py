"""GitHub issues, opened by the ``tgx-monitor[bot]`` GitHub App.

Why an App and not a token: GitHub does not notify you about an issue you opened
yourself, so issues created with Marvin's PAT would never reach Marvin. The App signs a
short JWT (RS256, ``tgxmon_gh_app_key``; app and installation ids from
``TGXMON_GH_APP_ID`` / ``TGXMON_GH_INSTALLATION_ID``), swaps it for an installation
token and caches that until five minutes before it expires. ``tgxmon_gh_token`` (a
PAT) is the fallback when the App is not configured or its token cannot be minted.

Payload actions (built by ``router.render``): ``open`` {title, body, labels},
``reopen`` / ``comment`` / ``close`` {comment}; the issue number comes from the
incident (``Message.issue_number``). :meth:`GitHubChannel.open_alert_issues` lists open
``alert`` issues for the reconcile loop.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from ...model import utcnow
from .base import Message, client, failure

API = "https://api.github.com"


class GitHubChannel:
    name = "github"

    def __init__(self, repo: str, *, app_id: str | None = None,
                 installation_id: str | None = None, app_key: str | None = None,
                 token: str | None = None, transport: httpx.AsyncBaseTransport | None = None,
                 now: Callable[[], dt.datetime] = utcnow, api: str = API) -> None:
        self.repo = repo
        self.app = (app_id, installation_id, app_key) if app_id and installation_id and app_key \
            else None
        self.pat = token
        self.transport = transport
        self.now = now
        self.api = api.rstrip("/")
        self._token: tuple[str, dt.datetime] | None = None

    # ------------------------------------------------------------------ auth
    def app_jwt(self) -> str:
        assert self.app is not None
        app_id, _, key = self.app
        t = int(self.now().timestamp())
        return jwt.encode({"iat": t - 60, "exp": t + 540, "iss": str(app_id)}, key,
                          algorithm="RS256")

    async def token(self, http: httpx.AsyncClient) -> str | None:
        now = self.now()
        if self._token and self._token[1] - dt.timedelta(minutes=5) > now:
            return self._token[0]
        if self.app is not None:
            try:
                r = await http.post(f"{self.api}/app/installations/{self.app[1]}/access_tokens",
                                    headers=self._headers(self.app_jwt()))
                if r.status_code == 201:
                    data = r.json()
                    exp = dt.datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
                    self._token = (data["token"], exp)
                    return data["token"]
            except (httpx.HTTPError, ValueError, KeyError, jwt.PyJWTError):
                pass
        return self.pat

    @staticmethod
    def _headers(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    # ------------------------------------------------------------------ calls
    async def _call(self, http: httpx.AsyncClient, method: str, path: str,
                    body: dict[str, Any] | None = None, params: dict[str, Any] | None = None,
                    ) -> httpx.Response:
        tok = await self.token(http)
        if not tok:
            raise RuntimeError("no GitHub credential (App or tgxmon_gh_token)")
        r = await http.request(method, f"{self.api}/repos/{self.repo}{path}",
                               headers=self._headers(tok), json=body, params=params)
        if r.status_code == 401:
            self._token = None  # revoked or expired early: mint a fresh one next time
        return r

    async def send(self, msg: Message) -> tuple[bool, dict[str, Any]]:
        p, n = msg.payload, msg.issue_number
        action = p.get("action", "comment")
        try:
            async with client(self.transport) as http:
                if action == "open":
                    r = await self._call(http, "POST", "/issues", {
                        "title": p["title"], "body": p["body"], "labels": p.get("labels", [])})
                    ok = r.status_code == 201
                    data = r.json() if ok else {}
                    return ok, {"status": r.status_code, "number": data.get("number"),
                                "url": data.get("html_url")}
                if not n:
                    return False, {"error": "no issue number for this incident"}
                steps: list[tuple[str, str, dict[str, Any]]] = []
                if action == "reopen":
                    steps.append(("PATCH", f"/issues/{n}", {"state": "open"}))
                if p.get("comment"):
                    steps.append(("POST", f"/issues/{n}/comments", {"body": p["comment"]}))
                if action == "close":
                    steps.append(("PATCH", f"/issues/{n}",
                                  {"state": "closed", "state_reason": "completed"}))
                status = 0
                for method, path, body in steps:
                    r = await self._call(http, method, path, body)
                    status = r.status_code
                    if status >= 300:
                        return False, {"status": status, "number": n, "step": f"{method} {path}"}
                return True, {"status": status, "number": n}
        except Exception as exc:  # noqa: BLE001 - a channel never raises
            return failure(exc)

    async def open_alert_issues(self, label: str = "alert", pages: int = 5) -> list[dict[str, Any]]:
        """Open issues carrying ``label`` (pull requests excluded). Raises on HTTP errors:
        reconcile must not mistake 'GitHub unreachable' for 'no open issues'."""
        out: list[dict[str, Any]] = []
        async with client(self.transport) as http:
            for page in range(1, pages + 1):
                r = await self._call(http, "GET", "/issues", params={
                    "state": "open", "labels": label, "per_page": 100, "page": page})
                r.raise_for_status()
                items = r.json()
                out += [{"number": i["number"], "title": i.get("title", ""),
                         "body": i.get("body") or "", "created_at": i.get("created_at"),
                         "labels": [lb["name"] for lb in i.get("labels", [])]}
                        for i in items if "pull_request" not in i]
                if len(items) < 100:
                    break
        return out
