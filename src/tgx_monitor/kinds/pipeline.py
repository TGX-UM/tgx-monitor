"""Host, pipeline, image, exposure and self checks: ``host gha registry security self``.

These kinds watch what sits around the services rather than the services themselves:
the nodes they run on, the GitHub Actions that feed them, the registries a reschedule
pulls from, admin pages that must stay shut, and the monitor's own health. Each one
reads a source that can be absent or rate-limited, so "could not tell" (``unknown``)
is kept apart from "is broken" (``error``/a failed assertion) throughout.

host (via agent:tgx1 | agent:tgx2)
    request ``{signal: mdstat|disk|memory|load|boot|peer|root_status|hidrive|agent}``.
    Reads ``ctx.agents.signals()`` (:class:`tgx_monitor.agent.AgentClient`). An agent that
    does not answer gives ``unknown`` for every signal except ``agent``, whose job is to
    say so (``reachable: false``).

gha
    request ``{repo, workflow?, branch?, event?}``. With ``workflow`` (file name or id):
    the workflow's ``state`` and its latest runs. Without: every workflow's state in the
    repo, to catch ``disabled_inactivity``. Token from secret ``tgxmon_gh_token``,
    anonymous without one; ETags make repeat polls free (304s do not count).

registry
    request ``{image}``. Manifest ``HEAD`` through the registry's bearer-token flow,
    anonymous first, then the ``tgxmon_ghcr_read_pat`` classic PAT for private GHCR
    packages (GHCR rejects GitHub App tokens, so none is tried). With ``ctx.docker``,
    also which nodes hold the image locally: the failure that matters is a reschedule
    onto a node that has neither the image nor working credentials. ``missing_on_nodes``
    is only meaningful for images that should run anywhere (not node-pinned ones).

security
    request ``{url, method: GET|HEAD, expect_status: [...], absent_markers: [...]}``.
    Only GET or HEAD is ever sent. ``{node_ip}`` in the url is replaced by the ``via``
    node's IP. A closed port is the good outcome, not an error. Bodies are never kept
    as evidence (they may be the very admin page that is exposed).

self (via core)
    request ``{signal: tick|outbox|vantage|selftest|token}``.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import re
import time
from typing import Any
from urllib.parse import urlencode

from ..catalogue import Check
from ..http import NODES, Fetched
from ..model import Call, Observation
from ..redact import redact_text
from .base import Context, Kind, github_read_token, register

GITHUB_API = "https://api.github.com"
GH_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
AGENT_STALE_S = 180.0
NO_EXPIRY_DAYS = 36500  # fine-grained tokens can be set to never expire


def _age_h(ts: str | None, now: dt.datetime) -> float | None:
    if not ts:
        return None
    try:
        d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return round((now - d).total_seconds() / 3600, 3)


def _evidence(values: dict[str, Any]) -> str:
    return redact_text(json.dumps(values, default=str)[:4000])


def probe_id(check: Check, via: str) -> str:
    """The scheduler's probe id for (check, via): same rule as ``Check.probe_ids``."""
    return check.id if len(check.via) == 1 else f"{check.id}@{via}"


# ====================================================================== host
SIGNALS = ("mdstat", "disk", "memory", "load", "boot", "peer", "root_status", "hidrive",
           "agent")


@register
class HostKind(Kind):
    name = "host"
    required = ("signal",)
    vias = ("agent:tgx1", "agent:tgx2")

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        if request.get("signal") not in SIGNALS:
            probs.append(f"host signal must be one of {', '.join(SIGNALS)}")
        return probs

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        node = via.split(":", 1)[-1]
        signal = check.request["signal"]
        call = Call("GET", f"agent:{node}/signals", via="agent")
        if ctx.agents is None:
            return Observation(unknown="no agent client in this process", calls=[call])
        t0 = time.perf_counter()
        snap = (await ctx.agents.signals()).get(node) or {"error": f"no entry for {node}"}
        call.ms = round((time.perf_counter() - t0) * 1000, 1)
        now = ctx.now()
        if "error" in snap and "collected_at" not in snap:
            call.note = str(snap["error"])[:300]
            if signal == "agent":
                return Observation(values={"reachable": False, "error": snap["error"]},
                                   calls=[call], evidence=call.note)
            return Observation(unknown=f"agent on {node} did not answer: {snap['error']}",
                               calls=[call])
        call.ok, call.status = True, 200
        age = _age_h(snap.get("collected_at"), now)
        age_s = None if age is None else round(age * 3600, 1)
        if signal == "agent":
            return self._agent(snap, age_s, call)
        if age_s is None or age_s > AGENT_STALE_S:
            return Observation(unknown=f"agent on {node} has no fresh data ({age_s}s old)",
                               calls=[call])
        err = (snap.get("errors") or {}).get(signal)
        if err and signal not in snap:
            return Observation(unknown=f"agent on {node} could not read {signal}: {err}",
                               calls=[call])
        data = snap.get(signal)
        if data is None:
            return Observation(unknown=f"agent on {node} has no {signal} yet", calls=[call])
        values, metrics = self._values(signal, data, now, check, via, ctx)
        if err:
            values["agent_error"] = err
        return Observation(values=values, calls=[call], metrics=metrics,
                           evidence=_evidence(values))

    @staticmethod
    def _agent(snap: dict[str, Any], age_s: float | None, call: Call) -> Observation:
        hbs = snap.get("heartbeats") or {}
        values = {"reachable": True, "snapshot_age_s": age_s, "errors": snap.get("errors", {}),
                  "error_count": len(snap.get("errors") or {}), "hc": snap.get("hc", {}),
                  "heartbeats": {k: v.get("age_s") for k, v in hbs.items()}}
        return Observation(values=values, calls=[call], evidence=_evidence(values))

    @staticmethod
    def _values(signal: str, data: Any, now: dt.datetime, check: Check, via: str,
                ctx: Context) -> tuple[dict[str, Any], dict[str, float]]:
        ts = now.timestamp()
        if signal == "mdstat":
            return dict(data), {}
        if signal in ("disk", "load", "peer"):
            return {signal: data}, {}
        if signal == "memory":
            return {"mem": data}, {}
        if signal == "hidrive":
            dirs = {}
            for name, d in data.items():
                d = dict(d)
                if "entries" in d:
                    d["entries"] = d["entries"][:50]  # newest first; evidence stays small
                if d.get("newest_mtime"):
                    d["newest_age_h"] = round((ts - d["newest_mtime"]) / 3600, 3)
                dirs[name] = d
            return {"hidrive": dirs}, {}
        if signal == "boot":
            boot = dict(data)
            bt = boot.get("btime")
            prev: list[float] = []
            if ctx.store is not None and bt is not None:
                prev = ctx.store.baseline(probe_id(check, via), "boot.btime", 30 * 86400,
                                          before=now)
            boot["previous_btime"] = int(prev[-1]) if prev else None
            # A 1-2 s wobble in btime is kernel rounding, not a reboot.
            boot["changed"] = bool(prev) and bt is not None and abs(bt - prev[-1]) > 5
            if bt is not None:
                boot["uptime_h"] = round((ts - bt) / 3600, 2)
            return {"boot": boot}, ({"boot.btime": float(bt)} if bt is not None else {})
        # root_status: the content of Egon's cron file, plus how old it is.
        values: dict[str, Any] = {"present": bool(data.get("present"))}
        if data.get("mtime"):
            values["age_s"] = round(ts - data["mtime"], 1)
            values["age_h"] = round((ts - data["mtime"]) / 3600, 3)
        if data.get("error"):
            values["error"] = data["error"]
        content = data.get("content")
        if isinstance(content, dict):
            values.update({k: v for k, v in content.items() if k not in values})
        return values, {}


# ====================================================================== gha
_ETAGS: dict[str, tuple[str, str]] = {}  # url|auth -> (etag, body); bounded below
_ETAG_CAP = 1000


async def gh_get(ctx: Context, path: str, params: dict[str, Any] | None = None,
                 timeout: float = 30.0) -> tuple[Fetched, Any, str]:
    """GET the GitHub REST API with the read token (or anonymously) and an ETag cache.

    Returns (fetch, parsed json or None, auth used). A 304 reuses the cached body.
    """
    url = f"{GITHUB_API}{path}" + (f"?{urlencode(params)}" if params else "")
    token, label = await github_read_token(ctx)
    f: Fetched | None = None
    auth = "anonymous"
    for tok in ([token, None] if token else [None]):
        auth = label if tok else "anonymous"
        key = f"{url}|{auth}"
        headers = dict(GH_HEADERS)
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        if key in _ETAGS:
            headers["If-None-Match"] = _ETAGS[key][0]
        f = await ctx.http.fetch("GET", url, headers=headers, timeout=timeout)
        if f.status == 401 and tok:
            f.call.note = "token rejected (401); retrying anonymously"
            continue
        break
    assert f is not None
    body = f.text
    if f.status == 304 and key in _ETAGS:
        body = _ETAGS[key][1]
        f.call.note = "304 not modified (ETag)"
        f.call.ok = True
    elif f.status == 200 and f.headers.get("etag"):
        if len(_ETAGS) >= _ETAG_CAP:
            _ETAGS.pop(next(iter(_ETAGS)))
        _ETAGS[key] = (f.headers["etag"], f.text)
    doc = None
    if f.status in (200, 304) and body:
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
    return f, doc, auth


def gh_problem(f: Fetched, what: str) -> tuple[str | None, str | None]:
    """(error, unknown) for a GitHub answer that is not a usable 200/304."""
    if f.error:
        return f.error, None
    if f.status in (200, 304):
        return None, None
    if f.status == 429 or (f.status == 403 and (
            f.headers.get("x-ratelimit-remaining") == "0" or "rate limit" in f.text.lower())):
        return None, f"GitHub rate limit while reading {what}"
    if f.status in (401, 403):
        return None, f"GitHub refused {what} (HTTP {f.status}); token missing or lacks access"
    if f.status == 404:
        return f"{what} not found (HTTP 404): renamed, deleted, or private", None
    if f.status is not None and f.status >= 500:
        return None, f"GitHub answered {f.status} for {what}"
    return f"unexpected HTTP {f.status} for {what}", None


@register
class GhaKind(Kind):
    name = "gha"
    required = ("repo",)
    vias = ("public", "core")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        repo = r["repo"]
        now = ctx.now()
        if not r.get("workflow"):
            return await self._repo_states(ctx, repo, check.timeout_s)
        wf = r["workflow"]
        f1, wfdoc, auth = await gh_get(ctx, f"/repos/{repo}/actions/workflows/{wf}",
                                       timeout=check.timeout_s)
        err, unk = gh_problem(f1, f"workflow {repo}/{wf}")
        if err or unk:
            return Observation(calls=[f1.call], error=err, unknown=unk,
                               evidence=redact_text(f1.text[:1000]))
        params: dict[str, Any] = {"per_page": 5}
        for k in ("branch", "event"):
            if r.get(k):
                params[k] = r[k]
        f2, runs, _ = await gh_get(ctx, f"/repos/{repo}/actions/workflows/{wf}/runs",
                                   params, timeout=check.timeout_s)
        err, unk = gh_problem(f2, f"runs of {repo}/{wf}")
        if err or unk:
            return Observation(calls=[f1.call, f2.call], error=err, unknown=unk,
                               evidence=redact_text(f2.text[:1000]))
        values = self._values(wfdoc or {}, runs or {}, now)
        values["auth"] = auth
        return Observation(values=values, calls=[f1.call, f2.call], evidence=_evidence(values))

    @staticmethod
    def _values(wf: dict[str, Any], runs: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
        rs = runs.get("workflow_runs") or []
        r0 = rs[0] if rs else {}
        done = next((x for x in rs if x.get("status") == "completed"), {})
        good = next((x for x in rs if x.get("conclusion") == "success"), {})
        return {
            "state": wf.get("state"), "workflow_name": wf.get("name"),
            "workflow_id": wf.get("id"), "workflow_path": wf.get("path"),
            "run_count": runs.get("total_count", len(rs)),
            "last_status": r0.get("status"), "last_conclusion": r0.get("conclusion"),
            "last_run_at": r0.get("created_at"),
            "last_run_age_h": _age_h(r0.get("created_at"), now),
            "last_event": r0.get("event"), "last_branch": r0.get("head_branch"),
            "last_head_sha": (r0.get("head_sha") or "")[:12] or None,
            "html_url": r0.get("html_url") or wf.get("html_url"),
            "completed_conclusion": done.get("conclusion"),
            "completed_at": done.get("updated_at"),
            "completed_age_h": _age_h(done.get("updated_at"), now),
            "last_success_at": good.get("created_at"),
            "last_success_age_h": _age_h(good.get("created_at"), now),
        }

    @staticmethod
    async def _repo_states(ctx: Context, repo: str, timeout: float) -> Observation:
        f, doc, auth = await gh_get(ctx, f"/repos/{repo}/actions/workflows", {"per_page": 100},
                                    timeout=timeout)
        err, unk = gh_problem(f, f"workflows of {repo}")
        if err or unk:
            return Observation(calls=[f.call], error=err, unknown=unk)
        wfs = (doc or {}).get("workflows") or []
        states = {w.get("path", "").rsplit("/", 1)[-1] or w.get("name"): w.get("state")
                  for w in wfs}
        values = {
            "states": states, "count": len(states), "auth": auth,
            "inactive": sorted(k for k, v in states.items() if v == "disabled_inactivity"),
            "disabled": sorted(k for k, v in states.items()
                               if v and v != "active"),
        }
        return Observation(values=values, calls=[f.call], evidence=_evidence(values))


# ====================================================================== registry
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


def parse_image(ref: str) -> tuple[str, str, str]:
    """``ghcr.io/x/y:tag`` -> (registry, repository, tag-or-digest), Docker's rules."""
    name, at, digest = ref.partition("@")
    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", name
    tag = "latest"
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path, tag = path.rsplit(":", 1)
    if registry == "docker.io" and "/" not in path:
        path = f"library/{path}"
    return registry, path, (digest if at else tag)


def local_names(registry: str, repo: str, tag: str) -> set[str]:
    """How ``docker images`` spells this reference in RepoTags."""
    names = {f"{registry}/{repo}:{tag}"}
    if registry == "docker.io":
        names |= {f"{repo}:{tag}", f"{repo.removeprefix('library/')}:{tag}"}
    return names


def _api_host(registry: str) -> str:
    return "registry-1.docker.io" if registry == "docker.io" else registry


@register
class RegistryKind(Kind):
    name = "registry"
    required = ("image",)
    vias = ("public", "core")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        registry, repo, ref = parse_image(check.request["image"])
        url = f"https://{_api_host(registry)}/v2/{repo}/manifests/{ref}"
        calls: list[Call] = []
        first = f = await self._head(ctx, url, None, check.timeout_s, calls)
        auth = "none"
        if f.status == 401:
            f, _ = await self._with_token(ctx, url, first, repo, None, check.timeout_s, calls)
            auth = "anonymous"
        if f.status in (401, 403, 404) and registry == "ghcr.io":
            pat = ctx.secrets("tgxmon_ghcr_read_pat")
            if not pat:
                if f.status != 404:
                    return Observation(calls=calls, unknown=(
                        "GHCR denied anonymous access (private package?) and secret "
                        "tgxmon_ghcr_read_pat is not available"))
            else:
                basic = base64.b64encode(f"tgx-monitor:{pat}".encode()).decode()
                f, ok = await self._with_token(ctx, url, first, repo, basic, check.timeout_s,
                                               calls)
                auth = "pat"
                if not ok:
                    return Observation(calls=calls, unknown=(
                        "GHCR rejected tgxmon_ghcr_read_pat (expired or lacks read:packages)"))
        if f.error or f.rate_limited:
            return Observation(calls=calls, error=None if f.rate_limited else f.error,
                               unknown="registry rate limit (429)" if f.rate_limited else None)
        values: dict[str, Any] = {
            "registry": registry, "repository": repo, "reference": ref, "auth": auth,
            "status": f.status, "reachable": f.status == 200,
            "digest": f.headers.get("docker-content-digest"),
            "media_type": f.headers.get("content-type"),
        }
        values.update(await self._nodes(ctx, registry, repo, ref, values["digest"],
                                         calls))
        return Observation(values=values, calls=calls, evidence=_evidence(values))

    @staticmethod
    async def _head(ctx: Context, url: str, token: str | None, timeout: float,
                    calls: list[Call]) -> Fetched:
        h = {"Accept": MANIFEST_ACCEPT}
        if token:
            h["Authorization"] = f"Bearer {token}"
        f = await ctx.http.fetch("HEAD", url, headers=h, follow=False, timeout=timeout)
        calls.append(f.call)
        return f

    async def _with_token(self, ctx: Context, url: str, f: Fetched, repo: str,
                          basic: str | None, timeout: float,
                          calls: list[Call]) -> tuple[Fetched, bool]:
        """Follow the WWW-Authenticate challenge; (new fetch, whether a token was issued)."""
        ch = dict(_CHALLENGE.findall(f.headers.get("www-authenticate", "")))
        if "realm" not in ch:
            return f, False
        params = {"service": ch.get("service", ""),
                  "scope": ch.get("scope") or f"repository:{repo}:pull"}
        headers = {"Authorization": f"Basic {basic}"} if basic else {}
        t = await ctx.http.fetch("GET", ch["realm"], params=params, headers=headers,
                                 timeout=timeout)
        calls.append(t.call)
        try:
            doc = json.loads(t.text) if t.status == 200 else {}
        except ValueError:
            doc = {}
        token = doc.get("token") or doc.get("access_token")
        if not token:
            return f, False
        return await self._head(ctx, url, token, timeout, calls), True

    @staticmethod
    async def _nodes(ctx: Context, registry: str, repo: str, ref: str, digest: str | None,
                     calls: list[Call]) -> dict[str, Any]:
        """Which nodes hold the image locally, through ``DockerAPI.images(node)``."""
        if ctx.docker is None or ref.startswith("sha256:"):
            return {}
        want = local_names(registry, repo, ref)
        present, missing, unknown, match = [], [], [], {}
        for node in sorted(NODES):
            try:
                images = await ctx.docker.images(node, calls)
            except Exception:  # noqa: BLE001 - DockerError, or that node's proxy is gone
                unknown.append(node)
                continue
            hits = [i for i in images if want & set(i.get("RepoTags") or [])]
            (present if hits else missing).append(node)
            if hits and digest:
                match[node] = any(d.endswith(digest) for i in hits
                                  for d in i.get("RepoDigests") or [])
        return {"present_on_nodes": present, "missing_on_nodes": missing,
                "nodes_unknown": unknown, "node_digest_match": match}


# ====================================================================== security
@register
class SecurityKind(Kind):
    name = "security"
    required = ("url",)
    vias = ("public", "tgx1", "tgx2")

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        if str(request.get("method", "GET")).upper() not in ("GET", "HEAD"):
            probs.append("security checks only ever send GET or HEAD")
        if "{node_ip}" in str(request.get("url", "")) and "public" in via:
            probs.append("{node_ip} in url needs via tgx1/tgx2, not public")
        if not request.get("expect_status") and not request.get("absent_markers"):
            probs.append("security needs expect_status or absent_markers")
        return probs

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        method = str(r.get("method", "GET")).upper()
        if method not in ("GET", "HEAD"):
            return Observation(unknown=f"refusing method {method}: security checks only read")
        url = r["url"]
        net_via = via
        if "{node_ip}" in url:
            url, net_via = url.replace("{node_ip}", NODES.get(via, "")), "public"
        f = await ctx.http.fetch(method, url, via=net_via, headers=r.get("headers"),
                                 follow=bool(r.get("follow", False)),
                                 verify=r.get("verify", True), timeout=check.timeout_s)
        if f.rate_limited:
            return Observation(calls=[f.call], unknown="rate limited (HTTP 429)")
        expect = [int(s) for s in r.get("expect_status") or []]
        if f.error:
            # Nothing answered: nothing is exposed. A closed admin port is the goal.
            values = {"reachable": False, "status": None, "markers_found": [],
                      "exposed": False, "error": f.error}
            return Observation(values=values, calls=[f.call], evidence=f.error)
        body = f.text.lower()
        found = [m for m in r.get("absent_markers") or [] if str(m).lower() in body]
        exposed = bool(found) or (bool(expect) and f.status not in expect)
        values = {"reachable": True, "status": f.status, "expected_status": expect,
                  "markers_found": found, "exposed": exposed,
                  "server": f.headers.get("server"), "final_url": f.final_url}
        ev = f"HTTP {f.status} from {method} {r['url']}; markers found: {found or 'none'}"
        return Observation(values=values, calls=[f.call], evidence=ev)


# ====================================================================== self
SELF_SIGNALS = ("tick", "outbox", "vantage", "selftest", "token")
_EXPIRY_FORMATS = ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M %Z",
                   "%Y-%m-%d")


def parse_expiry(text: str) -> dt.datetime | None:
    """Parse ``github-authentication-token-expiration`` (``2026-12-01 10:00:00 UTC``)."""
    for fmt in _EXPIRY_FORMATS:
        try:
            d = dt.datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
        return d if d.tzinfo else d.replace(tzinfo=dt.UTC)
    return None


@register
class SelfKind(Kind):
    name = "self"
    required = ("signal",)
    vias = ("core",)

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        if request.get("signal") not in SELF_SIGNALS:
            probs.append(f"self signal must be one of {', '.join(SELF_SIGNALS)}")
        return probs

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        sig = check.request["signal"]
        if sig == "vantage":
            return await self._vantage(ctx, check.timeout_s)
        if sig == "token":
            return await self._token(ctx, check.request.get("secret", "tgxmon_gh_token"),
                                     check.timeout_s)
        if ctx.store is None:
            return Observation(unknown="no store in this process")
        call = Call("SELECT", f"store:{sig}", via="file", ok=True)
        now = ctx.now()
        if sig == "tick":
            last = await asyncio.to_thread(ctx.store.get_meta, "last_tick")
            if not last:
                return Observation(unknown="store meta has no last_tick yet", calls=[call])
            age = _age_h(last, now)
            values = {"last_tick": last, "tick_age_s": None if age is None else
                      round(age * 3600, 1)}
        elif sig == "outbox":
            row = await asyncio.to_thread(
                ctx.store.one, "SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM outbox "
                "WHERE sent_at IS NULL AND dead=0 AND dry_run=0")
            dead = await asyncio.to_thread(
                ctx.store.one, "SELECT COUNT(*) AS n FROM outbox WHERE dead=1")
            age = _age_h((row or {}).get("oldest"), now)
            values = {"pending": (row or {}).get("n", 0),
                      "oldest_pending_age_min": round(age * 60, 1) if age is not None else 0.0,
                      "dead_letters": (dead or {}).get("n", 0)}
        else:  # selftest
            flag = await asyncio.to_thread(ctx.store.get_meta, "selftest_broken")
            values = {"broken": flag == "1"}
        return Observation(values=values, calls=[call])

    @staticmethod
    async def _vantage(ctx: Context, timeout: float) -> Observation:
        """Is the monitor's own network fine? A blind monitor must not page about targets."""
        from ..agent import tcp_probe

        dns = await tcp_probe("1.1.1.1", 53, timeout=min(5.0, timeout))
        dcall = Call("CONNECT", "tcp://1.1.1.1:53", ok=dns["ok"], ms=dns["ms"],
                     note=dns.get("error", ""))
        token, _ = await github_read_token(ctx)
        headers = {"Authorization": f"Bearer {token}"} if token else None
        f = await ctx.http.fetch("GET", f"{GITHUB_API}/zen", headers=headers, timeout=timeout)
        # Any HTTP answer (even 403/429) proves the path out works.
        values = {"dns_tcp_ok": dns["ok"], "github_ok": f.error is None,
                  "github_status": f.status, "vantage_ok": dns["ok"] and f.error is None}
        return Observation(values=values, calls=[dcall, f.call])

    @staticmethod
    async def _token(ctx: Context, secret: str, timeout: float) -> Observation:
        if secret == "app":
            token = await ctx.gh_app_token() if ctx.gh_app_token is not None else None
            if not token:
                return Observation(unknown="the GitHub App is not configured or its key "
                                           "was refused")
        else:
            token = ctx.secrets(secret)
            if not token:
                return Observation(unknown=f"secret {secret} is not available")
        f = await ctx.http.fetch("GET", f"{GITHUB_API}/rate_limit", timeout=timeout, headers={
            **GH_HEADERS, "Authorization": f"Bearer {token}"})
        if f.error:
            return Observation(calls=[f.call], error=f.error)
        if f.status == 401:
            values = {"valid": False, "status": 401, "days_left": 0}
            return Observation(values=values, calls=[f.call], evidence="token rejected (401)")
        if f.status != 200:
            return Observation(calls=[f.call], unknown=f"GitHub answered {f.status}")
        raw = f.headers.get("github-authentication-token-expiration")
        exp = parse_expiry(raw) if raw else None
        days = round((exp - ctx.now()).total_seconds() / 86400, 1) if exp else None
        values = {
            "valid": True, "secret": secret, "expires_at": exp.isoformat() if exp else None,
            "no_expiry": raw is None, "days_left": NO_EXPIRY_DAYS if raw is None else days,
            "rate_remaining": int(f.headers.get("x-ratelimit-remaining", "0") or 0),
        }
        if raw and exp is None:
            values["expiry_unparsed"] = raw
        return Observation(values=values, calls=[f.call])
