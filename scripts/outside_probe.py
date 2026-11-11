#!/usr/bin/env python3
"""The outside probe: is the cluster reachable, and is the monitor itself alive?

Runs in GitHub Actions (``.github/workflows/probe.yml``, every 20 minutes), i.e. on
infrastructure that shares nothing with the swarm. It is the alert path for the one
failure the monitor cannot report about itself: the monitor, its node, or the whole
edge being gone. Standard library only, so it needs no install step that could break.

What it checks, through **each node IP separately** (TLS with the real name as SNI,
like ``curl --resolve``), because DNS points at tgx1 only and a dead tgx2 edge would
otherwise stay invisible until the day it is needed:

1. ``https://status.bigcat-bioinformatics.org/status.json`` answers and its ``generated_at``
   is younger than 15 minutes (the public snapshot is rebuilt every 60 s by core);
2. about fifteen sentinel URLs across the estate answer with the expected content;
3. the A records of the monitor and sentinel hostnames are tgx1 (DNS-over-HTTPS to
   1.1.1.1).

Red means a cluster-level problem: the snapshot is stale or unreachable on either node,
the status hostname no longer points at tgx1, or at least ``--threshold`` sentinels (or
hostnames) fail together. One service being down is core's job, not this probe's: it is
listed in the summary but does not open the issue.

On red it keeps exactly one issue open ("Outside probe: cluster unreachable or stale",
label ``outside-probe``), mentions @marvinm2 and @egonw when it opens it, comments at
most hourly while red, and closes it on the first green run. It pings
``HC_PROBE_URL`` (healthchecks.io ``gha-probe``) with ``/fail`` on red, so a probe that
stops running at all is caught too.

    python scripts/outside_probe.py                    # report only
    python scripts/outside_probe.py --manage-issue     # as in Actions (GITHUB_TOKEN)
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import datetime as dt
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

NODES = {"tgx1": "81.169.246.233", "tgx2": "85.214.252.63"}
STATUS_URL = "https://status.bigcat-bioinformatics.org/status.json"
MAX_STATUS_AGE = dt.timedelta(minutes=15)
DOH = "https://cloudflare-dns.com/dns-query"
ISSUE_TITLE = "Outside probe: cluster unreachable or stale"
LABEL = "outside-probe"
MENTIONS = "@marvinm2 @egonw"
COMMENT_EVERY = dt.timedelta(minutes=55)  # runs are 20 min apart: at most hourly
TIMEOUT = 20.0
USER_AGENT = "tgx-monitor-outside-probe/1 (+https://github.com/TGX-UM/tgx-monitor)"
SPARQL_JSON = "application/sparql-results+json"
ASK = "?query=" + urllib.parse.quote("ASK { ?s ?p ?o }")
TRUE = r'"boolean"\s*:\s*true'


@dataclasses.dataclass(frozen=True)
class Sentinel:
    name: str
    url: str
    expect: str | None = None  # regex the body must match
    accept: str | None = None
    status: int = 200


# Hosted on the swarm, behind Traefik, with DNS on tgx1 (verified 2026-11-10/11).
SENTINELS = [
    Sentinel("aopwiki-sparql", "https://aopwiki.rdf.bigcat-bioinformatics.org/sparql" + ASK,
             TRUE, SPARQL_JSON),
    Sentinel("aopwiki-multirdf", "https://aopwiki-multirdf.vhp4safety.nl/sparql" + ASK,
             TRUE, SPARQL_JSON),
    Sentinel("wikipathways-sparql", "https://sparql.wikipathways.org/sparql" + ASK,
             TRUE, SPARQL_JSON),
    Sentinel("nanosafety-sparql", "https://nanosafety.rdf.bigcat-bioinformatics.org/sparql" + ASK,
             TRUE, SPARQL_JSON),
    Sentinel("bridgedb-xrefs", "https://webservice.bridgedb.org/Human/xrefs/L/1234",
             r"^[^\t{\[]+\t\S"),
    Sentinel("vhp-platform", "https://platform.vhp4safety.nl/", r"(?i)<title>[^<]*VHP4Safety"),
    Sentinel("molaop-builder", "https://molaop-builder.vhp4safety.nl/health", r'"healthy"'),
    Sentinel("molaop-analyser", "https://molaop-analyser.vhp4safety.nl/health"),
    Sentinel("aopwiki-dashboard", "https://aopwiki-dashboard.vhp4safety.nl/health",
             r'"healthy"'),
    Sentinel("qaop", "https://qaop.vhp4safety.nl/api/health", r'"healthy"'),
    Sentinel("cplogd", "https://cplogd.cloud.vhp4safety.nl/api/v2/health", "Service running"),
    Sentinel("curation-portal", "https://curation.wikipathways.org/health", r'"ok"'),
    Sentinel("r-odaf", "https://r-odaf.nl/__sockjs__/info", r'"websocket"\s*:\s*true'),
    Sentinel("ingredient-smiles", "https://ingredient-smiles.cloud.vhp4safety.nl/healthz"),
    Sentinel("mct8-docking", "https://mct8-docking.vhp4safety.nl/health"),
]


@dataclasses.dataclass
class Finding:
    check: str
    node: str  # tgx1 | tgx2 | dns
    ok: bool
    detail: str = ""
    ms: float | None = None


def safe(text: str, cap: int = 160) -> str:
    """Server-controlled text (an exception can echo a raw status line) on its way into a
    public issue: no @mentions, no Markdown, one line, short, inside a code span."""
    t = re.sub(r"[\x00-\x1f`|@<>\[\]]", " ", str(text))
    t = " ".join(t.split())[:cap]
    return f"`{t}`" if t else ""


# ---------------------------------------------------------------------- fetching
class _Pinned(http.client.HTTPSConnection):
    """HTTPS to a fixed IP with the real hostname as SNI and Host: curl --resolve."""

    def __init__(self, host: str, ip: str, port: int = 443, timeout: float = TIMEOUT) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch_via(ip: str, url: str, accept: str | None = None,
              timeout: float = TIMEOUT) -> tuple[int | None, str, float, str | None]:
    """GET ``url`` through ``ip``: (status, body excerpt, ms, error). Never raises."""
    parts = urllib.parse.urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    headers = {"User-Agent": USER_AGENT, "Accept": accept or "*/*"}
    t0 = time.perf_counter()
    conn = _Pinned(parts.hostname or "", ip, parts.port or 443, timeout)
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(256 * 1024).decode("utf-8", "replace")
        return resp.status, body, _ms(t0), None
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return None, "", _ms(t0), f"{type(exc).__name__}: {exc}"[:300]
    finally:
        conn.close()


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


def http_json(method: str, url: str, headers: dict[str, str] | None = None,
              body: Any = None, timeout: float = TIMEOUT) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {}),
        **({"Content-Type": "application/json"} if data else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except ValueError:
            return exc.code, None


# ---------------------------------------------------------------------- checks
def check_status(node: str, ip: str, now: dt.datetime) -> Finding:
    status, body, ms, err = fetch_via(ip, STATUS_URL, "application/json")
    name = "status.json fresh"
    if err or status != 200:
        return Finding(name, node, False, err or f"HTTP {status}", ms)
    try:
        doc = json.loads(body)
        gen = dt.datetime.fromisoformat(str(doc["generated_at"]).replace("Z", "+00:00"))
    except (ValueError, KeyError, TypeError):
        return Finding(name, node, False, "no parseable generated_at", ms)
    gen = gen if gen.tzinfo else gen.replace(tzinfo=dt.UTC)
    age = now - gen
    return Finding(name, node, age <= MAX_STATUS_AGE,
                   f"generated {int(age.total_seconds() // 60)} min ago", ms)


def check_sentinel(node: str, ip: str, s: Sentinel) -> Finding:
    status, body, ms, err = fetch_via(ip, s.url, s.accept)
    if err:
        return Finding(s.name, node, False, err, ms)
    if status != s.status:
        return Finding(s.name, node, False, f"HTTP {status}, expected {s.status}", ms)
    if s.expect and not re.search(s.expect, body, re.M):
        return Finding(s.name, node, False, f"HTTP {status} but body lacks /{s.expect}/", ms)
    return Finding(s.name, node, True, f"HTTP {status}", ms)


def resolve_a(name: str) -> tuple[set[str], str | None]:
    url = f"{DOH}?{urllib.parse.urlencode({'name': name, 'type': 'A'})}"
    try:
        status, doc = http_json("GET", url, {"Accept": "application/dns-json"})
    except (OSError, ValueError) as exc:
        return set(), f"{type(exc).__name__}: {exc}"[:200]
    if status != 200 or not isinstance(doc, dict):
        return set(), f"DoH HTTP {status}"
    return {a["data"] for a in doc.get("Answer") or [] if a.get("type") == 1}, None


def check_dns(name: str) -> Finding:
    ips, err = resolve_a(name)
    if err:
        return Finding(f"A {name}", "dns", False, err)
    ok = ips == {NODES["tgx1"]}
    return Finding(f"A {name}", "dns", ok, ", ".join(sorted(ips)) or "no A record")


def dns_names() -> list[str]:
    names = {urllib.parse.urlsplit(STATUS_URL).hostname or ""}
    names |= {urllib.parse.urlsplit(s.url).hostname or "" for s in SENTINELS}
    return sorted(n for n in names if n)


def run_all(now: dt.datetime, workers: int = 8) -> list[Finding]:
    jobs = []
    with cf.ThreadPoolExecutor(workers) as pool:
        for node, ip in NODES.items():
            jobs.append(pool.submit(check_status, node, ip, now))
            jobs += [pool.submit(check_sentinel, node, ip, s) for s in SENTINELS]
        jobs += [pool.submit(check_dns, n) for n in dns_names()]
        return [j.result() for j in jobs]


def verdict(findings: list[Finding], threshold: int) -> tuple[bool, list[str]]:
    """(red, reasons). Red only for cluster-level trouble; see the module docstring."""
    reasons = []
    for f in findings:
        if f.check == "status.json fresh" and not f.ok:
            reasons.append(f"status.json via {f.node}: {safe(f.detail)}")
    status_host = urllib.parse.urlsplit(STATUS_URL).hostname
    for f in findings:
        if f.check == f"A {status_host}" and not f.ok:
            reasons.append(f"{status_host} resolves to {safe(f.detail)}")
    for node in (*NODES, "dns"):
        bad = [f for f in findings
               if f.node == node and not f.ok and f.check != "status.json fresh"]
        if len(bad) >= threshold:
            what = "hostnames off tgx1" if node == "dns" else f"sentinels failing via {node}"
            reasons.append(f"{len(bad)} {what}")
    return bool(reasons), reasons


def summary_markdown(findings: list[Finding], red: bool, reasons: list[str],
                     now: dt.datetime) -> str:
    bad = [f for f in findings if not f.ok]
    head = "**RED**: " + "; ".join(reasons) if red else "**green**"
    lines = [f"### Outside probe {now:%Y-%m-%d %H:%M} UTC: {head}", "",
             f"{len(findings) - len(bad)}/{len(findings)} checks ok "
             f"(both nodes: {', '.join(f'{k} {v}' for k, v in NODES.items())}).", ""]
    if bad:
        lines += ["| check | via | detail |", "|---|---|---|"]
        lines += [f"| {f.check} | {f.node} | {safe(f.detail)} |" for f in bad]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- the issue
def decide(red: bool, issue: dict | None, now: dt.datetime) -> str:
    """open | comment | wait | close | none."""
    if red:
        if issue is None:
            return "open"
        last = dt.datetime.fromisoformat(issue["updated_at"].replace("Z", "+00:00"))
        return "comment" if now - last >= COMMENT_EVERY else "wait"
    return "close" if issue is not None else "none"


class GitHub:
    def __init__(self, repo: str, token: str, api: str = "https://api.github.com") -> None:
        self.repo, self.api = repo, api
        self.headers = {"Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        return http_json(method, f"{self.api}/repos/{self.repo}{path}", self.headers, body)

    def open_issue(self) -> dict | None:
        q = urllib.parse.urlencode({"state": "open", "labels": LABEL, "per_page": 20})
        status, items = self.call("GET", f"/issues?{q}")
        if status != 200:
            raise RuntimeError(f"listing issues failed: HTTP {status}")
        mine = [i for i in items or [] if i.get("title") == ISSUE_TITLE
                and "pull_request" not in i]
        return min(mine, key=lambda i: i["number"]) if mine else None


def manage_issue(gh: GitHub, red: bool, summary: str, now: dt.datetime,
                 run_url: str = "") -> str:
    issue = gh.open_issue()
    action = decide(red, issue, now)
    link = f"\n[workflow run]({run_url})\n" if run_url else ""
    if action == "open":
        gh.call("POST", "/labels", {"name": LABEL, "color": "c2410c",  # 422 if it exists
                                    "description": "Outside probe: cluster-level problem"})
        status, made = gh.call("POST", "/issues", {
            "title": ISSUE_TITLE, "labels": [LABEL],
            "body": f"{MENTIONS}\n\nThe outside probe (GitHub Actions, off the cluster) sees a "
                    f"cluster-level problem. This issue closes itself on the first green run; "
                    f"see RUNBOOK.md, \"Outside probe\".\n\n{summary}{link}"})
        if status != 201:
            raise RuntimeError(f"opening the issue failed: HTTP {status}")
        return f"opened #{made['number']}"
    if action == "comment":
        gh.call("POST", f"/issues/{issue['number']}/comments",
                {"body": f"Still red.\n\n{summary}{link}"})
        return f"commented on #{issue['number']}"
    if action == "close":
        opened = dt.datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
        mins = int((now - opened).total_seconds() // 60)
        gh.call("POST", f"/issues/{issue['number']}/comments",
                {"body": f"Green again at {now:%Y-%m-%d %H:%M} UTC, after {mins // 60} h "
                         f"{mins % 60} min.{link}"})
        gh.call("PATCH", f"/issues/{issue['number']}",
                {"state": "closed", "state_reason": "completed"})
        return f"closed #{issue['number']}"
    if action == "wait":
        return f"#{issue['number']} still open, commented under an hour ago"
    return "no issue needed"


def ping_healthchecks(url: str, red: bool, summary: str) -> str:
    target = url.rstrip("/") + ("/fail" if red else "")
    req = urllib.request.Request(target, data=summary.encode()[:10_000], method="POST",
                                 headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return f"healthchecks ping {'fail' if red else 'ok'}: HTTP {r.status}"
    except (OSError, urllib.error.URLError) as exc:  # the URL itself is never printed
        return f"healthchecks ping failed: {type(exc).__name__}"


# ---------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--manage-issue", action="store_true",
                   help="open, comment on or close the outside-probe issue "
                        "(needs GITHUB_TOKEN and GITHUB_REPOSITORY)")
    p.add_argument("--threshold", type=int, default=3,
                   help="failing sentinels on one node (or hostnames off tgx1) that make it red")
    p.add_argument("--json", help="write all findings here")
    p.add_argument("--strict", action="store_true", help="exit 1 when red")
    args = p.parse_args(argv)

    now = dt.datetime.now(dt.UTC)
    findings = run_all(now)
    red, reasons = verdict(findings, args.threshold)
    summary = summary_markdown(findings, red, reasons, now)
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(summary)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"at": now.isoformat(timespec="seconds"), "red": red, "reasons": reasons,
                       "findings": [dataclasses.asdict(f) for f in findings]}, fh, indent=1)

    rc = 1 if (red and args.strict) else 0
    if args.manage_issue:
        repo, token = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_TOKEN")
        if not (repo and token):
            print("--manage-issue needs GITHUB_REPOSITORY and GITHUB_TOKEN", file=sys.stderr)
            return 2
        run_url = ""
        if os.environ.get("GITHUB_RUN_ID"):
            run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}"
                       f"/actions/runs/{os.environ['GITHUB_RUN_ID']}")
        try:
            print(manage_issue(GitHub(repo, token), red, summary, now, run_url))
        except (RuntimeError, OSError, KeyError) as exc:
            print(f"issue management failed: {exc}", file=sys.stderr)
            rc = 1
    if os.environ.get("HC_PROBE_URL"):
        print(ping_healthchecks(os.environ["HC_PROBE_URL"], red, summary))
    return rc


if __name__ == "__main__":
    sys.exit(main())
