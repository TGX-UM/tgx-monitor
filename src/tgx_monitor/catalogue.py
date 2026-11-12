"""The check catalogue: targets, checks, owners, dependencies, maintenance windows.

Everything a person edits lives in ``catalogue/`` as YAML, one file per target, and is
public. Hence the rules ``validate()`` enforces beyond the schema: no e-mail addresses,
no host paths and no IP addresses except the two node aliases may appear in any field
that is published. Contacts live in a Docker secret, keyed by the handles used here.

Shape of a target file::

    id: aopwiki-sparql
    name: AOP-Wiki RDF SPARQL endpoint
    group: AOP-Wiki RDF
    class: data            # service | data | cron | backup | infra | security | pipeline
    criticality: high      # high | medium | low | muted
    owners: [marvinm2]
    depends_on: [edge-tgx1]
    maintenance: [aopwiki-reload]
    public: true
    public_summary: The AOP-Wiki as queryable RDF, reloaded weekly.
    links: [https://aopwiki.rdf.bigcat-bioinformatics.org/sparql]
    checks:
      - id: aopwiki-sparql-ask
        kind: sparql
        every: 5m
        via: [public, tgx1, tgx2]
        describe: The endpoint answers a trivial query in under five seconds.
        purpose: Shows that people and tools can query AOP-Wiki RDF at all.
        request: {endpoint: https://aopwiki.rdf.bigcat-bioinformatics.org/sparql,
                  ask: "ASK { ?s ?p ?o }"}
        assert:
          - {that: boolean, eq: true}
          - {that: latency_ms, lt: 5000}
"""

from __future__ import annotations

import hashlib
import re
from functools import cached_property
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from . import assertions as A

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTPATH_RE = re.compile(r"/mnt/|/home/|/var/run/|/run/secrets")
# Credential shapes (the same ones redact.py removes): a public file must never hold one.
CREDENTIAL_RE = re.compile(
    r"\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|hooks\.slack\.com/services/"
    r"|hc-ping\.com/[A-Za-z0-9]|\bxox[abposr]-[A-Za-z0-9-]{10,}|PRIVATE KEY-----"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.")
ALLOWED_IPS = {"81.169.246.233", "85.214.252.63", "1.1.1.1", "9.9.9.9", "8.8.8.8",
               "127.0.0.1"}

TargetClass = Literal["service", "data", "cron", "backup", "infra", "security", "pipeline"]
Criticality = Literal["high", "medium", "low", "muted"]
Via = Literal["public", "tgx1", "tgx2", "core", "agent:tgx1", "agent:tgx2"]


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    kind: str
    every: str = "15m"
    via: list[Via] = Field(default_factory=lambda: ["public"])
    describe: str = ""
    # One plain sentence for a non-specialist: why the check exists, i.e. what users would
    # notice or lose if it failed. Shown as "Purpose: ..." on the pages and in alerts.
    purpose: str = ""
    request: dict[str, Any] = Field(default_factory=dict)
    assert_: list[dict[str, Any]] = Field(default_factory=list, alias="assert")
    severity: Criticality | None = None
    alert_after: str | None = None  # minimum failing duration before alerting
    retry: str | None = None  # for sparse checks: one retry after this delay
    timeout: str = "30s"
    enabled: bool = True
    public: bool | None = None  # None: inherit from target
    inv_ids: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not ID_RE.match(v):
            raise ValueError(f"check id {v!r} must be kebab-case [a-z0-9-]")
        return v

    @property
    def interval_s(self) -> float:
        return A.parse_duration(self.every)

    def model_post_init(self, _ctx: Any) -> None:
        # Sparse checks (hourly or rarer) retry once after 10 minutes before they count,
        # so a single blip does not wait a whole cadence to clear (plan: alert policy).
        if self.retry is None:
            try:
                if A.parse_duration(self.every) >= 3600:
                    self.retry = "10m"
            except ValueError:
                pass  # validate() reports the bad duration

    @property
    def timeout_s(self) -> float:
        return A.parse_duration(self.timeout)

    def probe_ids(self) -> list[tuple[str, str]]:
        """(probe_id, via): one probe per vantage point."""
        if len(self.via) == 1:
            return [(self.id, self.via[0])]
        return [(f"{self.id}@{v}", v) for v in self.via]


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    name: str
    group: str = "Other"
    class_: TargetClass = Field(alias="class")
    criticality: Criticality = "medium"
    owners: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    maintenance: list[str] = Field(default_factory=list)
    public: bool = True
    public_summary: str = ""
    links: list[str] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)
    notes: str = ""

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not ID_RE.match(v):
            raise ValueError(f"target id {v!r} must be kebab-case [a-z0-9-]")
        return v


class Owners(BaseModel):
    model_config = ConfigDict(extra="forbid")

    admins: list[str]
    fallback: list[str]
    people: dict[str, dict[str, Any]] = Field(default_factory=dict)  # handle -> {name, github?}
    infra_cc: list[str] = Field(default_factory=list)  # cc'd on infra/backup/security


class Window(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    describe: str
    rrule: str  # RFC 5545 subset, UTC: FREQ=WEEKLY;BYDAY=SU / FREQ=MONTHLY;BYMONTHDAY=12
    start: str  # HH:MM UTC
    duration: str  # e.g. 100m


class KnownIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    check: str | None = None  # None: the whole target
    reason: str
    owner: str
    until: str  # ISO date; after it the issue alerts again
    ticket: str | None = None


class Catalogue:
    """Loaded, cross-validated catalogue."""

    def __init__(self, root: Path, private_yaml: str | None = None) -> None:
        """``private_yaml``: extra targets from the ``tgxmon_private_checks`` secret --
        security canaries that name a hole still open. They are forced non-public, so
        they never reach GitHub issues or the public page, and they are never in git."""
        self.root = Path(root)
        self.private_yaml = private_yaml
        self.targets: dict[str, Target] = {}
        self.owners: Owners | None = None
        self.windows: dict[str, Window] = {}
        self.known: list[KnownIssue] = []
        self.problems: list[str] = []
        self._load()

    # ------------------------------------------------------------------ loading
    def _yaml(self, path: Path) -> Any:
        try:
            return yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as exc:
            self.problems.append(f"{path.name}: YAML error: {exc}")
            return {}

    def _load(self) -> None:
        tdir = self.root / "targets"
        for path in sorted(tdir.glob("*.yaml")) if tdir.exists() else []:
            raw = self._yaml(path)
            docs = raw if isinstance(raw, list) else [raw]
            for doc in docs:
                if not doc:
                    continue
                try:
                    t = Target.model_validate(doc)
                except ValidationError as exc:
                    for e in exc.errors():
                        loc = ".".join(str(x) for x in e["loc"])
                        self.problems.append(f"{path.name}: {loc}: {e['msg']}")
                    continue
                if t.id in self.targets:
                    self.problems.append(f"{path.name}: duplicate target id {t.id}")
                self.targets[t.id] = t
        private_known: list[Any] = []
        self.private_ids: set[str] = set()  # targets from the private secret, not from git
        if self.private_yaml:
            try:
                raw = yaml.safe_load(self.private_yaml) or []
            except yaml.YAMLError as exc:
                self.problems.append(f"private checks: YAML error: {exc}")
                raw = []
            # Either a list of targets, or {targets: [...], known_issues: [...]}: known
            # issues that describe infrastructure state (a degraded array, a database
            # with no backup) are operational intelligence and stay out of git too.
            if isinstance(raw, dict):
                private_known = list(raw.get("known_issues") or [])
                raw = raw.get("targets") or []
            for doc in raw if isinstance(raw, list) else [raw]:
                try:
                    t = Target.model_validate({**doc, "public": False})
                except (ValidationError, TypeError) as exc:
                    self.problems.append(f"private checks: {exc}")
                    continue
                for c in t.checks:
                    c.public = False
                if t.id in self.targets:
                    self.problems.append(f"private checks: duplicate target id {t.id}")
                self.targets[t.id] = t
                self.private_ids.add(t.id)
        own = self.root / "owners.yaml"
        if own.exists():
            try:
                self.owners = Owners.model_validate(self._yaml(own))
            except ValidationError as exc:
                self.problems.append(f"owners.yaml: {exc}")
        else:
            self.problems.append("owners.yaml missing")
        mw = self.root / "maintenance.yaml"
        for doc in (self._yaml(mw) or []) if mw.exists() else []:
            try:
                w = Window.model_validate(doc)
                self.windows[w.id] = w
            except ValidationError as exc:
                self.problems.append(f"maintenance.yaml: {exc}")
        # known_issues.yaml plus known_issues/*.yaml (one file per area, so several people
        # can add issues without editing the same file).
        kdir = self.root / "known_issues"
        kfiles = [self.root / "known_issues.yaml", *sorted(kdir.glob("*.yaml"))]
        for ki in kfiles:
            for doc in (self._yaml(ki) or []) if ki.exists() else []:
                try:
                    self.known.append(KnownIssue.model_validate(doc))
                except ValidationError as exc:
                    self.problems.append(f"{ki.name}: {exc}")
        for doc in private_known:
            try:
                self.known.append(KnownIssue.model_validate(doc))
            except ValidationError as exc:
                self.problems.append(f"private known issues: {exc}")

    # ------------------------------------------------------------------ access
    @cached_property
    def checks(self) -> dict[str, tuple[Target, Check]]:
        return {c.id: (t, c) for t in self.targets.values() for c in t.checks}

    def probes(self) -> list[tuple[str, str, Target, Check]]:
        out = []
        for t in self.targets.values():
            for c in t.checks:
                if not c.enabled:
                    continue
                for pid, via in c.probe_ids():
                    out.append((pid, via, t, c))
        return out

    def query_text(self, ref: str) -> str:
        """Load a query file referenced as ``q/<name>.rq`` (relative to catalogue/queries)."""
        name = ref.removeprefix("q/")
        qdir = (self.root / "queries").resolve()
        p = (qdir / name).resolve()
        if qdir not in p.parents:
            raise ValueError(f"query path escapes the catalogue: {ref}")
        return p.read_text()

    @cached_property
    def sha(self) -> str:
        h = hashlib.sha256()
        for p in sorted(self.root.rglob("*")):
            if p.is_file() and "_import" not in p.parts:
                h.update(p.relative_to(self.root).as_posix().encode())
                h.update(p.read_bytes())
        return h.hexdigest()[:12]

    def ancestors(self, target_id: str) -> list[str]:
        seen: list[str] = []
        stack = list(self.targets[target_id].depends_on) if target_id in self.targets else []
        while stack:
            t = stack.pop()
            if t in seen:
                continue
            seen.append(t)
            if t in self.targets:
                stack.extend(self.targets[t].depends_on)
        return seen

    # ------------------------------------------------------------------ validation
    def validate(self, known_kinds: set[str] | None = None) -> list[str]:
        """Every problem, not the first. Empty list means the catalogue is sound."""
        probs = list(self.problems)
        handles = set()
        if self.owners:
            handles = set(self.owners.people) | set(self.owners.admins) | set(self.owners.fallback)
            for h in self.owners.admins + self.owners.fallback + self.owners.infra_cc:
                if h not in self.owners.people:
                    probs.append(f"owners.yaml: {h} is not listed under people")
        seen_checks: dict[str, str] = {}
        for t in self.targets.values():
            for o in t.owners:
                if handles and o not in handles:
                    probs.append(f"{t.id}: owner {o!r} not in owners.yaml")
            for d in t.depends_on:
                if d not in self.targets:
                    probs.append(f"{t.id}: depends_on unknown target {d!r}")
            for w in t.maintenance:
                if w not in self.windows:
                    probs.append(f"{t.id}: unknown maintenance window {w!r}")
            if t.criticality != "muted" and not t.owners:
                probs.append(f"{t.id}: no owners (use fallback explicitly)")
            if t.public and not t.public_summary:
                probs.append(f"{t.id}: public target needs public_summary")
            for u in t.links:
                if not u.startswith(("https://", "http://")):
                    probs.append(f"{t.id}: link {u!r} must be an http(s) URL")
            for c in t.checks:
                if c.id in seen_checks:
                    probs.append(f"{t.id}: check id {c.id} also in {seen_checks[c.id]}")
                seen_checks[c.id] = t.id
                if known_kinds is not None and c.kind not in known_kinds:
                    probs.append(f"{t.id}/{c.id}: unknown kind {c.kind!r}")
                if c.kind == "todo" and c.enabled:
                    probs.append(f"{t.id}/{c.id}: kind 'todo' must be structured or disabled")
                for dur in (c.every, c.timeout, c.alert_after, c.retry):
                    if dur:
                        try:
                            A.parse_duration(dur)
                        except ValueError as exc:
                            probs.append(f"{t.id}/{c.id}: {exc}")
                if c.enabled and not c.assert_:
                    probs.append(f"{t.id}/{c.id}: no assertions")
                # The purpose line is required in the public catalogue; private checks
                # live in a Docker secret and get theirs when the secret is next rotated.
                if c.enabled and t.id not in self.private_ids and not (c.describe and c.purpose):
                    probs.append(f"{t.id}/{c.id}: needs describe (what is checked) and "
                                 "purpose (why, in plain words)")
                for a in c.assert_:
                    for p in A.validate(a):
                        probs.append(f"{t.id}/{c.id}: {p}")
        probs.extend(self._cycles())
        probs.extend(self._leaks())
        return probs

    def _cycles(self) -> list[str]:
        out = []
        for tid in self.targets:
            if tid in self.ancestors(tid):
                out.append(f"{tid}: dependency cycle")
        return out

    def _leaks(self) -> list[str]:
        """Public repo hygiene: no e-mail, host paths, stray IPs or credentials anywhere.

        Every file counts (payloads and fixtures are published too), not only the YAML.
        """
        out = []
        for p in sorted(self.root.rglob("*")):
            if not p.is_file() or "_import" in p.relative_to(self.root).parts:
                continue
            text = p.read_bytes()[:4 << 20].decode("utf-8", errors="replace")
            if CREDENTIAL_RE.search(text):
                out.append(f"{p.relative_to(self.root)}: credential-shaped string")
            for m in EMAIL_RE.finditer(text):
                if not m.group(0).endswith((".rq", ".ttl")):
                    out.append(f"{p.relative_to(self.root)}: e-mail address {m.group(0)!r}")
            for m in IPV4_RE.finditer(text):
                if m.group(0) not in ALLOWED_IPS:
                    out.append(f"{p.relative_to(self.root)}: IP address {m.group(0)}")
            for m in HOSTPATH_RE.finditer(text):
                out.append(f"{p.relative_to(self.root)}: host path {m.group(0)!r}")
        return out


def load(root: Path | str = "catalogue", private_yaml: str | None = None) -> Catalogue:
    return Catalogue(Path(root), private_yaml)
