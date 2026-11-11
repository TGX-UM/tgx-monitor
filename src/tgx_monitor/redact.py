"""Redaction at ingest.

Everything that reaches the database, the UI, an issue or a Slack message passes
through here first. Two jobs:

* Remove secrets. Docker's ``/services`` and ``/tasks`` list responses carry
  ``ContainerSpec.Env`` in plain text (passwords included), so specs are stripped of
  Env/Args/Secrets/Configs before anything else sees them, and secret-looking strings
  in free text are masked.
* Make untrusted response bodies safe to display: strip ANSI escapes and control
  characters, cap the length. HTML escaping is the template engine's job (autoescape).
"""

from __future__ import annotations

import re
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Whole-match secrets: replaced entirely.
_SECRETS = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    re.compile(r"https://hc-ping\.com/[A-Za-z0-9/-]+"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*"),  # JWT
]
# key=value secrets: the key is kept so the reader knows what was there.
# Any name ending in one of these words (DBA_PASSWORD=, PGPASSWORD=, "access_token":) but
# not "tokens:"; the key may be quoted (JSON) and so may the value.
_KV_SECRET = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key|apikey)[\"']?\s*[=:]\s*)"
    r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s&\"',;]+)")
# "Authorization: <scheme> <credential>", "Bearer <token>", and Cookie / Set-Cookie values.
_AUTH_HEADER = re.compile(
    r"(?i)(\bauthorization[\"']?\s*[=:]\s*[\"']?(?:[A-Za-z]+\s+)?|\bbearer\s+)"
    r"[A-Za-z0-9._~+/=-]{6,}")
_COOKIE = re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*)\S.*$")
# user:password@ in a URL (postgres://u:pw@db, https://u:pw@host).
_USERINFO = re.compile(r"(://[^/\s:@]+:)[^/\s@]+@")
_SPEC_DROP = {"Env", "Args", "Secrets", "Configs", "Command", "DNSConfig", "Healthcheck"}
# Dropped only inside a container spec; a node's Description.Hostname is what maps a
# node to tgx1/tgx2 and is not sensitive.
_CONTAINER_DROP = {"Hostname"}
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_SECRET_LABEL = re.compile(r"(?i)(pass|secret|token|key|auth|credential)")


def _kv_sub(m: re.Match[str]) -> str:
    q = m.group(2)[0] if m.group(2)[:1] in ("'", '"') else ""
    return f"{m.group(1)}{q}[redacted]{q}"


def redact_text(text: str, cap: int = 65536) -> str:
    if not text:
        return ""
    t = _ANSI.sub("", text)
    t = _CTRL.sub("", t)
    t = _AUTH_HEADER.sub(r"\1[redacted]", t)
    for rx in _SECRETS:
        t = rx.sub("[redacted]", t)
    t = _KV_SECRET.sub(_kv_sub, t)
    t = _COOKIE.sub(r"\1[redacted]", t)
    t = _USERINFO.sub(r"\1[redacted]@", t)
    return t if len(t) <= cap else t[:cap] + "\n[… truncated]"


def redact_spec(obj: Any, _in_container: bool = False) -> Any:
    """Recursively drop sensitive fields from Docker API objects.

    Label values are masked when the key looks secret, and e-mail addresses are masked
    in every label value: ~40 live services carry ``tgx.service.owner=<e-mail>``.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _SPEC_DROP or (_in_container and k in _CONTAINER_DROP):
                continue
            if k == "Labels" and isinstance(v, dict):
                out[k] = {lk: ("[redacted]" if _SECRET_LABEL.search(lk)
                               else _EMAIL.sub("[e-mail]", lv) if isinstance(lv, str) else lv)
                          for lk, lv in v.items()}
                continue
            out[k] = redact_spec(v, _in_container or k == "ContainerSpec")
        return out
    if isinstance(obj, list):
        return [redact_spec(x, _in_container) for x in obj]
    return obj
