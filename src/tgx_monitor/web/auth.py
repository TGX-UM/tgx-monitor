"""Who may see and change what in the private UI, and the headers every page carries.

Local accounts rather than OAuth for now: the username is the GitHub handle used in
``owners.yaml``, the argon2 hash lives in the ``tgxmon_users`` Docker secret, and the
role follows from the catalogue (admins from ``owners.admins``, everyone else owns the
targets that list them). That gives a per-person audit trail without another service
on the login path.

Everything fails closed. No session key secret means nobody can log in; an unknown
user is checked against a dummy hash so the answer takes as long as for a real one;
five attempts a minute per address and user and twenty per address, then 429. Each
argon2 check costs 64 MiB, so only a few run at once and an over-long password is not
hashed at all: a burst of logins must not push core past its memory limit. The session
is a signed cookie (itsdangerous, 12 h, Secure, HttpOnly, SameSite=Lax) carrying the
handle, a fingerprint of the user's stored hash (removing a user or changing the
password ends their sessions) and the CSRF token that every POST form must echo.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets as pysecrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..secrets import read_secret, read_secret_json

if TYPE_CHECKING:
    from ..catalogue import Catalogue

SESSION_COOKIE = "tgxmon_session"
SESSION_MAX_AGE = 12 * 3600
MAX_PASSWORD = 1024  # longer is refused unhashed
LOGIN_SLOTS = 2  # concurrent argon2 verifications (64 MiB each)
_PH = PasswordHasher()
_DUMMY_HASH: list[str] = []  # computed on first use, not at import

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")
SECURITY_HEADERS = {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "strict-transport-security": "max-age=31536000",
}


@dataclass(frozen=True)
class Role:
    handle: str
    admin: bool
    targets: frozenset[str]

    def may_change(self, target_id: str) -> bool:
        """Silences and the like: admins anywhere, owners on their own targets."""
        return self.admin or target_id in self.targets


def role_for(handle: str, catalogue: Catalogue) -> Role:
    admins = set(catalogue.owners.admins) if catalogue.owners else set()
    owned = frozenset(t.id for t in catalogue.targets.values() if handle in t.owners)
    return Role(handle, handle in admins, owned)


def verify_password(handle: str, password: str, secrets_dir: Path | None) -> bool:
    users = read_secret_json("tgxmon_users", secrets_dir)
    stored = users.get(handle) if isinstance(users, dict) else None
    if not _DUMMY_HASH:
        _DUMMY_HASH.append(_PH.hash(pysecrets.token_hex(16)))
    try:
        ok = _PH.verify(stored if isinstance(stored, str) else _DUMMY_HASH[0], password)
    except (VerificationError, InvalidHashError):
        return False
    return bool(ok and isinstance(stored, str))


def user_fingerprint(handle: str, secrets_dir: Path | None) -> str | None:
    """Short digest of the user's stored hash; None when the user no longer exists."""
    users = read_secret_json("tgxmon_users", secrets_dir)
    stored = users.get(handle) if isinstance(users, dict) and handle else None
    if not isinstance(stored, str):
        return None
    return hashlib.sha256(stored.encode()).hexdigest()[:16]


def session_current(session: dict[str, Any], secrets_dir: Path | None) -> bool:
    """A logged-in session is valid only while its user and password are unchanged."""
    fp = user_fingerprint(str(session.get("u") or ""), secrets_dir)
    return fp is not None and token_ok(fp, str(session.get("fp") or ""))


class Sessions:
    """Signed, timestamped cookie payloads. Disabled (all loads fail) without a key."""

    def __init__(self, key: str | None) -> None:
        self._s = URLSafeTimedSerializer(key, salt="tgxmon-session") if key else None

    @classmethod
    def from_secret(cls, secrets_dir: Path | None) -> Sessions:
        return cls(read_secret("tgxmon_session_key", secrets_dir))

    @property
    def enabled(self) -> bool:
        return self._s is not None

    def dump(self, data: dict[str, Any]) -> str:
        if self._s is None:
            raise RuntimeError("no session key")
        return str(self._s.dumps(data))

    def load(self, raw: str | None) -> dict[str, Any] | None:
        if not raw or self._s is None:
            return None
        try:
            data = self._s.loads(raw, max_age=SESSION_MAX_AGE)
        except BadSignature:  # includes SignatureExpired
            return None
        return data if isinstance(data, dict) else None


def new_csrf() -> str:
    return pysecrets.token_urlsafe(32)


def csrf_ok(session: dict[str, Any] | None, token: str | None) -> bool:
    expected = (session or {}).get("csrf")
    return bool(expected and token) and hmac.compare_digest(str(expected), str(token))


def token_ok(expected: str | None, given: str | None) -> bool:
    """Constant-time compare that is also false when either side is missing."""
    a = (expected or "").encode()
    b = (given or "").encode()
    return bool(expected) and bool(given) and hmac.compare_digest(a, b)


class RateLimiter:
    """Sliding window: at most ``limit`` hits per ``per`` seconds per key."""

    def __init__(self, limit: int = 5, per: float = 60.0) -> None:
        self.limit, self.per = limit, per
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > self.per:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 10000:  # bound memory under a spray of keys
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.per]:
                    self._hits.pop(k, None)
            return True


def client_ip(scope: Scope) -> str:
    """The address Traefik saw: the last X-Forwarded-For hop, else the socket peer."""
    for k, v in scope.get("headers", []):
        if k == b"x-forwarded-for":
            return v.decode("latin-1").split(",")[-1].strip()[:64]
    client = scope.get("client")
    return client[0] if client else "?"


class SecurityHeaders:
    """Pure ASGI middleware: the same strict headers on every response, errors included."""

    def __init__(self, app: ASGIApp, *, cache: str = "no-store",
                 static_prefix: str = "/static/") -> None:
        self.app, self.cache, self.static_prefix = app, cache, static_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        static = scope.get("path", "").startswith(self.static_prefix)

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for k, v in SECURITY_HEADERS.items():
                    headers[k] = v
                if "cache-control" not in headers:
                    headers["cache-control"] = "public, max-age=3600" if static else self.cache
            await send(message)

        await self.app(scope, receive, _send)
