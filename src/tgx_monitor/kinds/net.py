"""Certificates and names: the ``tls`` and ``dns`` kinds.

Why these are their own kinds and not options on ``http``: the failures they catch are
invisible to a status code. Traefik answers a host it has no certificate for with its
self-signed default, so a browser warns while a ``verify=False`` probe sees a 200. A
node can keep serving an old certificate the other node renewed. A DNS record can drift
to VHP-1, dangle after a service is removed, or be shadowed by a GitHub Pages wildcard
that breaks ACME for every new name. Each of those was seen on the estate.

``tls`` request keys::

    host   (required) the name sent as SNI and verified against
    port   443

It connects through public DNS, or to the node IP for ``via: tgx1|tgx2``. A verifying
handshake runs first; when it fails only on the certificate, a second, non-verifying
handshake fetches the leaf so issuer and expiry are still reported. Values: ``verified
verify_error issuer_cn issuer_o subject_cn san not_before not_after days_left
is_traefik_default covers_host fingerprint_sha256 chain tls_version cipher peer_ip
latency_ms``. Connection refused, timeout or a handshake that fails even unverified
is an error: the endpoint does not speak TLS.

``dns`` request keys::

    name            (required)
    type            A (default) | AAAA | CNAME | NS | TXT | MX
    resolvers       list of resolver IPs (default: the system resolver)
    wildcard_probe  false | true (probe under the parent of ``name``) | a zone name

Values: ``answers`` (sorted strings, trailing dots stripped), ``first``, ``rcode``,
``nxdomain``, ``ad`` (DNSSEC-validated flag from the resolver), ``per_resolver``
``{ip: answers}``, ``consistent``, ``node`` (A only: tgx1 | tgx2 | other | none),
``cname_chain``, ``canonical_name`` and, with a wildcard probe, ``wildcard_zone``,
``wildcard_answers``, ``wildcard``. NXDOMAIN is a value, not an error: a dangling or
deleted record is something to assert on. A resolver timeout or SERVFAIL says nothing
about our records, so when no resolver answers the observation is unknown.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import secrets
import socket
import ssl
import time
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from ..catalogue import Check
from ..http import NODES
from ..model import Call, Observation
from .base import Context, Kind, register

TRAEFIK_DEFAULT = "TRAEFIK DEFAULT CERT"
DNS_TYPES = ("A", "AAAA", "CNAME", "NS", "TXT", "MX")
PROBE_PREFIX = "zz-tgxmon-probe-"


# ---------------------------------------------------------------------------- tls
def _verifying_context() -> ssl.SSLContext:
    """The system trust store, as a browser would see it. Tests swap this out."""
    return ssl.create_default_context()


def _insecure_context() -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _handshake(addr: str, port: int, host: str, timeout: float, verify: bool) -> dict[str, Any]:
    """One blocking TLS handshake. Raises OSError/ssl.SSLError; the caller sorts them."""
    ctx = _verifying_context() if verify else _insecure_context()
    with socket.create_connection((addr, port), timeout=timeout) as raw, \
            ctx.wrap_socket(raw, server_hostname=host) as s:
        chain = []
        get_chain = getattr(getattr(s, "_sslobj", None), "get_unverified_chain", None)
        if get_chain is not None:  # private in 3.12, public from 3.13
            try:
                chain = [c.public_bytes(ssl._ssl.ENCODING_DER) for c in get_chain() or []]
            except (AttributeError, ValueError, ssl.SSLError):
                chain = []
        return {"der": s.getpeercert(binary_form=True), "chain": chain,
                "tls_version": s.version(), "cipher": (s.cipher() or ("",))[0],
                "peer_ip": s.getpeername()[0]}


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else ""


def _covers(pattern: str, host: str) -> bool:
    """RFC 6125 style: a leading ``*.`` matches exactly one label."""
    p, h = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if p.startswith("*."):
        return "." in h and h.split(".", 1)[1] == p[2:]
    return p == h


def parse_cert(der: bytes, host: str, now: dt.datetime) -> dict[str, Any]:
    """The values an assertion needs from a leaf certificate, valid or not."""
    cert = x509.load_der_x509_certificate(der)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san = ext.get_values_for_type(x509.DNSName) + [
            str(ip) for ip in ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san = []
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    not_after = cert.not_valid_after_utc
    return {
        "issuer_cn": issuer_cn,
        "issuer_o": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "san": san,
        "covers_host": any(_covers(n, host) for n in san),
        "not_before": cert.not_valid_before_utc.isoformat(timespec="seconds"),
        "not_after": not_after.isoformat(timespec="seconds"),
        "days_left": round((not_after - now).total_seconds() / 86400, 2),
        "is_traefik_default": TRAEFIK_DEFAULT in issuer_cn.upper(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def _chain_names(chain: list[bytes]) -> list[str]:
    out = []
    for der in chain:
        try:
            out.append(_name_attr(x509.load_der_x509_certificate(der).subject,
                                  NameOID.COMMON_NAME))
        except ValueError:
            out.append("?")
    return out


@register
class TlsKind(Kind):
    name = "tls"
    required = ("host",)
    vias = ("public", "tgx1", "tgx2")

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        host = str(check.request["host"])
        port = int(check.request.get("port", 443))
        addr = NODES.get(via, host)
        timeout = check.timeout_s
        url = f"tls://{host}:{port}"
        calls: list[Call] = []

        async def attempt(verify: bool) -> tuple[dict[str, Any] | None, BaseException | None]:
            call = Call(method="TLS" if verify else "TLS (no verify)", url=url, via=via)
            calls.append(call)
            t0 = time.perf_counter()
            try:
                got = await asyncio.wait_for(
                    asyncio.to_thread(_handshake, addr, port, host, timeout, verify),
                    timeout=timeout + 2)
                call.ok = True
                return got, None
            except (OSError, TimeoutError) as exc:  # ssl.SSLError is an OSError
                call.note = _describe(exc)
                return None, exc
            finally:
                call.ms = round((time.perf_counter() - t0) * 1000, 1)

        got, exc = await attempt(verify=True)
        verify_error = ""
        if got is None:
            if not isinstance(exc, ssl.SSLError):  # refused, timeout, DNS: no answer at all
                return Observation(calls=calls, error=_describe(exc), evidence=_describe(exc))
            verify_error = _describe(exc)
            got, exc2 = await attempt(verify=False)
            if got is None:
                msg = f"TLS handshake failed: {_describe(exc2)}"
                return Observation(calls=calls, error=msg,
                                   evidence=f"{msg}; verifying attempt: {verify_error}")
        try:
            cert = parse_cert(got["der"], host, ctx.now())
        except (ValueError, TypeError) as exc3:
            return Observation(calls=calls, unknown=f"could not parse certificate: {exc3}")
        values: dict[str, Any] = {
            "verified": not verify_error, "verify_error": verify_error, **cert,
            "chain": _chain_names(got["chain"]), "tls_version": got["tls_version"],
            "cipher": got["cipher"], "peer_ip": got["peer_ip"],
            "latency_ms": calls[0].ms,
        }
        evidence = "" if not verify_error else (
            f"{verify_error}; issuer {cert['issuer_cn']!r}, SAN {cert['san']}, "
            f"not_after {cert['not_after']}")
        return Observation(values=values, calls=calls, evidence=evidence,
                           metrics={"days_left": cert["days_left"]})


def _describe(exc: BaseException | None) -> str:
    if exc is None:
        return ""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"certificate: {exc.verify_message or exc.reason}"
    if isinstance(exc, ssl.SSLError):
        return f"TLS: {exc.reason or exc}"
    if isinstance(exc, TimeoutError | socket.timeout):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return f"DNS: {exc.strerror or exc}"
    detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else exc
    return f"{type(exc).__name__}: {detail}"


# ---------------------------------------------------------------------------- dns
def _resolver(ip: str | None, timeout: float) -> dns.asyncresolver.Resolver:
    """A resolver for one nameserver IP, or the system one. Tests swap this out."""
    r = dns.asyncresolver.Resolver(configure=ip is None)
    if ip is not None:
        r.nameservers = [ip]
    r.lifetime = timeout
    r.timeout = min(timeout, 5.0)
    r.flags = dns.flags.RD | dns.flags.AD  # ask for the AD bit (RFC 6840)
    return r


def _text(rdata: Any) -> str:
    if hasattr(rdata, "address"):
        return str(rdata.address)
    if hasattr(rdata, "exchange"):
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if hasattr(rdata, "strings"):
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if hasattr(rdata, "target"):
        return rdata.target.to_text().rstrip(".")
    return rdata.to_text().rstrip(".")


async def _query(ip: str | None, name: str, rtype: str, timeout: float) -> dict[str, Any]:
    """One lookup. Returns {answers, rcode, nxdomain, ad, cname_chain, canonical_name}
    or {unknown: reason}. Never raises."""
    try:
        ans = await _resolver(ip, timeout).resolve(name, rtype, raise_on_no_answer=False,
                                                   search=False)
    except dns.resolver.NXDOMAIN:
        return {"answers": [], "rcode": "NXDOMAIN", "nxdomain": True, "ad": False,
                "cname_chain": [], "canonical_name": name}
    except dns.resolver.NoNameservers as exc:
        return {"unknown": f"SERVFAIL or refused: {str(exc)[:200]}"}
    except dns.exception.Timeout:
        return {"unknown": "resolver timeout"}
    except dns.exception.DNSException as exc:
        return {"unknown": f"{type(exc).__name__}: {str(exc)[:200]}"}
    rrset = ans.rrset
    chain = getattr(getattr(ans, "chaining_result", None), "cnames", []) or []
    return {
        "answers": sorted(_text(r) for r in rrset) if rrset is not None else [],
        "rcode": dns.rcode.to_text(ans.response.rcode()),
        "nxdomain": False,
        "ad": bool(ans.response.flags & dns.flags.AD),
        "cname_chain": [_text(rs[0]) for rs in chain if len(rs)],
        "canonical_name": ans.canonical_name.to_text().rstrip("."),
    }


def node_of(ip: str | None) -> str:
    if not ip:
        return "none"
    for alias, node_ip in NODES.items():
        if ip == node_ip:
            return alias
    return "other"


def _probe_zone(name: str, opt: Any) -> str | None:
    if not opt:
        return None
    if isinstance(opt, str):
        return opt.rstrip(".")
    parts = name.rstrip(".").split(".", 1)
    return parts[1] if len(parts) == 2 else None


@register
class DnsKind(Kind):
    name = "dns"
    required = ("name",)
    vias = ("public",)

    @classmethod
    def validate_request(cls, request: dict[str, Any], via: list[str]) -> list[str]:
        probs = super().validate_request(request, via)
        if str(request.get("type", "A")).upper() not in DNS_TYPES:
            probs.append(f"dns type must be one of {', '.join(DNS_TYPES)}")
        for ip in request.get("resolvers") or []:
            try:
                ipaddress.ip_address(str(ip))
            except ValueError:
                probs.append(f"resolver {ip!r} is not an IP address")
        return probs

    async def observe(self, check: Check, via: str, ctx: Context) -> Observation:
        r = check.request
        name = str(r["name"]).rstrip(".")
        rtype = str(r.get("type", "A")).upper()
        if rtype not in DNS_TYPES:
            return Observation(unknown=f"dns type {rtype!r} not supported")
        resolvers: list[str | None] = [str(x) for x in r.get("resolvers") or []] or [None]
        timeout = check.timeout_s

        async def timed(ip: str | None, qname: str) -> tuple[dict[str, Any], Call]:
            t0 = time.perf_counter()
            res = await _query(ip, qname, rtype, timeout)
            call = Call(method=f"DNS {rtype}", url=f"dns://{ip or 'system'}/{qname}",
                        via="public", ok="unknown" not in res,
                        ms=round((time.perf_counter() - t0) * 1000, 1),
                        note=res.get("unknown") or res.get("rcode", ""))
            return res, call

        done = await asyncio.gather(*(timed(ip, name) for ip in resolvers))
        calls = [c for _, c in done]
        per: dict[str, Any] = {}
        errors: dict[str, str] = {}
        answered: list[dict[str, Any]] = []
        for ip, (res, _) in zip(resolvers, done, strict=True):
            key = ip or "system"
            if "unknown" in res:
                errors[key] = res["unknown"]
                per[key] = None
            else:
                per[key] = res["answers"]
                answered.append(res)
        if not answered:
            msg = "; ".join(f"{k}: {v}" for k, v in errors.items())
            return Observation(calls=calls, unknown=f"no resolver answered for {name}: {msg}",
                               evidence=msg)
        main = answered[0]
        values: dict[str, Any] = {
            "answers": main["answers"],
            "first": main["answers"][0] if main["answers"] else None,
            "rcode": main["rcode"], "nxdomain": main["nxdomain"], "ad": main["ad"],
            "per_resolver": per, "resolver_errors": errors,
            "consistent": all(a["answers"] == main["answers"]
                              and a["nxdomain"] == main["nxdomain"] for a in answered),
            "cname_chain": main["cname_chain"], "canonical_name": main["canonical_name"],
        }
        if rtype == "A":
            values["node"] = node_of(values["first"])
        zone = _probe_zone(name, r.get("wildcard_probe"))
        if zone:
            label = f"{PROBE_PREFIX}{secrets.token_hex(4)}.{zone}"
            probe, call = await timed(resolvers[0], label)
            calls.append(call)
            values["wildcard_zone"] = zone
            if "unknown" in probe:
                values["wildcard"] = None
                values["wildcard_error"] = probe["unknown"]
            else:
                values["wildcard_answers"] = probe["answers"]
                values["wildcard"] = bool(probe["answers"])
        evidence = ""
        if errors or not values["consistent"]:
            evidence = f"per resolver: {per}; errors: {errors}"
        return Observation(values=values, calls=calls, evidence=evidence[:4000])
