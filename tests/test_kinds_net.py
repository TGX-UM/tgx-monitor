"""tls and dns kinds, offline.

TLS runs real handshakes against a throwaway server on 127.0.0.1 with certificates
minted here, so parsing, the verify-then-insecure fallback and error mapping are all
exercised for real. DNS swaps the resolver factory for one that returns dnspython
``Answer`` objects built from wire-format messages, so the code parses what a real
resolver would hand it.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tgx_monitor.catalogue import Check, Target
from tgx_monitor.kinds import KINDS, net
from tgx_monitor.kinds.base import Context, run_probe

NOW = dt.datetime.now(dt.UTC)


def _ctx() -> Context:
    return Context(http=None, catalogue=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------- certs
def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def _cert(subject: x509.Name, issuer: x509.Name, key, sign_key, *, san: list[str] | None,
          days: float = 90, ca: bool = False, start: float = -1) -> x509.Certificate:
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW + dt.timedelta(days=start))
         .not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
                            critical=False)
    # Python 3.13 verifies with VERIFY_X509_STRICT, which wants these as real CAs set them.
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                        critical=False)
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
        sign_key.public_key()), critical=False)
    if ca:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
    return b.sign(sign_key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


@pytest.fixture(scope="module")
def ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name("Test Root CA", "Test Org")
    return key, name, _cert(name, name, key, key, san=None, days=3650, ca=True, start=-30)


def _leaf(ca, host_sans: list[str], days: float = 60, start: float = -1):
    ca_key, ca_name, _ = ca
    key = ec.generate_private_key(ec.SECP256R1())
    return key, _cert(_name(host_sans[0]), ca_name, key, ca_key, san=host_sans, days=days,
                      start=start)


def _traefik_default():
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name("TRAEFIK DEFAULT CERT")
    return key, _cert(name, name, key, key, san=["abc.def.traefik.default"], days=365)


# ---------------------------------------------------------------------------- server
@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[Callable[..., int]]:
    """Start a one-thread TLS server for a key/cert pair; returns its port."""
    stops: list[Callable[[], None]] = []

    def start(key, cert) -> int:
        cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
        cf.write_bytes(_pem(cert))
        kf.write_bytes(_key_pem(key))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cf, kf)
        lsock = socket.create_server(("127.0.0.1", 0))
        lsock.settimeout(0.2)
        stop = threading.Event()

        def loop() -> None:
            while not stop.is_set():
                try:
                    conn, _ = lsock.accept()
                except OSError:
                    continue
                try:
                    with sctx.wrap_socket(conn, server_side=True) as s:
                        s.settimeout(1)
                        with contextlib.suppress(OSError):
                            s.recv(1)
                except OSError:  # the client aborted after a failed verify
                    conn.close()

        threading.Thread(target=loop, daemon=True).start()

        def halt() -> None:
            stop.set()
            lsock.close()

        stops.append(halt)
        return lsock.getsockname()[1]

    yield start
    for s in stops:
        s()


@pytest.fixture
def local_nodes(monkeypatch):
    monkeypatch.setitem(net.NODES, "tgx1", "127.0.0.1")
    monkeypatch.setitem(net.NODES, "tgx2", "127.0.0.1")


def _tls_check(host: str, port: int, timeout: str = "5s", via: str = "tgx1") -> Check:
    return Check(id="tls-probe", kind="tls", via=[via], timeout=timeout,
                 request={"host": host, "port": port})


# ---------------------------------------------------------------------------- tls
def test_kinds_registered():
    assert KINDS["tls"] is net.TlsKind
    assert KINDS["dns"] is net.DnsKind


async def test_traefik_default_cert_is_reported_not_raised(tls_server, local_nodes):
    port = tls_server(*_traefik_default())
    obs = await net.TlsKind().observe(_tls_check("www.example.test", port), "tgx1", _ctx())
    assert obs.error is None and obs.unknown is None
    v = obs.values
    assert v["verified"] is False
    assert "self-signed" in v["verify_error"] or "certificate" in v["verify_error"]
    assert v["is_traefik_default"] is True
    assert v["issuer_cn"] == "TRAEFIK DEFAULT CERT"
    assert v["covers_host"] is False
    assert 363 < v["days_left"] < 366
    assert v["peer_ip"] == "127.0.0.1"
    assert [c.method for c in obs.calls] == ["TLS", "TLS (no verify)"]
    assert obs.calls[0].ok is False and obs.calls[1].ok is True
    assert "self-signed" in obs.evidence or "certificate" in obs.evidence


async def test_verified_cert_one_handshake(tls_server, local_nodes, monkeypatch, ca):
    key, cert = _leaf(ca, ["svc.example.test", "alias.example.test"], days=30)
    port = tls_server(key, cert)
    monkeypatch.setattr(net, "_verifying_context",
                        lambda: ssl.create_default_context(cadata=_pem(ca[2]).decode()))
    obs = await net.TlsKind().observe(_tls_check("alias.example.test", port, via="tgx2"),
                                      "tgx2", _ctx())
    v = obs.values
    assert obs.error is None
    assert v["verified"] is True and v["verify_error"] == ""
    assert v["issuer_cn"] == "Test Root CA" and v["issuer_o"] == "Test Org"
    assert v["subject_cn"] == "svc.example.test"
    assert v["san"] == ["svc.example.test", "alias.example.test"]
    assert v["covers_host"] is True
    assert v["is_traefik_default"] is False
    assert 29 < v["days_left"] <= 30
    assert v["tls_version"].startswith("TLSv1.")
    assert len(v["fingerprint_sha256"]) == 64
    assert v["chain"][0] == "svc.example.test"
    assert dt.datetime.fromisoformat(v["not_after"]) > NOW
    assert len(obs.calls) == 1 and obs.calls[0].ok
    assert obs.metrics["days_left"] == v["days_left"]
    assert obs.evidence == ""


async def test_expired_cert_still_parsed(tls_server, local_nodes, monkeypatch, ca):
    key, cert = _leaf(ca, ["old.example.test"], days=-2, start=-90)
    port = tls_server(key, cert)
    monkeypatch.setattr(net, "_verifying_context",
                        lambda: ssl.create_default_context(cadata=_pem(ca[2]).decode()))
    obs = await net.TlsKind().observe(_tls_check("old.example.test", port), "tgx1", _ctx())
    assert obs.values["verified"] is False
    assert "expired" in obs.values["verify_error"]
    assert obs.values["days_left"] < 0


async def test_wrong_host_fails_verification(tls_server, local_nodes, monkeypatch, ca):
    key, cert = _leaf(ca, ["svc.example.test"])
    port = tls_server(key, cert)
    monkeypatch.setattr(net, "_verifying_context",
                        lambda: ssl.create_default_context(cadata=_pem(ca[2]).decode()))
    obs = await net.TlsKind().observe(_tls_check("other.example.test", port), "tgx1", _ctx())
    assert obs.values["verified"] is False
    assert obs.values["covers_host"] is False
    assert "match" in obs.values["verify_error"]


async def test_connection_refused_is_error(local_nodes):
    s = socket.create_server(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    obs = await net.TlsKind().observe(_tls_check("svc.example.test", port), "tgx1", _ctx())
    assert obs.error is not None and "Refused" in obs.error
    assert obs.values == {}
    assert len(obs.calls) == 1 and not obs.calls[0].ok


async def test_silent_server_times_out_as_error(local_nodes):
    s = socket.create_server(("127.0.0.1", 0))  # accepts TCP, never speaks TLS
    try:
        obs = await net.TlsKind().observe(
            _tls_check("svc.example.test", s.getsockname()[1], timeout="1s"), "tgx1", _ctx())
    finally:
        s.close()
    assert obs.error == "timeout"


async def test_run_probe_judges_traefik_default(tls_server, local_nodes):
    port = tls_server(*_traefik_default())
    t = Target.model_validate({
        "id": "www-example", "name": "x", "class": "service", "owners": ["a"],
        "public_summary": "x",
        "checks": [{"id": "tls-www", "kind": "tls", "via": ["tgx1"], "timeout": "5s",
                    "request": {"host": "www.example.test", "port": port},
                    "assert": [{"that": "is_traefik_default", "eq": False},
                               {"that": "days_left", "gt": 21}]}]})
    res = await run_probe(t, t.checks[0], "tls-www", "tgx1", _ctx())
    assert res.status == "failed"
    assert [o.status for o in res.outcomes] == ["failed", "ok"]
    assert res.metrics["days_left"] > 300


def test_covers_wildcards():
    assert net._covers("*.example.org", "a.example.org")
    assert not net._covers("*.example.org", "a.b.example.org")
    assert not net._covers("*.example.org", "example.org")
    assert net._covers("Example.org.", "example.org")


def test_tls_validate_request():
    assert net.TlsKind.validate_request({"host": "x"}, ["public", "tgx1", "tgx2"]) == []
    probs = net.TlsKind.validate_request({}, ["core"])
    assert any("host" in p for p in probs) and any("core" in p for p in probs)


# ---------------------------------------------------------------------------- dns
def _answer(name: str, rtype: str, records: list[tuple[str, str, str]],
            ad: bool = False) -> dns.resolver.Answer:
    """A dnspython Answer as a resolver would return it. records: (owner, type, rdata)."""
    q = dns.message.make_query(name, rtype)
    r = dns.message.make_response(q)
    for owner, typ, rdata in records:
        r.answer.append(dns.rrset.from_text(owner, 300, "IN", typ, rdata))
    if ad:
        r.flags |= dns.flags.AD
    r = dns.message.from_wire(r.to_wire())  # sections resolve the way a real reply does
    return dns.resolver.Answer(dns.name.from_text(name), dns.rdatatype.from_text(rtype),
                               dns.rdataclass.IN, r)


class FakeResolver:
    def __init__(self, behave: Callable[[str, str], dns.resolver.Answer]) -> None:
        self.behave = behave

    async def resolve(self, name, rtype, raise_on_no_answer=True, search=None):
        return self.behave(str(name), str(rtype))


@pytest.fixture
def resolvers(monkeypatch):
    """Map resolver ip ('system' for None) -> behaviour(name, type)."""
    table: dict[str, Callable[[str, str], dns.resolver.Answer]] = {}
    seen: list[tuple[str, str, str]] = []

    def factory(ip, timeout):
        key = ip or "system"

        def behave(name: str, rtype: str):
            seen.append((key, name, rtype))
            return table[key](name, rtype)
        return FakeResolver(behave)

    monkeypatch.setattr(net, "_resolver", factory)
    return table, seen


def _a(ip: str, ad: bool = False):
    return lambda name, rtype: _answer(name, rtype, [(name + ".", "A", ip)], ad=ad)


def _nx(name, rtype):
    raise dns.resolver.NXDOMAIN(qnames=[dns.name.from_text(name)])


def _timeout(name, rtype):
    raise dns.exception.Timeout()


def _servfail(name, rtype):
    raise dns.resolver.NoNameservers(request=dns.message.make_query(name, rtype), errors=[])


def _dns_check(**request) -> Check:
    return Check(id="dns-probe", kind="dns", timeout="5s", request=request)


async def test_dns_a_points_at_tgx1_and_resolvers_agree(resolvers):
    table, seen = resolvers
    table["1.1.1.1"] = _a("81.169.246.233", ad=True)
    table["9.9.9.9"] = _a("81.169.246.233")
    obs = await net.DnsKind().observe(
        _dns_check(name="aopwiki.example.org", resolvers=["1.1.1.1", "9.9.9.9"]), "public",
        _ctx())
    v = obs.values
    assert obs.unknown is None and obs.error is None
    assert v["answers"] == ["81.169.246.233"] and v["first"] == "81.169.246.233"
    assert v["node"] == "tgx1" and v["consistent"] is True
    assert v["rcode"] == "NOERROR" and v["nxdomain"] is False and v["ad"] is True
    assert v["per_resolver"] == {"1.1.1.1": ["81.169.246.233"], "9.9.9.9": ["81.169.246.233"]}
    assert "wildcard" not in v
    assert [c.url for c in obs.calls] == ["dns://1.1.1.1/aopwiki.example.org",
                                          "dns://9.9.9.9/aopwiki.example.org"]


async def test_dns_inconsistent_and_other_node(resolvers):
    table, _ = resolvers
    table["1.1.1.1"] = _a("192.0.2.17")
    table["9.9.9.9"] = _a("85.214.252.63")
    v = (await net.DnsKind().observe(
        _dns_check(name="x.example.org", resolvers=["1.1.1.1", "9.9.9.9"]), "public",
        _ctx())).values
    assert v["node"] == "other" and v["consistent"] is False
    assert v["per_resolver"]["9.9.9.9"] == ["85.214.252.63"]


async def test_dns_nxdomain_is_a_value(resolvers):
    table, _ = resolvers
    table["system"] = _nx
    obs = await net.DnsKind().observe(_dns_check(name="gone.example.org"), "public", _ctx())
    assert obs.unknown is None and obs.error is None
    assert obs.values["nxdomain"] is True and obs.values["rcode"] == "NXDOMAIN"
    assert obs.values["answers"] == [] and obs.values["node"] == "none"


@pytest.mark.parametrize("fail", [_timeout, _servfail])
async def test_dns_no_resolver_answers_is_unknown(resolvers, fail):
    table, _ = resolvers
    table["1.1.1.1"] = fail
    obs = await net.DnsKind().observe(_dns_check(name="x.example.org", resolvers=["1.1.1.1"]),
                                      "public", _ctx())
    assert obs.unknown is not None and obs.error is None
    assert obs.calls[0].ok is False


async def test_dns_one_resolver_failing_keeps_the_others(resolvers):
    table, _ = resolvers
    table["1.1.1.1"] = _timeout
    table["9.9.9.9"] = _a("81.169.246.233")
    obs = await net.DnsKind().observe(
        _dns_check(name="x.example.org", resolvers=["1.1.1.1", "9.9.9.9"]), "public", _ctx())
    assert obs.unknown is None
    assert obs.values["node"] == "tgx1"
    assert obs.values["per_resolver"]["1.1.1.1"] is None
    assert "timeout" in obs.values["resolver_errors"]["1.1.1.1"]
    assert obs.evidence


async def test_dns_cname_chain(resolvers):
    table, _ = resolvers
    table["system"] = lambda name, rtype: _answer(name, rtype, [
        ("www.r-odaf.example.", "CNAME", "r-odaf.example."),
        ("r-odaf.example.", "A", "81.169.246.233")])
    v = (await net.DnsKind().observe(_dns_check(name="www.r-odaf.example"), "public",
                                     _ctx())).values
    assert v["cname_chain"] == ["r-odaf.example"]
    assert v["canonical_name"] == "r-odaf.example"
    assert v["node"] == "tgx1"


async def test_dns_wildcard_probe_parent_zone(resolvers):
    table, seen = resolvers

    def behave(name, rtype):
        if name.startswith(net.PROBE_PREFIX):
            return _answer(name, rtype, [(name + ".", "A", "185.199.109.153")])
        return _answer(name, rtype, [(name + ".", "A", "81.169.246.233")])
    table["1.1.1.1"] = behave
    v = (await net.DnsKind().observe(
        _dns_check(name="svc.zone.example", resolvers=["1.1.1.1"], wildcard_probe=True),
        "public", _ctx())).values
    assert v["wildcard_zone"] == "zone.example"
    assert v["wildcard"] is True and v["wildcard_answers"] == ["185.199.109.153"]
    assert seen[-1][1].endswith(".zone.example") and seen[-1][1].startswith(net.PROBE_PREFIX)


async def test_dns_wildcard_probe_explicit_zone_nx(resolvers):
    table, seen = resolvers
    table["system"] = lambda name, rtype: (_nx(name, rtype) if name.startswith(net.PROBE_PREFIX)
                                           else _a("81.169.246.233")(name, rtype))
    v = (await net.DnsKind().observe(
        _dns_check(name="zone.example", wildcard_probe="zone.example"), "public", _ctx())).values
    assert v["wildcard"] is False and v["wildcard_answers"] == []
    assert seen[-1][1].endswith(".zone.example")


async def test_dns_record_types_formatting(resolvers):
    table, _ = resolvers
    records = {
        "MX": [("z.example.", "MX", "10 mail.z.example.")],
        "TXT": [("z.example.", "TXT", '"v=spf1 " "-all"')],
        "NS": [("z.example.", "NS", "ns4.stratoserver.net."),
               ("z.example.", "NS", "ns3.stratoserver.net.")],
    }
    for rtype, recs in records.items():
        table["system"] = lambda name, rt, recs=recs: _answer(name, rt, recs)
        v = (await net.DnsKind().observe(_dns_check(name="z.example", type=rtype), "public",
                                         _ctx())).values
        assert "node" not in v
        if rtype == "MX":
            assert v["answers"] == ["10 mail.z.example"]
        elif rtype == "TXT":
            assert v["answers"] == ["v=spf1 -all"]
        else:
            assert v["answers"] == ["ns3.stratoserver.net", "ns4.stratoserver.net"]


async def test_dns_empty_noerror(resolvers):
    table, _ = resolvers
    table["system"] = lambda name, rtype: _answer(name, rtype, [])
    v = (await net.DnsKind().observe(_dns_check(name="z.example", type="AAAA"), "public",
                                     _ctx())).values
    assert v["answers"] == [] and v["first"] is None and v["nxdomain"] is False


def test_dns_validate_request():
    assert net.DnsKind.validate_request({"name": "x", "resolvers": ["1.1.1.1"]},
                                        ["public"]) == []
    probs = net.DnsKind.validate_request({"name": "x", "type": "SRV",
                                          "resolvers": ["one.one"]}, ["tgx1"])
    assert len(probs) == 3


def test_node_of():
    assert net.node_of("81.169.246.233") == "tgx1"
    assert net.node_of("85.214.252.63") == "tgx2"
    assert net.node_of("1.2.3.4") == "other"
    assert net.node_of(None) == "none"


# ---------------------------------------------------------------------------- live
LIVE_HOST = "aopwiki.rdf.bigcat-bioinformatics.org"


@pytest.mark.live
@pytest.mark.parametrize("via", ["tgx1", "tgx2"])
async def test_live_tls_aopwiki_on_each_node(via):
    obs = await net.TlsKind().observe(_tls_check(LIVE_HOST, 443, timeout="15s", via=via),
                                      via, _ctx())
    assert obs.error is None, obs.error
    v = obs.values
    assert v["verified"] is True and v["is_traefik_default"] is False
    assert LIVE_HOST in v["san"] and v["peer_ip"] == net.NODES[via]
    assert v["days_left"] > 0


@pytest.mark.live
async def test_live_dns_aopwiki():
    obs = await net.DnsKind().observe(
        _dns_check(name=LIVE_HOST, resolvers=["1.1.1.1", "9.9.9.9"], wildcard_probe=True),
        "public", _ctx())
    assert obs.unknown is None, obs.unknown
    assert obs.values["node"] == "tgx1" and obs.values["consistent"] is True
    assert obs.values["wildcard"] in (True, False)
