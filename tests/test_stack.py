"""stack.yml keeps the deployment rules: secrets as files, private overlays, no host
ports or node pins, nobody as root, and the socket proxy exactly as narrow as the code."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from tgx_monitor.docker import ALLOWED_PATHS

STACK = yaml.safe_load((Path(__file__).resolve().parents[1] / "stack.yml").read_text())
SERVICES = STACK["services"]


def _labels(svc: str) -> dict[str, str]:
    out = {}
    for item in SERVICES[svc].get("deploy", {}).get("labels", []):
        k, _, v = item.partition("=")
        out[k] = v
    return out


def test_no_host_ports_no_node_pins_no_root():
    for name, svc in SERVICES.items():
        assert "ports" not in svc, name
        assert not svc.get("deploy", {}).get("placement"), name
        assert str(svc.get("user", "10001")).split(":")[0] not in ("0", "root"), name
        assert svc.get("cap_drop") == ["ALL"], name


def test_secrets_are_external_files_and_env_holds_no_credentials():
    for key, v in STACK["secrets"].items():
        # external only; a rotated secret keeps its mount name via name: <key>_v<n>
        assert v.get("external") is True and set(v) <= {"external", "name"}, key
        assert re.fullmatch(rf"{key}(_v\d+)?", v.get("name", key)), key
    for name, svc in SERVICES.items():
        for k, v in (svc.get("environment") or {}).items():
            if re.search(r"(?i)pass|secret|token|key|credential", k):
                assert not v, f"{name}: {k} looks like a plaintext credential"


def test_private_overlays_are_encrypted_and_the_docker_api_is_internal():
    nets = STACK["networks"]
    assert nets["tgxmon_dockerapi"]["internal"] is True
    for n in ("tgxmon_dockerapi", "tgxmon_int"):
        assert nets[n]["driver_opts"]["encrypted"] == "true", n
    for name, svc in SERVICES.items():
        if "tgxmon_dockerapi" in svc.get("networks", []):
            assert name in ("core", "docker-proxy"), name


def test_docker_socket_only_in_the_proxy_read_only_and_get_only():
    for name, svc in SERVICES.items():
        socks = [v for v in svc.get("volumes", []) if "docker.sock" in str(v.get("source"))]
        if name == "docker-proxy":
            assert socks and all(v.get("read_only") for v in socks)
        else:
            assert not socks, name
    cmd = SERVICES["docker-proxy"]["command"]
    assert [c.split("=", 1)[1] for c in cmd if c.startswith("-allowGET=")] == [ALLOWED_PATHS]
    others = [c for c in cmd if re.match(r"-allow(?!GET=|from=|healthcheck)", c)]
    assert not others, others


def test_login_router_outranks_the_catch_all_and_push_stays_internal():
    labels = _labels("core")
    core_rule = labels["traefik.http.routers.tgxmon-core.rule"]
    assert "!PathPrefix(`/api/push`)" in core_rule
    assert int(labels.get("traefik.http.routers.tgxmon-login.priority", "0")) > len(core_rule)
    assert labels["traefik.http.routers.tgxmon-login.middlewares"] == "tgxmon-login-rl"
