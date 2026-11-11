"""The per-node agent (parsers, dead-man logic, /signals, AgentClient) and the root cron."""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import httpx
import pytest

from tgx_monitor import agent as ag

# /proc/mdstat on tgx1, 2026-11-10: md1 (root fs) has lost a member.
MDSTAT_TGX1 = """Personalities : [raid1] [raid0] [raid6] [raid5] [raid4] [raid10]
md2 : active raid1 nvme1n1p5[1] nvme0n1p5[0]
      453006656 blocks super 1.2 [2/2] [UU]
      bitmap: 4/4 pages [16KB], 65536KB chunk

md1 : active raid1 nvme0n1p4[1]
      20462592 blocks super 1.2 [2/1] [_U]

md0 : active raid1 nvme0n1p2[1] nvme1n1p2[0]
      1022976 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""

MDSTAT_REBUILD = """Personalities : [raid1]
md1 : active raid1 nvme1n1p4[2] nvme0n1p4[1]
      20462592 blocks super 1.2 [2/1] [_U]
      [====>................]  recovery = 23.4% (4790016/20462592) finish=1.2min
md5 : inactive sdb1[0](S)
      1000 blocks
md6 : active raid1 sdc1[0](F) sdd1[1]
      1000 blocks [2/2] [UU]
"""

MEMINFO = """MemTotal:       32702292 kB
MemFree:         1000000 kB
MemAvailable:   17196646 kB
SwapTotal:       8178684 kB
SwapFree:        2726228 kB
"""


def test_mdstat_flags_the_degraded_root_array() -> None:
    m = ag.parse_mdstat(MDSTAT_TGX1)
    assert m["degraded_arrays"] == ["md1"]
    assert m["array_count"] == 3
    md1 = m["arrays"]["md1"]
    assert (md1["level"], md1["total"], md1["active"], md1["status"]) == ("raid1", 2, 1, "_U")
    assert md1["devices"] == ["nvme0n1p4"]
    assert not m["arrays"]["md2"]["degraded"]


def test_mdstat_rebuild_inactive_and_failed_member() -> None:
    m = ag.parse_mdstat(MDSTAT_REBUILD)
    assert m["arrays"]["md1"]["progress"] == "recovery 23.4%"
    assert m["arrays"]["md5"]["degraded"]  # inactive
    assert m["arrays"]["md6"]["failed_devices"] == ["sdc1"]
    assert m["degraded_arrays"] == ["md1", "md5", "md6"]


def test_meminfo_loadavg_btime() -> None:
    mem = ag.parse_meminfo(MEMINFO)
    assert mem["available_pct"] == pytest.approx(52.6, abs=0.1)
    assert mem["swap_free_pct"] == pytest.approx(33.3, abs=0.1)
    load = ag.parse_loadavg("8.46 9.10 8.46 3/1200 4242\n", 6)
    assert load["per_cpu15"] == pytest.approx(1.41)
    assert ag.parse_btime("cpu 1 2 3\nbtime 1793702592\nprocesses 9\n") == 1793702592


def test_mount_fstype_picks_the_longest_prefix() -> None:
    mi = textwrap.dedent("""\
        1 0 0:1 / / rw - overlay overlay rw
        2 1 0:2 / /hostfs/hidrive ro,relatime - cifs //smb3.example/root ro
        3 1 0:3 / /hostfs/gluster-brick ro - xfs /dev/md2 ro
    """)
    assert ag.mount_fstype("/hostfs/hidrive", mi) == ("cifs", True)
    assert ag.mount_fstype("/hostfs/hidrive/docker/x", mi) == ("cifs", False)
    assert ag.mount_fstype("/tmp", mi) == ("overlay", False)


def test_node_alias_and_pairs() -> None:
    assert ag.node_alias("h3068544.stratoserver.net") == "tgx1"
    assert ag.node_alias("h2973005") == "tgx2"
    assert ag.node_alias("tgx2") == "tgx2"
    assert ag.peer_of("tgx1") == "tgx2"
    assert ag.parse_pairs("rootfs=/a, brick=/b,/c/hidrive") == {
        "rootfs": "/a", "brick": "/b", "hidrive": "/c/hidrive"}


def test_list_dir_caps_and_sorts(tmp_path: Path) -> None:
    for i in range(5):
        p = tmp_path / f"virtuoso-{i}.tar.gz"
        p.write_bytes(b"x" * (i + 1))
        os.utime(p, (1000 + i, 1000 + i))
    out = ag.list_dir(str(tmp_path), now=1000 + 4 + 7200, cap=3)
    assert out["truncated"] and out["count"] == 3
    assert out["entries"][0]["mtime"] >= out["entries"][-1]["mtime"]
    assert out["newest_age_h"] == pytest.approx(2.0, abs=0.01)


def test_root_status_missing_fresh_and_broken(tmp_path: Path) -> None:
    p = tmp_path / "status.json"
    assert ag.read_root_status(str(p), 0)["present"] is False
    p.write_text('{"gluster": {"split_brain": 0}}')
    os.utime(p, (5000, 5000))
    rs = ag.read_root_status(str(p), 5000 + 600)
    assert rs["present"] and rs["age_s"] == 600 and rs["content"]["gluster"]["split_brain"] == 0
    p.write_text("{not json")
    assert "not JSON" in ag.read_root_status(str(p), 0)["error"]


def test_heartbeat_round_trip_and_verdict(tmp_path: Path) -> None:
    ag.write_heartbeat(tmp_path, "core")
    hb = ag.read_heartbeat(tmp_path, "core", now=ag._epoch(json.loads(
        (tmp_path / "core.json").read_text())["ts"]) + 400)
    assert hb["present"] and hb["age_s"] == pytest.approx(400, abs=1)
    assert ag.Agent.verdict({"core": hb}) == "core heartbeat 400s old"
    assert ag.Agent.verdict({"core": {"present": True, "age_s": 10}}) is None
    assert ag.Agent.verdict({"tgx2": {"present": False}}) == "tgx2 heartbeat missing"


# ---------------------------------------------------------------------- whole agent
@pytest.fixture
def proc(tmp_path: Path) -> Path:
    d = tmp_path / "proc"
    (d / "self").mkdir(parents=True)
    (d / "mdstat").write_text(MDSTAT_TGX1)
    (d / "meminfo").write_text(MEMINFO)
    (d / "loadavg").write_text("1.0 1.0 1.0 1/1 1\n")
    (d / "stat").write_text("btime 1793702592\n")
    (d / "self" / "mountinfo").write_text("1 0 0:1 / / rw - overlay overlay rw\n")
    return d


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _agent(tmp_path: Path, proc: Path, clock: Clock, sent: list[httpx.Request],
           dry_run: bool = False) -> ag.Agent:
    (tmp_path / "hd").mkdir()
    (tmp_path / "hd" / "virtuoso-1.tar.gz").write_bytes(b"x")
    cfg = ag.AgentConfig(node="tgx1", hostname="h3068544", proc=str(proc),
                         paths={"rootfs": str(tmp_path)}, hidrive={"dash": str(tmp_path / "hd")},
                         status_file=str(tmp_path / "status.json"),
                         hb_dir=str(tmp_path / "hb"), dry_run=dry_run)

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(req)
        return httpx.Response(200, text="OK")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return ag.Agent(cfg, hc_urls={"agent-tgx1": "https://hc.invalid/abc"}, client=client,
                    clock=clock)


@pytest.fixture(autouse=True)
def no_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(host: str, port: int, timeout: float = 5.0) -> dict:
        return {"ok": port != 24007, "ms": 1.0}

    monkeypatch.setattr(ag, "tcp_probe", fake)


async def test_cycle_collects_everything_and_respects_startup_grace(
        tmp_path: Path, proc: Path) -> None:
    clock, sent = Clock(1_800_000_000.0), []
    a = _agent(tmp_path, proc, clock, sent)
    snap = await a.cycle()
    assert snap["errors"] == {}
    assert snap["mdstat"]["degraded_arrays"] == ["md1"]
    assert snap["disk"]["rootfs"]["used_pct"] is not None
    assert snap["peer"]["failed"] == ["24007"] and snap["peer"]["node"] == "tgx2"
    assert snap["root_status"]["present"] is False
    assert snap["hidrive"]["dash"]["count"] == 1
    assert (tmp_path / "hb" / "tgx1.json").exists()
    # core and tgx2 have never written: a /fail is due, but not inside the grace period.
    assert snap["hc"]["state"] == "grace" and sent == []

    clock.t += ag.STARTUP_GRACE_S + 1
    await a.cycle()
    assert [str(r.url) for r in sent] == ["https://hc.invalid/abc/fail"]
    assert b"core heartbeat missing" in sent[0].content

    ag.write_heartbeat(tmp_path / "hb", "core")
    ag.write_heartbeat(tmp_path / "hb", "tgx2")
    clock.t = ag._epoch(ag.iso()) + 5  # back to real time so the fresh files count
    a.started = clock.t - ag.STARTUP_GRACE_S - 1
    await a.cycle()
    assert str(sent[-1].url) == "https://hc.invalid/abc"
    await a.cycle()  # unchanged and within a minute: no second ping
    assert len(sent) == 2


async def test_dry_run_never_pings(tmp_path: Path, proc: Path) -> None:
    clock, sent = Clock(1_800_000_000.0), []
    a = _agent(tmp_path, proc, clock, sent, dry_run=True)
    a.started -= ag.STARTUP_GRACE_S + 1
    snap = await a.cycle()
    assert snap["hc"]["state"] == "dry-run" and snap["hc"]["kind"] == "fail"
    assert sent == []


async def test_a_broken_signal_does_not_stop_the_others(tmp_path: Path, proc: Path) -> None:
    (proc / "mdstat").unlink()
    a = _agent(tmp_path, proc, Clock(1_800_000_000.0), [], dry_run=True)
    snap = await a.cycle()
    assert "FileNotFoundError" in snap["errors"]["mdstat"]
    assert snap["memory"]["available_pct"] > 0


async def test_signals_endpoint(tmp_path: Path, proc: Path) -> None:
    from starlette.testclient import TestClient

    a = _agent(tmp_path, proc, Clock(1_800_000_000.0), [], dry_run=True)
    with TestClient(a.app()) as c:
        assert c.get("/signals").status_code == 503
        await a.cycle()
        r = c.get("/signals")
        assert r.status_code == 200 and r.json()["node"] == "tgx1"
        assert c.get("/livez").status_code == 200


# ---------------------------------------------------------------------- core's client
async def test_agent_client_maps_answers_to_nodes() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.host)
        if req.url.host == "10.0.0.5":
            return httpx.Response(200, json={"node": "tgx1", "collected_at": "x"})
        raise httpx.ConnectError("refused")

    c = ag.AgentClient(transport=httpx.MockTransport(handler),
                       resolve=lambda host, port: ["10.0.0.5", "10.0.0.6"])
    out = await c.signals()
    assert out["tgx1"]["collected_at"] == "x" and out["tgx1"]["_addr"] == "10.0.0.5"
    assert "no agent answered for tgx2" in out["tgx2"]["error"]
    assert "10.0.0.6" in out["tgx2"]["error"]
    await c.signals()  # cached
    assert len(calls) == 2


async def test_agent_client_unresolvable() -> None:
    def boom(host: str, port: int) -> list[str]:
        raise OSError("Name or service not known")

    out = await ag.AgentClient(resolve=boom).signals()
    assert set(out) == {"tgx1", "tgx2"} and "cannot resolve" in out["tgx1"]["error"]


def test_cli_registers_agent() -> None:
    import argparse

    p = argparse.ArgumentParser()
    ag.add_commands(p.add_subparsers(dest="cmd"))
    args = p.parse_args(["agent", "--once"])
    assert args.fn is ag.cmd_agent and args.once


# ---------------------------------------------------------------------- root cron script
SCRIPT = Path(__file__).resolve().parents[1] / "host" / "tgx-monitor-status.sh"

FAKE_GLUSTER = """#!/bin/sh
case "$1 $2" in
  "volume list") echo swarm-data ;;
  "volume heal") cat <<'EOF'
Brick 81.169.246.233:/mnt/gluster-brick/swarm-data
Status: Connected
Total Number of entries: 3
Number of entries in heal pending: 3
Number of entries in split-brain: 1
Number of entries possibly healing: 0

Brick 85.214.252.63:/mnt/gluster-brick/swarm-data
Status: Transport endpoint is not connected
Total Number of entries: -
Number of entries in heal pending: -
Number of entries in split-brain: -
Number of entries possibly healing: -
EOF
  ;;
  "peer status") sleep 5 ;;
esac
"""

FAKE_MDADM = """#!/bin/sh
case "$2" in
  /dev/md1) printf '/dev/md1:\\n        Raid Level : raid1\\n      Raid Devices : 2\\n\
             State : clean, degraded \\n    Active Devices : 1\\n    Failed Devices : 0\\n' ;;
  *) printf '/dev/md0:\\n        Raid Level : raid1\\n      Raid Devices : 2\\n\
             State : clean \\n    Active Devices : 2\\n    Failed Devices : 0\\n' ;;
esac
"""


def test_status_script_dry_run(tmp_path: Path) -> None:
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, body in (("gluster", FAKE_GLUSTER), ("mdadm", FAKE_MDADM)):
        (bin_ / name).write_text(body)
        (bin_ / name).chmod(0o755)
    mdstat = tmp_path / "mdstat"
    mdstat.write_text(MDSTAT_TGX1)
    out = tmp_path / "out" / "status.json"
    env = {"PATH": os.environ["PATH"], "STATUS_OUT": str(out), "STATUS_TEST_BIN": str(bin_),
           "MDSTAT": str(mdstat), "PROBE_TIMEOUT": "1", "LOCK_FILE": str(tmp_path / "lock"),
           "HC_FILE": str(tmp_path / "hc")}
    (tmp_path / "hc").write_text("https://hc.invalid/should-not-be-pinged\n")
    r = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    assert oct(out.stat().st_mode & 0o777) == "0o644"
    s = json.loads(out.read_text())
    assert s["schema"] == 1 and s["generated_at"]
    g = s["gluster"]
    assert g["heal_pending"] == 3 and g["split_brain"] == 1 and g["bricks_down"] == 1
    assert any("gluster_peers: timed out" in e for e in s["errors"])
    assert s["md"]["md1"]["degraded"] and not s["md"]["md0"]["degraded"]
    assert s["md_degraded"] == ["md1"]
    assert s["md"]["md1"]["active_devices"] == 1
    for key in ("inodes", "ntp", "reboot_required", "units", "dockerd", "systemd", "smart"):
        assert key in s
    assert not list(out.parent.glob(".status.json.tmp.*"))


def test_status_script_lock_is_not_in_a_world_writable_dir() -> None:
    """Root's lock in /run/lock (1777) could be pre-created and held by any local user,
    which would stop every run; the default must sit in a root-only directory."""
    m = re.search(r"^LOCK_FILE=\$\{LOCK_FILE:-(\S+)\}$", SCRIPT.read_text(), re.M)
    assert m and m.group(1).startswith("/run/") and not m.group(1).startswith(
        ("/run/lock/", "/tmp/", "/var/tmp/", "/dev/shm/"))
