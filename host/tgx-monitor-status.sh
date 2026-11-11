#!/usr/bin/env bash
# tgx-monitor-status.sh - root-only host health, written as a world-readable JSON file.
#
# Why this exists: the tgx-monitor agent runs unprivileged (non-root, no capabilities)
# and cannot ask Gluster about pending heals or split-brain, run mdadm --detail or
# smartctl, or see NTP and systemd state. This script runs those READ-ONLY commands as
# root every 5 minutes and leaves the answers in /mnt/gluster/docker/tgx-monitor/root-status/<host>.json,
# which the agent reads through a read-only bind mount.
#
# What it does NOT do: it changes nothing on the host. No restarts, no heals, no writes
# outside its output file and the lock file. Each probe is wrapped in `timeout 20`
# and a probe that fails or times out is recorded as such; it never stops the run.
#
# Install (root, both nodes):   see host/README.md
#   install -m 0755 tgx-monitor-status.sh /usr/local/sbin/tgx-monitor-status
#   echo '*/5 * * * * root /usr/local/sbin/tgx-monitor-status' > /etc/cron.d/tgx-monitor-status
#
# Environment (for testing; the cron needs none of these):
#   STATUS_OUT   output file        (default /mnt/gluster/docker/tgx-monitor/root-status/<short hostname>.json)
#   HC_FILE      healthchecks URL   (default /root/.tgx-monitor-hc; skipped if absent)
#   NO_PING=1    never ping healthchecks (implied when STATUS_OUT is set)
#   LOCK_FILE    flock file         (default /run/tgx-monitor-status.lock; not /run/lock,
#                which is world-writable: anyone could pre-create and hold the lock there)
#   Tests only:  STATUS_TEST_BIN (dir of fake tools put first on PATH), MDSTAT (file
#                read instead of /proc/mdstat), PROBE_TIMEOUT (seconds, default 20)

set -u
umask 022
export LC_ALL=C PATH=${STATUS_TEST_BIN:+$STATUS_TEST_BIN:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

OUT=${STATUS_OUT:-/mnt/gluster/docker/tgx-monitor/root-status/$(hostname -s).json}
HC_FILE=${HC_FILE:-/root/.tgx-monitor-hc}
NO_PING=${NO_PING:-}
[ -n "${STATUS_OUT:-}" ] && NO_PING=1
LOCK_FILE=${LOCK_FILE:-/run/tgx-monitor-status.lock}
MDSTAT=${MDSTAT:-/proc/mdstat}
T=${PROBE_TIMEOUT:-20}

# One run at a time: a hung gluster call must not pile up runs every 5 minutes.
exec 9>"$LOCK_FILE" || exit 0
flock -n 9 || exit 0

WORK=$(mktemp -d /tmp/tgx-monitor-status.XXXXXX) || exit 1
trap 'rm -rf "$WORK"' EXIT
START=$(date +%s)

# run NAME CMD...: stdout -> NAME.out, stderr (capped) -> NAME.err, exit code -> NAME.rc.
# Exit code 124 means the 20 s timeout hit, 127 that the tool is not installed.
run() {
    local name=$1
    shift
    timeout "$T" "$@" >"$WORK/$name.out" 2>"$WORK/$name.err" </dev/null
    echo $? >"$WORK/$name.rc"
    truncate -s '<4096' "$WORK/$name.err" 2>/dev/null || true
}
have() { command -v "$1" >/dev/null 2>&1; }

# --- GlusterFS: volumes, heal summary per volume, peers -----------------------------
if have gluster; then
    run gluster_volumes gluster volume list
    if [ "$(cat "$WORK/gluster_volumes.rc")" = 0 ]; then
        while read -r vol; do
            case $vol in '' | *[!A-Za-z0-9._-]*) continue ;; esac
            run "heal__$vol" gluster volume heal "$vol" info summary
        done <"$WORK/gluster_volumes.out"
    fi
    run gluster_peers gluster peer status
fi

# --- md RAID: mdadm --detail for each array the kernel lists -------------------------
if have mdadm && [ -r "$MDSTAT" ]; then
    awk '/^md[0-9]+ *:/ {print $1}' "$MDSTAT" >"$WORK/md.list"
    while read -r name; do
        run "md__$name" mdadm --detail "/dev/$name"
    done <"$WORK/md.list"
fi

# --- SMART health per physical disk (smartctl is optional) --------------------------
if have smartctl; then
    touch "$WORK/smart_ran"
    for dev in /dev/nvme[0-9]n[0-9] /dev/nvme[0-9][0-9]n[0-9] /dev/sd[a-z]; do
        [ -b "$dev" ] || continue
        run "smart__$(basename "$dev")" smartctl -H "$dev"
    done
fi

# --- inodes, NTP, pending reboot, daemons, systemd ----------------------------------
run df_inodes df -iP / /mnt/gluster-brick
have timedatectl && run ntp timedatectl show -p NTPSynchronized --value
for unit in docker glusterd containerd; do
    run "unit__$unit" systemctl is-active "$unit"
done
# A wedged systemd (2026-11-02) answers nothing at all: the timeout is the signal.
run systemd systemctl is-system-running
[ -e /var/run/reboot-required ] && cp /var/run/reboot-required.pkgs "$WORK/reboot.pkgs" \
    2>/dev/null
[ -e /var/run/reboot-required ] && touch "$WORK/reboot.required"
uname -r >"$WORK/kernel" 2>/dev/null
hostname >"$WORK/hostname" 2>/dev/null

# --- assemble JSON (python3 ships with Ubuntu 24.04; stdlib only, isolated mode) ----
OUT_DIR=$(dirname "$OUT")
mkdir -p "$OUT_DIR"
# mktemp (O_EXCL, random name): this runs as root in a directory other accounts can
# write, so the temporary file must never be a name someone could plant a link at.
# The final mv replaces a planted link instead of following it.
TMP_OUT=$(mktemp "$OUT_DIR/.status.json.XXXXXX") || exit 1
python3 -I -S - "$WORK" "$TMP_OUT" "$START" <<'PY'
import datetime as dt
import json
import os
import re
import sys
import time

work, out, start = sys.argv[1], sys.argv[2], int(sys.argv[3])
errors = []


def read(name, default=None):
    try:
        with open(os.path.join(work, name), errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def probe(name):
    """(stdout, rc) of one probe; rc None if it did not run. Notes timeouts as errors."""
    rc = read(name + ".rc")
    if rc is None:
        return None, None
    rc = int(rc.strip() or -1)
    if rc == 124:
        errors.append(f"{name}: timed out")
    elif rc == 127:
        errors.append(f"{name}: command not found")
    elif rc != 0 and name.split("__")[0] not in ("unit", "systemd", "smart"):
        err = (read(name + ".err") or "").strip().splitlines()
        errors.append(f"{name}: exit {rc}" + (f": {err[0][:200]}" if err else ""))
    return read(name + ".out", ""), rc


def num(rx, text):
    m = re.search(rx, text, re.M)
    return int(m.group(1)) if m else None


status = {"schema": 1, "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
          "host": (read("hostname") or "").strip(), "kernel": (read("kernel") or "").strip()}

# Gluster
vols_out, vols_rc = probe("gluster_volumes")
if vols_rc is None:
    status["gluster"] = {"available": False}
else:
    g = {"available": vols_rc == 0, "volumes": {}}
    for vol in (vols_out or "").split():
        text, rc = probe("heal__" + vol)
        if rc is None:
            continue
        bricks = re.findall(r"^Brick (\S+)\s*\nStatus: ([^\n]*)", text or "", re.M)
        v = {
            "ok": rc == 0, "bricks": len(bricks),
            "bricks_connected": sum(1 for _, s in bricks if s.strip() == "Connected"),
            "heal_pending": sum(int(x) for x in re.findall(
                r"Number of entries in heal pending:\s*(\d+)", text or "")),
            "split_brain": sum(int(x) for x in re.findall(
                r"Number of entries in split-brain:\s*(\d+)", text or "")),
            "possibly_healing": sum(int(x) for x in re.findall(
                r"Number of entries possibly healing:\s*(\d+)", text or "")),
        }
        if rc != 0:
            v["heal_pending"] = v["split_brain"] = None
        g["volumes"][vol] = v
    ok_vols = [v for v in g["volumes"].values() if v["ok"]]
    g["heal_pending"] = sum(v["heal_pending"] for v in ok_vols) if ok_vols else None
    g["split_brain"] = sum(v["split_brain"] for v in ok_vols) if ok_vols else None
    g["bricks_down"] = sum(v["bricks"] - v["bricks_connected"] for v in ok_vols)
    peers_out, peers_rc = probe("gluster_peers")
    states = re.findall(r"^State: (.*)$", peers_out or "", re.M)
    g["peers_total"] = num(r"Number of Peers:\s*(\d+)", peers_out or "")
    g["peers_connected"] = sum(1 for s in states if "(Connected)" in s)
    g["peer_states"] = [s.strip() for s in states]
    status["gluster"] = g

# md RAID
md = {}
for f in sorted(os.listdir(work)):
    if f.startswith("md__") and f.endswith(".rc"):
        name = f[4:-3]
        text, rc = probe("md__" + name)
        kv = {k.strip(): v.strip() for k, sep, v in
              (ln.partition(":") for ln in (text or "").splitlines()) if sep}
        state = kv.get("State")
        md[name] = {
            "state": state, "level": kv.get("Raid Level"),
            "raid_devices": int(kv["Raid Devices"]) if kv.get("Raid Devices", "").isdigit()
            else None,
            "active_devices": int(kv["Active Devices"])
            if kv.get("Active Devices", "").isdigit() else None,
            "failed_devices": int(kv["Failed Devices"])
            if kv.get("Failed Devices", "").isdigit() else None,
            "degraded": bool(state) and any(w in state for w in
                                            ("degraded", "FAILED", "inactive")),
            "rebuild": kv.get("Rebuild Status"),
        }
status["md"] = md
status["md_degraded"] = sorted(k for k, v in md.items() if v["degraded"])

# SMART
smart = {}
for f in sorted(os.listdir(work)):
    if f.startswith("smart__") and f.endswith(".rc"):
        name = f[7:-3]
        text, rc = probe("smart__" + name)
        m = re.search(r"(?:self-assessment test result|SMART Health Status):\s*(\S+)",
                      text or "")
        health = m.group(1) if m else None
        # smartctl's exit code is a bitmask; bit 3 (8) means "disk failing".
        smart[name] = {"health": health, "passed": health in ("PASSED", "OK"),
                       "exit": rc}
status["smart_available"] = os.path.exists(os.path.join(work, "smart_ran")) or bool(smart)
status["smart"] = smart

# inodes
text, rc = probe("df_inodes")
inodes = {}
for ln in (text or "").splitlines()[1:]:
    f = ln.split()
    if len(f) >= 6 and f[4].rstrip("%").isdigit():
        key = {"/": "root", "/mnt/gluster-brick": "brick"}.get(f[5], f[5])
        inodes[key] = {"used_pct": int(f[4].rstrip("%")), "mount": f[5]}
status["inodes"] = inodes

# NTP, reboot, units, systemd
text, rc = probe("ntp")
status["ntp"] = {"synchronized": (text or "").strip() == "yes" if rc is not None else None}
pkgs = read("reboot.pkgs")
status["reboot_required"] = os.path.exists(os.path.join(work, "reboot.required"))
status["reboot_pkgs"] = len((pkgs or "").split()) if status["reboot_required"] else 0
units = {}
for u in ("docker", "glusterd", "containerd"):
    text, rc = probe("unit__" + u)
    units[u] = (text or "").strip() or ("timeout" if rc == 124 else "unknown")
status["units"] = units
status["dockerd"] = units["docker"]
text, rc = probe("systemd")
status["systemd"] = {"state": (text or "").strip() or None, "responsive": rc != 124}

status["errors"] = errors
status["duration_s"] = int(time.time()) - start
with open(out, "w") as fh:
    json.dump(status, fh, indent=1, sort_keys=True)
    fh.write("\n")
PY
PY_RC=$?

if [ "$PY_RC" = 0 ] && [ -s "$TMP_OUT" ]; then
    chmod 0644 "$TMP_OUT" && mv -f "$TMP_OUT" "$OUT"
    RESULT=success
else
    rm -f "$TMP_OUT"
    RESULT=fail
fi

# --- dead-man ping: tells healthchecks.io the cron ran (content is judged elsewhere) --
if [ -z "$NO_PING" ] && [ -r "$HC_FILE" ]; then
    HC_URL=$(head -n1 "$HC_FILE" | tr -d '[:space:]')
    case $HC_URL in
        https://*)
            [ "$RESULT" = fail ] && HC_URL="$HC_URL/fail"
            if have curl; then
                timeout "$T" curl -fsS -m 10 --retry 2 -o /dev/null "$HC_URL" || true
            else
                timeout "$T" python3 -I -S -c \
                    'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=10)' \
                    "$HC_URL" >/dev/null 2>&1 || true
            fi
            ;;
    esac
fi

[ "$RESULT" = success ]
