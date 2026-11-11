# host/tgx-monitor-status.sh

A small root cron job for both swarm nodes (tgx1, tgx2). It answers the host questions
that need root and that the unprivileged tgx-monitor agent cannot ask itself, and leaves
the answers in a world-readable JSON file that the agent reads.

**It only reads.** Every command below is a status query. The script restarts nothing,
heals nothing and changes no configuration. It writes only to `/mnt/gluster/docker/tgx-monitor/root-status/<short hostname>.json`
(the JSON file) and to its lock file `/run/tgx-monitor-status.lock` (root-only `/run`,
not the world-writable `/run/lock`, where another user could hold the lock and stop the runs).

## What it collects

| Probe | Command | Why |
|---|---|---|
| Gluster heal state | `gluster volume list`, `gluster volume heal <vol> info summary` | pending heals and split-brain after a node outage |
| Gluster peers | `gluster peer status` | peer connected or not |
| RAID | `mdadm --detail /dev/mdN` for each array in `/proc/mdstat` | array state (tgx1 `md1` is degraded now) |
| Disks | `smartctl -H` per NVMe/SATA disk, only if smartmontools is installed | early disk failure |
| Inodes | `df -iP / /mnt/gluster-brick` | inode exhaustion |
| Clock | `timedatectl show -p NTPSynchronized --value` | NTP sync |
| Pending reboot | existence of `/var/run/reboot-required` | kernel updates waiting |
| Daemons | `systemctl is-active docker glusterd containerd`, `systemctl is-system-running` | dockerd down with the host still up, as on 2026-11-02; a hung systemd shows up as a timeout |

Each command runs under `timeout 20`. A probe that fails, times out or is not installed is
recorded in the `errors` list of the JSON and the run carries on. A lock (`flock`) stops a
slow run from overlapping the next one. The JSON is built with the system `python3` in
isolated mode (standard library only), written to a temporary file, set to mode 0644
and moved into place, so a reader never sees half a file.

## Install (root, on tgx1 and on tgx2)

```bash
install -m 0755 host/tgx-monitor-status.sh /usr/local/sbin/tgx-monitor-status
echo '*/5 * * * * root /usr/local/sbin/tgx-monitor-status' > /etc/cron.d/tgx-monitor-status
```

Optional dead-man ping: put the healthchecks.io ping URL for this node
(`root-status-tgx1` or `root-status-tgx2`; Marvin sends both) in a root-only file.

```bash
install -m 0600 /dev/null /root/.tgx-monitor-hc
echo 'https://hc-ping.com/<uuid>' > /root/.tgx-monitor-hc
```

After each run the script pings that URL, or `<url>/fail` if it could not write the
JSON. Without the file it pings nothing. The ping only says that the cron ran. Whether
the host is healthy is judged by tgx-monitor from the JSON content.

## Verify

```bash
/usr/local/sbin/tgx-monitor-status; echo "exit $?"     # 0 when the file was written
ls -l /mnt/gluster/docker/tgx-monitor/root-status/<host>.json                 # -rw-r--r-- root root, minutes old
python3 -m json.tool /mnt/gluster/docker/tgx-monitor/root-status/<host>.json | head -40
```

Check `md.md1.degraded`, `gluster.heal_pending`, `gluster.split_brain` and `errors`.
On a node without smartmontools, `smart` is `{}` and `smart_available` is `false`.

To try it without root and without touching `/var/lib`, set `STATUS_OUT`. That also
turns the ping off:

```bash
STATUS_OUT=/tmp/status.json bash host/tgx-monitor-status.sh && cat /tmp/status.json
```

## Output shape (schema 1)

```json
{
 "schema": 1, "generated_at": "2026-11-11T10:05:01+00:00", "host": "h3068544",
 "kernel": "6.8.0-147-generic", "duration_s": 2,
 "gluster": {"available": true, "heal_pending": 0, "split_brain": 0, "bricks_down": 0,
             "peers_total": 1, "peers_connected": 1, "peer_states": ["Peer in Cluster (Connected)"],
             "volumes": {"swarm-data": {"ok": true, "bricks": 2, "bricks_connected": 2,
                                        "heal_pending": 0, "split_brain": 0, "possibly_healing": 0}}},
 "md": {"md1": {"state": "clean, degraded", "level": "raid1", "raid_devices": 2,
                "active_devices": 1, "failed_devices": 0, "degraded": true, "rebuild": null}},
 "md_degraded": ["md1"],
 "smart": {"nvme0n1": {"health": "PASSED", "passed": true, "exit": 0}}, "smart_available": true,
 "inodes": {"root": {"used_pct": 14, "mount": "/"}, "brick": {"used_pct": 3, "mount": "/mnt/gluster-brick"}},
 "ntp": {"synchronized": true}, "reboot_required": false, "reboot_pkgs": 0,
 "units": {"docker": "active", "glusterd": "active", "containerd": "active"}, "dockerd": "active",
 "systemd": {"state": "degraded", "responsive": true},
 "errors": []
}
```

`gluster.heal_pending` and `gluster.split_brain` are `null` when the heal query itself
failed. A failed query is not reported as zero.

## How it is used

The tgx-monitor agent on each node bind-mounts `/mnt/gluster/docker/tgx-monitor/root-status`
read-only, reads its own node's file every 30 s and serves it to the monitor core, together with the file's
age. The `host` checks with `signal: root_status` assert on these fields, for example
`{that: age_h, lt: 0.25}`, `{that: gluster.split_brain, eq: 0}` and
`{that: md_degraded, len_eq: 0}`.
