"""Alert commands for ``tgx-monitor``, registered by ``cli.main`` via ``add_commands``.

    test-alert   [--channel all|github,smtp,slack] [--to H,H] --who H [--dry-run]
    test-incident --break | --fix
    silence add TARGET [--check ID] --reason TEXT --until 2h|ISO --who H
    silence list | silence rm ID --who H
    ack INCIDENT (id or key) --who H
    outbox [--dead | --sent] [--limit N]

They write to the same database as the core service (``TGXMON_DB``, default
``/data/monitor.db``) and are meant to run inside the core container via
``docker exec``; the core's dispatcher does the sending.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path

from ..assertions import parse_duration
from ..model import utcnow
from ..store import Store

DEFAULT_DB = os.environ.get("TGXMON_DB", "/data/monitor.db")


def _store(args: argparse.Namespace) -> Store:
    return Store(Path(args.db))


def _until(text: str) -> dt.datetime:
    try:
        return utcnow() + dt.timedelta(seconds=parse_duration(text))
    except ValueError:
        ts = dt.datetime.fromisoformat(text)
        return ts if ts.tzinfo else ts.replace(tzinfo=dt.UTC)


def cmd_test_alert(args: argparse.Namespace) -> int:
    from .. import catalogue as catmod
    from .testing import CHANNELS, enqueue_test_alert

    cat = catmod.load(Path(args.catalogue))
    channels = list(CHANNELS) if args.channel == "all" else args.channel.split(",")
    to = args.to.split(",") if args.to else list(cat.owners.admins if cat.owners else [])
    key = enqueue_test_alert(_store(args), cat, to, channels, args.who, dry_run=args.dry_run,
                             private_base_url=os.environ.get("TGXMON_PRIVATE_URL", ""))
    print(f"queued test incident {key} on {', '.join(channels)} to {', '.join(to)}; "
          "the core dispatcher sends it and resolves it after 5 min")
    return 0


def cmd_test_incident(args: argparse.Namespace) -> int:
    from .testing import set_selftest

    set_selftest(_store(args), broken=args.broken)
    print("monitor-selftest is now "
          + ("BROKEN: expect an incident within 3 cycles + 2 min" if args.broken
             else "fixed: expect recovery after 2 passes"))
    return 0


def cmd_silence(args: argparse.Namespace) -> int:
    from .engine import add_silence, list_silences, remove_silence

    store = _store(args)
    if args.action == "add":
        if not (args.target and args.reason and args.until and args.who):
            print("silence add needs TARGET --reason --until --who")
            return 2
        sid = add_silence(store, args.target, args.reason, _until(args.until), args.who,
                          check_id=args.check)
        print(f"silence {sid} added")
    elif args.action == "rm":
        if not (args.target and args.who):
            print("silence rm needs ID --who")
            return 2
        ok = remove_silence(store, int(args.target), args.who)
        print("removed" if ok else "no such silence")
        return 0 if ok else 1
    else:
        for s in list_silences(store):
            print(f"{s['id']:>4}  {s['target_id']}/{s['check_id'] or '*'}  until {s['until']}  "
                  f"by {s['created_by']}: {s['reason']}")
    return 0


def cmd_ack(args: argparse.Namespace) -> int:
    from .engine import ack_incident

    ok = ack_incident(_store(args), args.ref, args.who)
    print(f"acknowledged {args.ref}" if ok else f"no open incident {args.ref}")
    return 0 if ok else 1


def cmd_outbox(args: argparse.Namespace) -> int:
    from .outbox import listing

    which = "dead" if args.dead else "sent" if args.sent else "pending"
    for r in listing(_store(args), which, args.limit):
        print(f"{r['id']:>6} {r['created_at']} {r['channel']:6s} {r['event']:9s} "
              f"att={r['attempts']} {'DRY ' if r['dry_run'] else ''}"
              f"{','.join(r['recipients'])}  {r['payload'].get('line', '')}  {r['reply'] or ''}")
    return 0


def add_commands(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    def parser(name: str, help_: str, fn: object) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_)
        p.add_argument("--db", default=DEFAULT_DB)
        p.set_defaults(fn=fn)
        return p

    p = parser("test-alert", "queue a synthetic incident through the real channels",
               cmd_test_alert)
    p.add_argument("--channel", default="all", help="all or a comma list: github,smtp,slack")
    p.add_argument("--to", help="comma-separated handles (default: the admins)")
    p.add_argument("--who", required=True)
    p.add_argument("--dry-run", action="store_true")

    p = parser("test-incident", "break or fix the monitor-selftest check", cmd_test_incident)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--break", dest="broken", action="store_true")
    g.add_argument("--fix", dest="broken", action="store_false")

    p = parser("silence", "add, list or remove silences", cmd_silence)
    p.add_argument("action", choices=["add", "list", "rm"])
    p.add_argument("target", nargs="?", help="target id (add) or silence id (rm)")
    p.add_argument("--check")
    p.add_argument("--reason")
    p.add_argument("--until", help="a duration (2h, 3d) or an ISO timestamp (UTC)")
    p.add_argument("--who")

    p = parser("ack", "acknowledge an open incident (stops escalation)", cmd_ack)
    p.add_argument("ref", help="incident id or key")
    p.add_argument("--who", required=True)

    p = parser("outbox", "list pending, dead or sent notifications", cmd_outbox)
    p.add_argument("--dead", action="store_true")
    p.add_argument("--sent", action="store_true")
    p.add_argument("--limit", type=int, default=50)

