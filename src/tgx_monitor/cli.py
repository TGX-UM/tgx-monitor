"""Command line.

    tgx-monitor doctor                     validate the catalogue (no network)
    tgx-monitor check --once [--only ID..] run probes once and print a report
    tgx-monitor run                        the long-running core service
    tgx-monitor serve-public               serve the static public snapshot
    tgx-monitor agent                      the per-node host agent
    tgx-monitor import-inventory FILE      generate catalogue stubs from inv.json
    tgx-monitor test-alert / test-incident end-to-end alert tests
    tgx-monitor backup DEST / restore-verify FILE
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from . import catalogue as catmod
from .http import Http
from .kinds import IMPORT_ERRORS, KINDS, Context

DEFAULT_CATALOGUE = os.environ.get("TGXMON_CATALOGUE", "catalogue")


def _catalogue(args: argparse.Namespace) -> catmod.Catalogue:
    return catmod.load(Path(args.catalogue))


def cmd_doctor(args: argparse.Namespace) -> int:
    cat = _catalogue(args)
    probs = cat.validate(known_kinds=set(KINDS))
    for t in cat.targets.values():
        for c in t.checks:
            k = KINDS.get(c.kind)
            if k is not None:
                probs += [f"{t.id}/{c.id}: {p}" for p in k.validate_request(c.request, c.via)]
    probs += [f"kind module {m}: {e}" for m, e in IMPORT_ERRORS.items()]
    n_checks = sum(len(t.checks) for t in cat.targets.values())
    print(f"catalogue {cat.sha}: {len(cat.targets)} targets, {n_checks} checks, "
          f"{len(cat.probes())} probes, kinds: {', '.join(sorted(KINDS))}")
    for p in probs:
        print(f"  ✗ {p}")
    print("ok" if not probs else f"{len(probs)} problem(s)")
    return 0 if not probs else 1


async def _check_once(args: argparse.Namespace) -> int:
    from .scheduler import run_all_once
    from .secrets import secret_reader

    cat = _catalogue(args)
    http = Http()
    ctx = Context(http=http, catalogue=cat, secrets=secret_reader())
    try:
        res = await run_all_once(ctx, cat, only=args.only or None, concurrency=args.concurrency)
    finally:
        await http.aclose()
    bad = 0
    rows = []
    for pid, via, r in sorted(res, key=lambda x: x[0]):
        mark = {"ok": "✓", "failed": "✗", "unknown": "?"}.get(r.status, "·")
        if r.status != "ok":
            bad += 1
        rows.append({"probe": pid, "via": via, "status": r.status, "ms": r.duration_ms,
                     "summary": r.summary, "warn": r.warn})
        if not args.json:
            w = " (warn)" if r.warn else ""
            print(f"{mark} {pid:55s} {r.status:8s} {r.duration_ms:8.0f}ms  {r.summary[:110]}{w}")
            if args.verbose and r.status != "ok":
                for o in r.outcomes:
                    if o.status != "ok":
                        print(f"      - {o.assertion}: expected {o.expected}, found {o.found}")
    if args.json:
        print(json.dumps(rows, indent=1))
    else:
        print(f"{len(res) - bad}/{len(res)} ok")
    if args.report:
        Path(args.report).write_text(json.dumps(rows, indent=1))
    return 0 if bad == 0 else 2


def cmd_check(args: argparse.Namespace) -> int:
    return asyncio.run(_check_once(args))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tgx-monitor")
    p.add_argument("--catalogue", default=DEFAULT_CATALOGUE)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="validate the catalogue").set_defaults(fn=cmd_doctor)

    c = sub.add_parser("check", help="run probes once")
    c.add_argument("--once", action="store_true", default=True)
    c.add_argument("--only", nargs="*")
    c.add_argument("--concurrency", type=int, default=10)
    c.add_argument("--json", action="store_true")
    c.add_argument("--verbose", "-v", action="store_true")
    c.add_argument("--report")
    c.set_defaults(fn=cmd_check)

    # Commands implemented in other modules register themselves here if present.
    for mod in ("service", "importer", "alerts.cli", "agent", "web.public", "backup"):
        try:
            m = __import__(f"tgx_monitor.{mod}", fromlist=["add_commands"])
        except ModuleNotFoundError:
            continue
        if hasattr(m, "add_commands"):
            m.add_commands(sub)

    args = p.parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
