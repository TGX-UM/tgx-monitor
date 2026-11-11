#!/usr/bin/env python3
"""Render the JS-heavy pages in ``catalogue/browser.yaml`` and record what drew.

Why this runs in GitHub Actions and not on the cluster: a headless Chromium is several
hundred MB of memory and a large attack surface, for a check that is fine every 6 h.
Actions runs it; this script writes ``browser/latest.json``; the workflow commits it to
the ``history`` branch; the ``browser_artifact`` check in core reads it and alerts like
any other check. If this workflow stops, the artifact ages and that check goes red.

Output (stable, read by ``kinds/data.py`` ``browser_artifact``)::

    {"generated_at": "...Z", "runner": "...", "playwright": "1.64.1",
     "pages": [{"id", "url", "ok", "status", "title", "ms", "found", "marks",
                "console_errors", "problems": [...], "checks": {name: bool}}]}

Only page views: no clicks that submit, no logins, no forms.

    python scripts/browser_checks.py [--config catalogue/browser.yaml] [--out browser/latest.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
from importlib.metadata import version
from pathlib import Path
from typing import Any

import yaml
from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

UA = "tgx-monitor-browser-check/1 (+https://github.com/TGX-UM/tgx-monitor)"


def load(path: Path) -> list[dict[str, Any]]:
    doc = yaml.safe_load(path.read_text()) or {}
    pages = doc.get("pages") or []
    ids = [p["id"] for p in pages]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"{path}: duplicate page ids")
    return pages


def _scroll_through(page: Page) -> None:
    """Scroll down in steps so lazy-loaded plots get their intersection events."""
    height = page.evaluate("document.body.scrollHeight")
    for y in range(0, int(height) + 800, 800):
        page.evaluate(f"window.scrollTo(0, {y})")
        page.wait_for_timeout(250)
    page.evaluate("window.scrollTo(0, 0)")


def check_page(browser: Any, spec: dict[str, Any]) -> dict[str, Any]:
    timeout_ms = float(spec.get("timeout", 60)) * 1000
    out: dict[str, Any] = {"id": spec["id"], "url": spec["url"], "ok": False, "status": None,
                           "title": "", "ms": None, "found": 0, "marks": 0,
                           "console_errors": 0, "problems": [], "checks": {}}
    errors: list[str] = []
    ctx = browser.new_context(user_agent=UA, viewport={"width": 1366, "height": 900})
    page = ctx.new_page()
    page.set_default_timeout(timeout_ms)
    page.on("console", lambda m: errors.append(m.text[:200]) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(f"pageerror: {str(e)[:200]}"))
    t0 = time.perf_counter()
    try:
        resp = page.goto(spec["url"], wait_until="domcontentloaded")
        out["status"] = resp.status if resp else None
        if spec.get("scroll"):
            page.wait_for_load_state("networkidle")
            _scroll_through(page)
        sel = spec.get("wait_for")
        if sel:
            page.wait_for_selector(sel, state="visible")
            want = int(spec.get("min_count", 1))
            deadline = time.perf_counter() + timeout_ms / 1000
            while page.locator(sel).count() < want and time.perf_counter() < deadline:
                page.wait_for_timeout(500)
            out["found"] = page.locator(sel).count()
            out["checks"]["min_count"] = out["found"] >= want
        if spec.get("marks"):
            out["marks"] = page.locator(spec["marks"]).count()
            out["checks"]["marks"] = out["marks"] >= 1
        out["title"] = page.title()
        if spec.get("title_contains"):
            out["checks"]["title"] = spec["title_contains"] in out["title"]
        if spec.get("text_contains"):
            out["checks"]["text"] = spec["text_contains"] in page.inner_text("body")
    except PWError as exc:
        out["problems"].append(f"{type(exc).__name__}: {str(exc).splitlines()[0][:300]}")
    finally:
        out["ms"] = round((time.perf_counter() - t0) * 1000)
        ctx.close()
    out["console_errors"] = len(errors)
    out["console_sample"] = errors[:5]
    if out["status"] is not None and out["status"] >= 400:
        out["problems"].append(f"HTTP {out['status']}")
    if "max_console_errors" in spec:
        out["checks"]["console"] = len(errors) <= int(spec["max_console_errors"])
    out["problems"] += [f"check {k} failed" for k, v in out["checks"].items() if not v]
    out["ok"] = not out["problems"] and out["status"] is not None
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--config", default="catalogue/browser.yaml")
    p.add_argument("--out", default="browser/latest.json")
    p.add_argument("--only", nargs="*", help="page ids")
    p.add_argument("--channel", help="use an installed browser, e.g. chrome (local runs)")
    args = p.parse_args(argv)

    pages = [s for s in load(Path(args.config)) if not args.only or s["id"] in args.only]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=args.channel) if args.channel \
            else pw.chromium.launch()
        try:
            results = [check_page(browser, s) for s in pages]
        finally:
            browser.close()
    doc = {"generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
           "runner": "github-actions" if os.environ.get("GITHUB_ACTIONS") else "local",
           "playwright": version("playwright"), "pages": results}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    for r in results:
        mark = "ok  " if r["ok"] else "FAIL"
        print(f"{mark} {r['id']:32s} {r['ms']:>6}ms found={r['found']} marks={r['marks']} "
              f"console_errors={r['console_errors']} {'; '.join(r['problems'])}")
    # Exit 0 even when a page fails: the verdict belongs to core's browser_artifact
    # check, and a red workflow would skip the commit that carries the evidence.
    return 0


if __name__ == "__main__":
    sys.exit(main())
