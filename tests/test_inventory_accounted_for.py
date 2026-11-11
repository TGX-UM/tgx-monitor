"""Every one of the 566 live-verified inventory checks is accounted for.

Each inventory check id must appear in some catalogue check's ``inv_ids`` (public
targets, or the private security-canary config), or in a ``dropped-*.yaml`` file with a
reason (merged into another check, legacy host retired, moved to the private config,
not checkable from the cluster, ...).

The id index and the dropped reasons are private (``catalogue/_import/private/``,
git-ignored): they name internal hosts and holes that are still open, which a public
repository must not list. ``catalogue/_import/inventory.json`` carries the count and a
hash of the sorted ids, so the full check runs wherever the private copy is present
and the public CI still confirms the catalogue never claims an id outside it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from tgx_monitor import catalogue as catmod

ROOT = Path(__file__).resolve().parents[1] / "catalogue"
SUMMARY = ROOT / "_import" / "inventory.json"
PRIVATE = ROOT / "_import" / "private"
INDEX = PRIVATE / "inv-index.json"
PRIVATE_CHECKS = PRIVATE / "private_checks.yaml"


def inventory_ids() -> list[str]:
    idx = json.loads(INDEX.read_text())
    return sorted({c for slice_ in idx.values() for t in slice_ for c in t["checks"]})


def dropped() -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(PRIVATE.glob("dropped-*.yaml")):
        for row in yaml.safe_load(p.read_text()) or []:
            assert row.get("reason"), f"{p.name}: {row} has no reason"
            out[row["inv_id"]] = row["reason"]
    return out


def covered(cat: catmod.Catalogue) -> set[str]:
    return {i for t in cat.targets.values() for c in t.checks for i in c.inv_ids}


def test_public_catalogue_stays_within_the_inventory_size():
    summary = json.loads(SUMMARY.read_text())
    assert summary["total"] == 566
    assert len(covered(catmod.load(ROOT))) <= summary["total"]


@pytest.mark.skipif(not INDEX.exists(), reason="private inventory index not present")
def test_private_index_is_the_published_inventory():
    summary = json.loads(SUMMARY.read_text())
    ids = inventory_ids()
    assert len(ids) == summary["total"]
    assert hashlib.sha256("\n".join(ids).encode()).hexdigest() == summary["sha256_sorted_ids"]


@pytest.mark.skipif(not INDEX.exists(), reason="private inventory index not present")
def test_every_inventory_check_is_accounted_for():
    private = PRIVATE_CHECKS.read_text() if PRIVATE_CHECKS.exists() else None
    cat = catmod.load(ROOT, private)
    have = covered(cat)
    gone = dropped()
    ids = set(inventory_ids())
    missing = sorted(ids - have - set(gone))
    assert not missing, f"{len(missing)} inventory checks unaccounted for: {missing[:40]}"
    unknown = sorted((have | set(gone)) - ids)
    assert not unknown, f"inv_ids that are not in the inventory: {unknown[:20]}"
