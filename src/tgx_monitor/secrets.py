"""Reading secrets.

In the swarm every credential is a Docker secret mounted at ``/run/secrets/<name>``
(AGENTS.md: never plaintext env in a stack file). Locally, ``TGXMON_SECRETS_DIR``
points at a directory with the same file names, for development. A missing secret
returns None and the check or channel that needed it reports ``unknown`` -- it never
crashes the process and never falls back to something weaker.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

SECRETS_DIR = Path(os.environ.get("TGXMON_SECRETS_DIR", "/run/secrets"))


def read_secret(name: str, base: Path | None = None) -> str | None:
    p = (base or SECRETS_DIR) / name
    try:
        return p.read_text().strip() or None
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


def read_secret_json(name: str, base: Path | None = None) -> Any:
    raw = read_secret(name, base)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        import yaml

        return yaml.safe_load(raw)


def secret_reader(base: Path | None = None) -> Callable[[str], str | None]:
    return lambda name: read_secret(name, base)
