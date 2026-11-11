"""Check kinds. Importing this package registers every kind in ``KINDS``."""

from importlib import import_module

from .base import KINDS, Context, Kind, register, run_probe

# Each module registers its kinds on import. A missing optional module (a kind still
# being built) must not break the others, so failures are collected, not raised;
# ``doctor`` reports them.
IMPORT_ERRORS: dict[str, str] = {}
for _mod in ("web", "sparql", "net", "data", "infra", "pipeline"):
    try:
        import_module(f"{__name__}.{_mod}")
    except ModuleNotFoundError as exc:
        if exc.name != f"{__name__}.{_mod}":
            IMPORT_ERRORS[_mod] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        IMPORT_ERRORS[_mod] = f"{type(exc).__name__}: {exc}"

__all__ = ["KINDS", "Context", "Kind", "register", "run_probe", "IMPORT_ERRORS"]
