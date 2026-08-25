"""Check registry.

Each check is a callable taking (client, target, fingerprint) and returning a
list of Findings. They register themselves via @register so adding a check is
dropping a function in one of the modules here — no central list to edit and
forget. `ALL` is populated at import time.
"""

from __future__ import annotations

from collections.abc import Callable

from ..http import Client
from ..model import Finding, Target

CheckFn = Callable[[Client, Target, object], list[Finding]]

ALL: list[tuple[str, CheckFn]] = []


def register(check_id: str):
    def deco(fn: CheckFn) -> CheckFn:
        ALL.append((check_id, fn))
        return fn
    return deco


# Import side effects populate ALL. Kept at the bottom to avoid a circular
# import: the modules below import `register` from this package.
from . import disclosure, endpoints, headers  # noqa: E402,F401
