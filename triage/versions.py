"""Version comparison that works well enough for PyPI and npm versions."""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version


def version_key(v: str) -> tuple:
    try:
        return (0, Version(v))
    except InvalidVersion:
        nums = tuple(int(x) for x in re.findall(r"\d+", v)[:4])
        return (1, nums)


def is_newer(a: str, b: str) -> bool:
    """True when version ``a`` sorts after ``b``."""
    ka, kb = version_key(a), version_key(b)
    if ka[0] != kb[0]:
        return False
    return ka > kb
