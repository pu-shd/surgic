"""Path containment checks (prefix matching is not containment)."""
from __future__ import annotations

import os


def is_under(path: str, root: str) -> bool:
    """True if ``path`` is ``root`` or inside it, after resolving symlinks."""
    p, r = os.path.realpath(path), os.path.realpath(root)
    try:
        return os.path.commonpath([p, r]) == r
    except ValueError:  # different drives / mix of absolute and relative
        return False
