"""Helpers for pyCognito."""

from typing import Any


def is_int(value: Any) -> bool:
    """Returns True if the value is an integer."""
    return value is not None and isinstance(value, int)
