"""Parse human durations such as ``30s``, ``5m``, ``1h30m`` or ``2d``."""

from __future__ import annotations

import re

_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)")


def parse_duration(value: object, *, field: str = "duration") -> float:
    """Return ``value`` in seconds. Numbers are already seconds."""
    if isinstance(value, bool):
        raise ValueError(f"{field}: expected a duration, got {value!r}")
    if isinstance(value, int | float):
        if value < 0:
            raise ValueError(f"{field}: must not be negative")
        return float(value)
    if not isinstance(value, str):
        raise ValueError(f"{field}: expected a duration such as '5m', got {value!r}")
    text = value.strip().lower().replace(" ", "")
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return float(text)
    pos = 0
    total = 0.0
    for match in _PART.finditer(text):
        if match.start() != pos:
            break
        total += float(match.group(1)) * _UNITS[match.group(2)]
        pos = match.end()
    if pos != len(text) or not text:
        raise ValueError(f"{field}: cannot parse duration {value!r} (use e.g. 30s, 5m, 1h30m, 2d)")
    return total


def format_duration(seconds: float) -> str:
    """Short human form: ``90`` -> ``1m30s``."""
    seconds = round(seconds)
    if seconds <= 0:
        return "0s"
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size:
            amount, seconds = divmod(seconds, size)
            parts.append(f"{amount}{unit}")
    return "".join(parts)
