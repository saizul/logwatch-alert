"""A tiny, safe ``{{ variable | filter }}`` template renderer.

Only dotted lookups into the context are possible: no attribute access, no calls,
no expressions. Unknown variables render as an empty string.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

_TAG = re.compile(r"{{\s*(.+?)\s*}}")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_-]+)*$")
_MISSING = object()


class TemplateError(ValueError):
    """Raised for a malformed template."""


def lookup(context: Mapping[str, Any], path: str) -> Any:
    """Resolve ``a.b.0.c`` inside nested mappings and lists; returns ``_MISSING`` if absent."""
    current: Any = context
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, list | tuple) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def _to_text(value: Any) -> str:
    if value is None or value is _MISSING:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Mapping | list | tuple):
        return json.dumps(value, default=str, ensure_ascii=False)
    return str(value)


def _apply(value: Any, name: str, arg: str | None) -> Any:
    if name == "default":
        return arg if value in (_MISSING, None, "") else value
    if name == "json":
        return json.dumps(None if value is _MISSING else value, default=str, ensure_ascii=False)
    text = _to_text(value)
    if name == "upper":
        return text.upper()
    if name == "lower":
        return text.lower()
    if name == "trim":
        return text.strip()
    if name == "truncate":
        limit = int(arg or 200)
        return text if len(text) <= limit else text[: max(limit - 1, 0)] + "…"
    raise TemplateError(f"unknown filter {name!r} (use default, json, upper, lower, trim, truncate)")


_FILTER = re.compile(r"^([a-z_]+)(?:\((.*)\))?$")


def _parse(expr: str) -> tuple[str, list[tuple[str, str | None]]]:
    name, *filters = (part.strip() for part in expr.split("|"))
    if not _NAME.match(name):
        raise TemplateError(f"invalid variable {name!r}")
    parsed = []
    for item in filters:
        match = _FILTER.match(item)
        if not match:
            raise TemplateError(f"invalid filter {item!r}")
        arg = match.group(2)
        if arg is not None:
            arg = arg.strip().strip("'\"")
        parsed.append((match.group(1), arg))
    return name, parsed


def validate(template: str) -> None:
    """Raise ``TemplateError`` if ``template`` cannot be rendered."""
    for match in _TAG.finditer(template):
        _, filters = _parse(match.group(1))
        for name, arg in filters:
            _apply("", name, arg)


def render(template: str, context: Mapping[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        name, filters = _parse(match.group(1))
        value = lookup(context, name)
        for filter_name, arg in filters:
            value = _apply(value, filter_name, arg)
        return _to_text(value)

    return _TAG.sub(replace, template)
