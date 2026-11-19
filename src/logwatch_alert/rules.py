"""Rule definitions: regex patterns, JSON field conditions, thresholds and cooldowns."""

from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from logwatch_alert import templating
from logwatch_alert.durations import parse_duration

SEVERITIES = ("debug", "info", "warning", "error", "critical")

DEFAULT_TITLE = "[{{ severity | upper }}] {{ rule }} on {{ hostname }}"
DEFAULT_MESSAGE = (
    "{{ count }} match(es) in {{ window_human }} from {{ source }}{{ group_suffix }}\n"
    "{{ suppressed_note }}"
    "Last line:\n{{ line | truncate(1000) }}"
)

_OPERATORS = ("equals", "not_equals", "in", "not_in", "regex", "contains", "exists", "gt", "gte", "lt", "lte")


class RuleError(ValueError):
    """Invalid rule definition."""


_MISSING = object()


def get_field(data: Any, path: str) -> Any:
    """Look up ``a.b.0`` in parsed JSON. A literal key containing dots wins over traversal."""
    if isinstance(data, Mapping) and path in data:
        return data[path]
    current = data
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _same(actual: Any, expected: Any) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual is expected
    if actual == expected:
        return True
    # "500" in the log and 500 in the rule (or the other way round) should match.
    a, b = _number(actual), _number(expected)
    return a is not None and b is not None and a == b


@dataclass(frozen=True)
class Condition:
    """One check on a JSON field, e.g. ``status: {gte: 500}``."""

    path: str
    op: str
    value: Any
    pattern: re.Pattern[str] | None = None

    @classmethod
    def parse(cls, path: str, spec: Any) -> list[Condition]:
        if not isinstance(spec, Mapping):
            return [cls(path, "equals", spec)]
        if not spec:
            raise RuleError(f"json condition for {path!r} is empty")
        out = []
        for op, value in spec.items():
            if op not in _OPERATORS:
                raise RuleError(f"json condition {path!r}: unknown operator {op!r} (use {', '.join(_OPERATORS)})")
            pattern = None
            if op in ("in", "not_in") and not isinstance(value, list):
                raise RuleError(f"json condition {path!r}: {op} needs a list")
            if op in ("gt", "gte", "lt", "lte") and _number(value) is None:
                raise RuleError(f"json condition {path!r}: {op} needs a number")
            if op == "exists" and not isinstance(value, bool):
                raise RuleError(f"json condition {path!r}: exists needs true or false")
            if op == "regex":
                try:
                    pattern = re.compile(str(value))
                except re.error as exc:
                    raise RuleError(f"json condition {path!r}: invalid regex: {exc}") from exc
            out.append(cls(path, op, value, pattern))
        return out

    def check(self, data: Any) -> bool:
        actual = get_field(data, self.path)
        if self.op == "exists":
            return (actual is not _MISSING) is self.value
        if actual is _MISSING:
            return self.op in ("not_equals", "not_in")
        if self.op == "equals":
            return _same(actual, self.value)
        if self.op == "not_equals":
            return not _same(actual, self.value)
        if self.op == "in":
            return any(_same(actual, v) for v in self.value)
        if self.op == "not_in":
            return not any(_same(actual, v) for v in self.value)
        if self.op == "regex":
            assert self.pattern is not None
            text = actual if isinstance(actual, str) else json.dumps(actual, default=str)
            return self.pattern.search(text) is not None
        if self.op == "contains":
            if isinstance(actual, list):
                return any(_same(item, self.value) for item in actual)
            return str(self.value) in str(actual)
        number = _number(actual)
        if number is None:
            return False
        limit = float(self.value)
        return {
            "gt": number > limit,
            "gte": number >= limit,
            "lt": number < limit,
            "lte": number <= limit,
        }[self.op]


@dataclass(frozen=True)
class Match:
    captures: dict[str, str]
    fields: Any


@dataclass
class Rule:
    name: str
    patterns: list[re.Pattern[str]] = field(default_factory=list)
    exclude: list[re.Pattern[str]] = field(default_factory=list)
    conditions: list[Condition] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    count: int = 1
    window: float = 60.0
    cooldown: float = 600.0
    group_by: str = ""
    severity: str = "error"
    notify: list[str] | None = None
    title: str = DEFAULT_TITLE
    message: str = DEFAULT_MESSAGE
    description: str = ""
    pack: str | None = None
    ignore_case: bool = False

    def applies_to(self, source: str, path: str | None = None) -> bool:
        """``sources`` entries are source names or globs, checked against the name and the file path."""
        if not self.sources:
            return True
        candidates = [source] if path is None or path == source else [source, path]
        return any(fnmatch.fnmatchcase(c, pattern) for c in candidates for pattern in self.sources)

    def match(self, source: str, line: str, fields: Any = None, *, path: str | None = None) -> Match | None:
        """Return a ``Match`` if ``line`` (and its parsed JSON ``fields``) triggers the rule."""
        if not self.applies_to(source, path):
            return None
        captures: dict[str, str] = {}
        if self.patterns:
            for pattern in self.patterns:
                found = pattern.search(line)
                if found:
                    captures = {k: v for k, v in found.groupdict().items() if v is not None}
                    break
            else:
                return None
        if self.conditions:
            if fields is None:
                return None
            if not all(condition.check(fields) for condition in self.conditions):
                return None
        if any(pattern.search(line) for pattern in self.exclude):
            return None
        return Match(captures=captures, fields=fields)


def _compile_list(value: Any, *, rule: str, key: str, flags: int) -> list[re.Pattern[str]]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out = []
    for item in items:
        if not isinstance(item, str) or not item:
            raise RuleError(f"rule {rule!r}: {key} must be a regex string or a list of them")
        try:
            out.append(re.compile(item, flags))
        except re.error as exc:
            raise RuleError(f"rule {rule!r}: invalid {key} regex {item!r}: {exc}") from exc
    return out


_RULE_KEYS = {
    "name",
    "description",
    "pattern",
    "patterns",
    "exclude",
    "json",
    "sources",
    "threshold",
    "cooldown",
    "group_by",
    "severity",
    "notify",
    "title",
    "message",
    "ignore_case",
    "enabled",
}


def parse_rule(raw: Mapping[str, Any], *, pack: str | None = None, default_cooldown: float = 600.0) -> Rule:
    if not isinstance(raw, Mapping):
        raise RuleError("each rule must be a mapping")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RuleError("every rule needs a non-empty 'name'")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise RuleError(f"rule {name!r}: unknown key(s) {', '.join(sorted(unknown))}")
    ignore_case = bool(raw.get("ignore_case", False))
    flags = re.IGNORECASE if ignore_case else 0
    if "pattern" in raw and "patterns" in raw:
        raise RuleError(f"rule {name!r}: use either 'pattern' or 'patterns', not both")
    patterns = _compile_list(raw.get("pattern", raw.get("patterns")), rule=name, key="pattern", flags=flags)
    exclude = _compile_list(raw.get("exclude"), rule=name, key="exclude", flags=flags)
    conditions: list[Condition] = []
    json_spec = raw.get("json")
    if json_spec is not None:
        if not isinstance(json_spec, Mapping) or not json_spec:
            raise RuleError(f"rule {name!r}: 'json' must be a mapping of field: condition")
        for path, spec in json_spec.items():
            try:
                conditions.extend(Condition.parse(str(path), spec))
            except RuleError as exc:
                raise RuleError(f"rule {name!r}: {exc}") from exc
    if not patterns and not conditions:
        raise RuleError(f"rule {name!r}: needs a 'pattern' and/or 'json' conditions")

    count, window = 1, 60.0
    threshold = raw.get("threshold")
    if threshold is not None:
        if isinstance(threshold, int) and not isinstance(threshold, bool):
            count = threshold
        elif isinstance(threshold, Mapping):
            count = threshold.get("count", 1)
            try:
                window = parse_duration(threshold.get("window", 60), field=f"rule {name!r} threshold.window")
            except ValueError as exc:
                raise RuleError(str(exc)) from exc
        else:
            raise RuleError(f"rule {name!r}: threshold must be a number or {{count: N, window: 5m}}")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RuleError(f"rule {name!r}: threshold.count must be a positive integer")
        if window <= 0:
            raise RuleError(f"rule {name!r}: threshold.window must be positive")
    try:
        cooldown = parse_duration(raw.get("cooldown", default_cooldown), field=f"rule {name!r} cooldown")
    except ValueError as exc:
        raise RuleError(str(exc)) from exc

    severity = str(raw.get("severity", "error")).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"rule {name!r}: severity must be one of {', '.join(SEVERITIES)}")
    sources = raw.get("sources") or []
    if isinstance(sources, str):
        sources = [sources]
    if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
        raise RuleError(f"rule {name!r}: sources must be a list of source names or globs")
    notify = raw.get("notify")
    if isinstance(notify, str):
        notify = [notify]
    if notify is not None and (not isinstance(notify, list) or not all(isinstance(n, str) for n in notify)):
        raise RuleError(f"rule {name!r}: notify must be a list of notifier names")
    templates = {}
    for key, default in (("title", DEFAULT_TITLE), ("message", DEFAULT_MESSAGE), ("group_by", "")):
        value = raw.get(key, default)
        if not isinstance(value, str):
            raise RuleError(f"rule {name!r}: {key} must be a string")
        try:
            templating.validate(value)
        except templating.TemplateError as exc:
            raise RuleError(f"rule {name!r}: {key}: {exc}") from exc
        templates[key] = value
    return Rule(
        name=name.strip(),
        patterns=patterns,
        exclude=exclude,
        conditions=conditions,
        sources=list(sources),
        count=count,
        window=window,
        cooldown=cooldown,
        group_by=templates["group_by"],
        severity=severity,
        notify=list(notify) if notify is not None else None,
        title=templates["title"],
        message=templates["message"],
        description=str(raw.get("description", "")),
        pack=pack,
        ignore_case=ignore_case,
    )
