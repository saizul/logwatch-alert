"""Turn matching lines into alerts: sliding-window thresholds, grouping and cooldowns."""

from __future__ import annotations

import json
import re
import socket
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from logwatch_alert import templating
from logwatch_alert.durations import format_duration
from logwatch_alert.rules import Match, Rule

MAX_SAMPLES = 5


@dataclass
class Alert:
    rule: str
    severity: str
    title: str
    message: str
    group: str
    count: int
    source: str
    line: str
    samples: list[str]
    first_seen: float
    last_seen: float
    suppressed: int
    notify: list[str] | None
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "group": self.group,
            "count": self.count,
            "source": self.source,
            "line": self.line,
            "samples": list(self.samples),
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "suppressed": self.suppressed,
            "hostname": self.context.get("hostname", ""),
            "captures": self.context.get("captures", {}),
            "fields": self.context.get("fields"),
        }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class _GroupState:
    hits: deque[float] = field(default_factory=deque)
    samples: deque[tuple[float, str]] = field(default_factory=lambda: deque(maxlen=MAX_SAMPLES))
    last_fired: float | None = None
    suppressed: int = 0
    last_seen: float = 0.0


def parse_json_line(line: str) -> Any:
    """Parse a JSON log line; returns ``None`` for non-JSON text."""
    text = line.strip()
    if not text.startswith("{"):
        # Tolerate a prefix such as a Docker timestamp or "web-1 | " before the object.
        start = text.find("{")
        if start == -1 or not text.endswith("}"):
            return None
        text = text[start:]
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


class Engine:
    """Feed lines with :meth:`process`; it returns the alerts that should be sent."""

    def __init__(
        self,
        rules: Iterable[Rule],
        *,
        hostname: str | None = None,
        clock: Callable[[], float] = time.time,
        max_groups: int = 10000,
    ) -> None:
        self.rules = list(rules)
        self.hostname = hostname or socket.gethostname()
        self.clock = clock
        self.max_groups = max_groups
        self._state: dict[str, dict[str, _GroupState]] = {rule.name: {} for rule in self.rules}
        self.lines_seen = 0
        self.alerts_fired = 0

    def process(
        self, source: str, line: str, *, path: str | None = None, fields: Any = None, parse_json: bool = True
    ) -> list[Alert]:
        now = self.clock()
        self.lines_seen += 1
        if fields is None and parse_json:
            fields = parse_json_line(line)
        alerts = []
        for rule in self.rules:
            found = rule.match(source, line, fields, path=path)
            if found is not None:
                alert = self._hit(rule, found, source, line, now, path)
                if alert is not None:
                    alerts.append(alert)
        return alerts

    def _context(self, rule: Rule, found: Match, source: str, line: str, path: str | None) -> dict[str, Any]:
        ctx: dict[str, Any] = {}
        if isinstance(found.fields, dict):
            ctx.update({k: v for k, v in found.fields.items() if isinstance(k, str) and k.isidentifier()})
        ctx.update(found.captures)
        ctx.update(
            {
                "rule": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "source": source,
                "source_path": path or source,
                "line": line,
                "hostname": self.hostname,
                "captures": found.captures,
                "fields": found.fields,
            }
        )
        return ctx

    def _hit(self, rule: Rule, found: Match, source: str, line: str, now: float, path: str | None) -> Alert | None:
        ctx = self._context(rule, found, source, line, path)
        group = templating.render(rule.group_by, ctx).strip() if rule.group_by else ""
        groups = self._state[rule.name]
        state = groups.get(group)
        if state is None:
            if len(groups) >= self.max_groups:
                self._prune_rule(rule, now, force=True)
            state = groups[group] = _GroupState()
        state.last_seen = now
        if state.last_fired is not None and now - state.last_fired < rule.cooldown:
            state.suppressed += 1
            return None
        state.hits.append(now)
        state.samples.append((now, line))
        cutoff = now - rule.window
        while state.hits and state.hits[0] < cutoff:
            state.hits.popleft()
        while state.samples and state.samples[0][0] < cutoff:
            state.samples.popleft()
        if len(state.hits) < rule.count:
            return None
        first = state.hits[0]
        count = len(state.hits)
        samples = [text for _, text in state.samples]
        suppressed = state.suppressed
        state.hits.clear()
        state.samples.clear()
        state.suppressed = 0
        state.last_fired = now
        self.alerts_fired += 1
        ctx.update(
            {
                "group": group,
                "group_suffix": f" ({group})" if group else "",
                "count": count,
                "threshold": rule.count,
                "window": int(rule.window),
                "window_human": format_duration(rule.window) if rule.count > 1 else "1 line",
                "cooldown_human": format_duration(rule.cooldown),
                "first_seen": _iso(first),
                "last_seen": _iso(now),
                "time": _iso(now),
                "samples": "\n".join(samples),
                "suppressed": suppressed,
                "suppressed_note": (
                    f"({suppressed} more match(es) were suppressed by the cooldown since the last alert)\n"
                    if suppressed
                    else ""
                ),
            }
        )
        ctx["title"] = _one_line(templating.render(rule.title, ctx))
        ctx["message"] = templating.render(rule.message, ctx).strip()
        return Alert(
            rule=rule.name,
            severity=rule.severity,
            title=ctx["title"],
            message=ctx["message"],
            group=group,
            count=count,
            source=source,
            line=line,
            samples=samples,
            first_seen=first,
            last_seen=now,
            suppressed=suppressed,
            notify=rule.notify,
            context=ctx,
        )

    def _prune_rule(self, rule: Rule, now: float, *, force: bool = False) -> None:
        groups = self._state[rule.name]
        for key, state in list(groups.items()):
            idle = now - state.last_seen
            cooling = state.last_fired is not None and now - state.last_fired < rule.cooldown
            if idle > rule.window and not cooling:
                del groups[key]
        if force and len(groups) >= self.max_groups:
            # Still full: forget the least recently seen groups.
            for key in sorted(groups, key=lambda k: groups[k].last_seen)[: max(len(groups) // 10, 1)]:
                del groups[key]

    def prune(self) -> None:
        """Forget idle groups (e.g. one-off IP addresses) to keep memory bounded."""
        now = self.clock()
        for rule in self.rules:
            self._prune_rule(rule, now)

    def group_count(self) -> int:
        return sum(len(groups) for groups in self._state.values())


_WS = re.compile(r"\s+")


def _one_line(text: str) -> str:
    return _WS.sub(" ", text).strip()
