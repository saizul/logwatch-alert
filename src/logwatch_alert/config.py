"""Load and validate ``config.yaml``: sources, settings, rule packs, rules and notifiers."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from logwatch_alert.durations import parse_duration
from logwatch_alert.notifiers import ConfigError as NotifierConfigError
from logwatch_alert.notifiers import Notifier, build_notifier
from logwatch_alert.rules import Rule, RuleError, parse_rule


class ConfigError(ValueError):
    """The configuration is invalid. Messages never include secret values."""


_ENV = re.compile(r"\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: Any, env: dict[str, str] | None = None, *, where: str = "config") -> Any:
    """Replace ``${VAR}`` and ``${VAR:-default}`` in every string; ``$$`` is a literal ``$``."""
    env = os.environ if env is None else env  # type: ignore[assignment]
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            if match.group(0) == "$$":
                return "$"
            name, default = match.group(1), match.group(2)
            if name in env:
                return env[name]
            if default is not None:
                return default
            raise ConfigError(f"{where}: environment variable {name} is not set")

        return _ENV.sub(replace, value)
    if isinstance(value, list):
        return [expand_env(item, env, where=f"{where}[{i}]") for i, item in enumerate(value)]
    if isinstance(value, dict):
        return {k: expand_env(v, env, where=f"{where}.{k}") for k, v in value.items()}
    return value


@dataclass
class Source:
    name: str
    path: str | None = None
    stdin: bool = False
    format: str = "auto"  # auto | json | text
    strip: re.Pattern[str] | None = None


@dataclass
class Settings:
    poll_interval: float = 1.0
    glob_refresh: float = 10.0
    start_at: str = "end"
    default_cooldown: float = 600.0
    hostname: str | None = None
    heartbeat_file: str | None = None
    default_notify: list[str] | None = None
    retries: int = 2


@dataclass
class Config:
    sources: list[Source] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)
    rules: list[Rule] = field(default_factory=list)
    notifiers: dict[str, Notifier] = field(default_factory=dict)


# Rule packs ------------------------------------------------------------------


def available_packs() -> list[str]:
    root = resources.files("logwatch_alert") / "packs"
    return sorted(p.name.removesuffix(".yaml") for p in root.iterdir() if p.name.endswith(".yaml"))


def read_pack(name: str) -> tuple[str, str]:
    """Return ``(pack_name, yaml_text)`` for a built-in pack or a path to a YAML file."""
    if name.endswith((".yaml", ".yml")) or os.sep in name or "/" in name:
        path = Path(name).expanduser()
        try:
            return path.stem, path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read rule pack {name}: {exc.strerror or exc}") from exc
    resource = resources.files("logwatch_alert") / "packs" / f"{name}.yaml"
    if not resource.is_file():
        raise ConfigError(f"unknown rule pack {name!r} (built-in packs: {', '.join(available_packs())})")
    return name, resource.read_text(encoding="utf-8")


def load_pack(spec: Any, *, default_cooldown: float) -> list[Rule]:
    """``spec`` is a pack name or ``{name, sources, notify, severity, disable, overrides}``."""
    if isinstance(spec, str):
        spec = {"name": spec}
    if not isinstance(spec, dict) or not isinstance(spec.get("name"), str):
        raise ConfigError("each entry in 'packs' must be a pack name or a mapping with 'name'")
    allowed = {"name", "sources", "notify", "severity", "disable", "overrides"}
    unknown = set(spec) - allowed
    if unknown:
        raise ConfigError(f"pack {spec['name']!r}: unknown key(s) {', '.join(sorted(unknown))}")
    pack_name, text = read_pack(spec["name"])
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"rule pack {pack_name}: invalid YAML: {exc}") from exc
    raw_rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(raw_rules, list):
        raise ConfigError(f"rule pack {pack_name}: expected a top-level 'rules' list")
    disable = set(spec.get("disable") or [])
    overrides = spec.get("overrides") or {}
    if not isinstance(overrides, dict):
        raise ConfigError(f"pack {pack_name}: overrides must map rule names to settings")
    names = {r.get("name") for r in raw_rules if isinstance(r, dict)}
    for unknown_rule in (set(overrides) | disable) - names:
        raise ConfigError(f"pack {pack_name}: no rule named {unknown_rule!r} (rules: {', '.join(sorted(names))})")
    rules = []
    for raw in raw_rules:
        if raw.get("name") in disable:
            continue
        merged = dict(raw)
        for key in ("sources", "notify", "severity"):
            if key in spec:
                merged[key] = spec[key]
        merged.update(overrides.get(raw.get("name"), {}) or {})
        try:
            rules.append(parse_rule(merged, pack=pack_name, default_cooldown=default_cooldown))
        except RuleError as exc:
            raise ConfigError(f"pack {pack_name}: {exc}") from exc
    return rules


# Main config -----------------------------------------------------------------


def _parse_sources(raw: Any) -> list[Source]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError("'sources' must be a list")
    sources: list[Source] = []
    for i, item in enumerate(raw):
        if isinstance(item, str):
            item = {"path": item}
        if not isinstance(item, dict):
            raise ConfigError(f"sources[{i}] must be a path or a mapping")
        unknown = set(item) - {"path", "stdin", "name", "format", "strip"}
        if unknown:
            raise ConfigError(f"sources[{i}]: unknown key(s) {', '.join(sorted(unknown))}")
        path, stdin = item.get("path"), bool(item.get("stdin", False))
        if bool(path) == stdin:
            raise ConfigError(f"sources[{i}]: set exactly one of 'path' or 'stdin: true'")
        if path is not None and not isinstance(path, str):
            raise ConfigError(f"sources[{i}]: path must be a string")
        fmt = str(item.get("format", "auto"))
        if fmt not in ("auto", "json", "text"):
            raise ConfigError(f"sources[{i}]: format must be auto, json or text")
        strip = None
        if item.get("strip"):
            try:
                strip = re.compile(str(item["strip"]))
            except re.error as exc:
                raise ConfigError(f"sources[{i}]: invalid strip regex: {exc}") from exc
        name = str(item.get("name") or ("stdin" if stdin else path))
        if any(s.name == name for s in sources):
            raise ConfigError(f"sources[{i}]: duplicate source name {name!r}")
        sources.append(Source(name=name, path=path, stdin=stdin, format=fmt, strip=strip))
    if sum(s.stdin for s in sources) > 1:
        raise ConfigError("only one source can read stdin")
    return sources


def _parse_settings(raw: Any) -> Settings:
    if raw is None:
        return Settings()
    if not isinstance(raw, dict):
        raise ConfigError("'settings' must be a mapping")
    known = set(Settings.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"settings: unknown key(s) {', '.join(sorted(unknown))}")
    s = Settings()
    try:
        for key in ("poll_interval", "glob_refresh", "default_cooldown"):
            if key in raw:
                setattr(s, key, parse_duration(raw[key], field=f"settings.{key}"))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if s.poll_interval <= 0 or s.glob_refresh <= 0:
        raise ConfigError("settings: poll_interval and glob_refresh must be positive")
    start_at = str(raw.get("start_at", "end"))
    if start_at not in ("end", "beginning"):
        raise ConfigError("settings.start_at must be 'end' or 'beginning'")
    s.start_at = start_at
    s.hostname = str(raw["hostname"]) if raw.get("hostname") else None
    s.heartbeat_file = str(raw["heartbeat_file"]) if raw.get("heartbeat_file") else None
    if "default_notify" in raw:
        dn = raw["default_notify"]
        if isinstance(dn, str):
            dn = [dn]
        if not isinstance(dn, list):
            raise ConfigError("settings.default_notify must be a list of notifier names")
        s.default_notify = [str(x) for x in dn]
    retries = raw.get("retries", 2)
    if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 10:
        raise ConfigError("settings.retries must be an integer between 0 and 10")
    s.retries = retries
    return s


def parse_config(
    data: Any, *, env: dict[str, str] | None = None, notifier_kwargs: dict[str, Any] | None = None
) -> Config:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError("the config file must contain a mapping")
    unknown = set(data) - {"sources", "settings", "packs", "rules", "notifiers"}
    if unknown:
        raise ConfigError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
    data = expand_env(data, env)
    config = Config(sources=_parse_sources(data.get("sources")), settings=_parse_settings(data.get("settings")))

    packs = data.get("packs") or []
    if not isinstance(packs, list):
        raise ConfigError("'packs' must be a list")
    for spec in packs:
        config.rules.extend(load_pack(spec, default_cooldown=config.settings.default_cooldown))
    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list):
        raise ConfigError("'rules' must be a list")
    for raw in raw_rules:
        if isinstance(raw, dict) and raw.get("enabled", True) is False:
            continue
        try:
            config.rules.append(parse_rule(raw, default_cooldown=config.settings.default_cooldown))
        except RuleError as exc:
            raise ConfigError(str(exc)) from exc
    seen: set[str] = set()
    for rule in config.rules:
        if rule.name in seen:
            raise ConfigError(f"duplicate rule name {rule.name!r}")
        seen.add(rule.name)

    raw_notifiers = data.get("notifiers") or {}
    if not isinstance(raw_notifiers, dict):
        raise ConfigError("'notifiers' must be a mapping of name: options")
    for name, options in raw_notifiers.items():
        try:
            config.notifiers[str(name)] = build_notifier(str(name), options, **(notifier_kwargs or {}))
        except NotifierConfigError as exc:
            raise ConfigError(str(exc)) from exc

    names = set(config.notifiers)
    referenced = list(config.settings.default_notify or [])
    for rule in config.rules:
        referenced.extend(rule.notify or [])
    missing = sorted(set(referenced) - names)
    if missing:
        configured = ", ".join(sorted(names)) or "none"
        raise ConfigError(f"unknown notifier(s) referenced: {', '.join(missing)} (configured: {configured})")
    return config


def load_config(path: str | os.PathLike[str], **kwargs: Any) -> Config:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror or exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    return parse_config(data, **kwargs)
