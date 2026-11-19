from pathlib import Path

import pytest

from logwatch_alert.config import ConfigError, expand_env, load_config, load_pack, parse_config

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_expand_env():
    env = {"A": "1", "TOKEN": "secret"}
    data = {"x": "${A}", "y": ["pre-${TOKEN}-post", "${MISSING:-fallback}", "${EMPTY:-}"], "z": 5, "lit": "$${A}"}
    assert expand_env(data, env) == {"x": "1", "y": ["pre-secret-post", "fallback", ""], "z": 5, "lit": "${A}"}


def test_missing_env_names_the_variable_not_a_value():
    with pytest.raises(ConfigError, match=r"notifiers\.tg\.bot_token: environment variable TG_TOKEN is not set"):
        parse_config({"notifiers": {"tg": {"type": "telegram", "bot_token": "${TG_TOKEN}", "chat_id": 1}}}, env={})


def test_example_configs_are_valid():
    env = {"TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "1", "SLACK_WEBHOOK_URL": "https://hooks.invalid/x"}
    import os

    old = dict(os.environ)
    os.environ.update(env)
    try:
        config = load_config(EXAMPLES / "config.yaml")
        stdin_config = load_config(EXAMPLES / "docker-logs.yaml")
    finally:
        os.environ.clear()
        os.environ.update(old)
    names = {r.name for r in config.rules}
    assert {"nginx-5xx-spike", "ssh-brute-force", "oom-kill", "php-fatal-error", "app-5xx", "disk-full"} <= names
    php = next(r for r in config.rules if r.name == "php-fpm-max-children")
    assert (php.severity, php.cooldown, php.sources) == ("error", 3600, ["php", "nginx-error"])
    assert set(config.notifiers) == {"telegram", "slack", "discord", "pager", "email"}
    assert config.sources[-1].format == "json"
    assert stdin_config.sources[0].stdin
    assert stdin_config.sources[0].strip.sub("", "web-1  | hello", count=1) == "hello"
    assert stdin_config.sources[0].strip.sub("", "2026-11-19T03:12:01.123456789Z hello", count=1) == "hello"


def test_sources_parsing():
    config = parse_config({"sources": ["/var/log/a.log", {"stdin": True, "name": "docker"}]})
    assert [(s.name, s.path, s.stdin) for s in config.sources] == [
        ("/var/log/a.log", "/var/log/a.log", False),
        ("docker", None, True),
    ]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "mapping"),
        ({"rulez": []}, "unknown top-level"),
        ({"sources": [{"path": "/a", "stdin": True}]}, "exactly one"),
        ({"sources": [{"stdin": True}, {"stdin": True, "name": "b"}]}, "only one source"),
        ({"sources": ["/a", "/a"]}, "duplicate source"),
        ({"sources": [{"path": "/a", "format": "xml"}]}, "format"),
        ({"sources": [{"path": "/a", "strip": "("}]}, "strip"),
        ({"settings": {"start_at": "middle"}}, "start_at"),
        ({"settings": {"poll_interval": "fast"}}, "poll_interval"),
        ({"settings": {"nope": 1}}, "unknown key"),
        ({"settings": {"retries": 99}}, "retries"),
        ({"packs": ["apache"]}, "unknown rule pack"),
        ({"packs": [{"name": "ssh", "disable": ["nope"]}]}, "no rule named"),
        ({"packs": [{"name": "ssh", "colour": 1}]}, "unknown key"),
        ({"rules": [{"name": "a", "pattern": "x"}, {"name": "a", "pattern": "y"}]}, "duplicate rule"),
        ({"packs": ["ssh", "ssh"]}, "duplicate rule"),
        ({"rules": [{"name": "a", "pattern": "x", "notify": ["ghost"]}]}, "unknown notifier"),
        ({"settings": {"default_notify": ["ghost"]}}, "unknown notifier"),
        ({"notifiers": {"x": {"type": "fax"}}}, "type must be"),
    ],
)
def test_config_errors(data, message):
    with pytest.raises(ConfigError, match=message):
        parse_config(data, env={})


def test_disabled_rules_are_skipped():
    config = parse_config({"rules": [{"name": "a", "pattern": "x", "enabled": False}, {"name": "b", "pattern": "y"}]})
    assert [r.name for r in config.rules] == ["b"]


def test_pack_options():
    rules = load_pack(
        {"name": "ssh", "notify": ["tg"], "sources": ["auth"], "disable": ["ssh-root-login"]}, default_cooldown=60
    )
    assert [r.name for r in rules] == ["ssh-brute-force"]
    assert rules[0].notify == ["tg"] and rules[0].sources == ["auth"]


def test_custom_pack_file(tmp_path):
    pack = tmp_path / "mine.yaml"
    pack.write_text("rules:\n  - name: mine\n    pattern: boom\n", encoding="utf-8")
    (rule,) = load_pack(str(pack), default_cooldown=60)
    assert (rule.name, rule.pack, rule.cooldown) == ("mine", "mine", 60)
    pack.write_text("nope: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="'rules' list"):
        load_pack(str(pack), default_cooldown=60)


def test_load_config_errors(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(bad)
