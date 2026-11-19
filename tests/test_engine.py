from logwatch_alert.engine import Engine, parse_json_line
from logwatch_alert.rules import parse_rule


def make(clock, **raw):
    raw.setdefault("name", "r")
    raw.setdefault("pattern", "ERROR")
    return Engine([parse_rule(raw)], hostname="host1", clock=clock)


def test_single_match_fires_with_rendered_title(clock):
    engine = make(clock, severity="critical")
    (alert,) = engine.process("app", "ERROR disk full")
    assert alert.title == "[CRITICAL] r on host1"
    assert "ERROR disk full" in alert.message
    assert alert.count == 1
    assert alert.to_dict()["hostname"] == "host1"


def test_threshold_in_sliding_window(clock):
    engine = make(clock, threshold={"count": 3, "window": "1m"}, cooldown=0)
    assert engine.process("app", "ERROR 1") == []
    clock.advance(20)
    assert engine.process("app", "ERROR 2") == []
    clock.advance(50)  # the first hit is now outside the window
    assert engine.process("app", "ERROR 3") == []
    clock.advance(5)
    (alert,) = engine.process("app", "ERROR 4")
    assert alert.count == 3
    assert alert.samples == ["ERROR 2", "ERROR 3", "ERROR 4"]
    assert "3 match(es) in 1m" in alert.message
    # The window resets after firing.
    assert engine.process("app", "ERROR 5") == []


def test_cooldown_suppresses_and_reports_count(clock):
    engine = make(clock, cooldown="10m")
    assert len(engine.process("app", "ERROR a")) == 1
    for _ in range(4):
        clock.advance(60)
        assert engine.process("app", "ERROR b") == []
    clock.advance(400)  # 640s after the alert
    (alert,) = engine.process("app", "ERROR c")
    assert alert.suppressed == 4
    assert "4 more match(es) were suppressed" in alert.message


def test_group_by_keeps_separate_windows_and_cooldowns(clock):
    engine = make(
        clock,
        pattern=r"fail from (?P<ip>\S+)",
        threshold={"count": 2, "window": "5m"},
        group_by="{{ ip }}",
        cooldown="1h",
    )
    assert engine.process("ssh", "fail from 1.1.1.1") == []
    assert engine.process("ssh", "fail from 2.2.2.2") == []
    (alert,) = engine.process("ssh", "fail from 1.1.1.1")
    assert alert.group == "1.1.1.1"
    assert "(1.1.1.1)" in alert.message
    assert engine.process("ssh", "fail from 1.1.1.1") == []  # cooling down
    (other,) = engine.process("ssh", "fail from 2.2.2.2")
    assert other.group == "2.2.2.2"


def test_dedupe_identical_lines_with_group_by_line(clock):
    engine = make(clock, group_by="{{ line }}", cooldown="1h")
    assert len(engine.process("a", "ERROR x")) == 1
    assert engine.process("a", "ERROR x") == []
    assert len(engine.process("a", "ERROR y")) == 1


def test_json_fields_available_in_templates(clock):
    engine = Engine(
        [
            parse_rule(
                {
                    "name": "api-5xx",
                    "json": {"status": {"gte": 500}, "path": {"regex": "^/api"}},
                    "message": "{{ status }} on {{ path }} ({{ fields.req.id }})",
                }
            )
        ],
        clock=clock,
    )
    line = '{"status": 503, "path": "/api/orders", "req": {"id": "abc"}}'
    (alert,) = engine.process("app", line)
    assert alert.message == "503 on /api/orders (abc)"
    assert engine.process("app", '{"status": 200, "path": "/api"}') == []
    assert engine.process("app", "not json 503") == []


def test_multiple_rules_can_fire_on_one_line(clock):
    engine = Engine([parse_rule({"name": "a", "pattern": "x"}), parse_rule({"name": "b", "pattern": "x"})], clock=clock)
    assert [a.rule for a in engine.process("s", "x")] == ["a", "b"]


def test_prune_forgets_idle_groups_but_keeps_cooling_ones(clock):
    engine = make(
        clock, pattern=r"ip=(?P<ip>\S+)", group_by="{{ ip }}", threshold={"count": 5, "window": "1m"}, cooldown="1h"
    )
    for i in range(50):
        engine.process("s", f"ip=10.0.0.{i}")
    for _ in range(5):
        engine.process("s", "ip=9.9.9.9")
    assert engine.group_count() == 51
    clock.advance(120)
    engine.prune()
    assert engine.group_count() == 1  # 9.9.9.9 is still in its cooldown


def test_max_groups_bound(clock):
    engine = Engine(
        [parse_rule({"name": "r", "pattern": r"(?P<n>\d+)", "group_by": "{{ n }}", "threshold": 3})],
        clock=clock,
        max_groups=100,
    )
    for i in range(1000):
        engine.process("s", str(i))
    assert engine.group_count() <= 100


def test_parse_json_line():
    assert parse_json_line('{"a": 1}') == {"a": 1}
    assert parse_json_line('2024-01-01T00:00:00Z {"a": 1}') == {"a": 1}
    assert parse_json_line("[1, 2]") is None
    assert parse_json_line("{broken") is None
    assert parse_json_line("plain") is None
