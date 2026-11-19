import pytest

from logwatch_alert.rules import Condition, RuleError, get_field, parse_rule


def test_pattern_captures_named_groups():
    rule = parse_rule({"name": "r", "pattern": r"user=(?P<user>\w+) code=(?P<code>\d+)"})
    found = rule.match("app", "login user=bob code=42")
    assert found is not None
    assert found.captures == {"user": "bob", "code": "42"}
    assert rule.match("app", "nothing here") is None


def test_pattern_list_first_match_wins():
    rule = parse_rule({"name": "r", "patterns": [r"A (?P<x>\d)", r"B (?P<y>\d)"]})
    assert rule.match("s", "B 7").captures == {"y": "7"}
    assert rule.match("s", "C 7") is None


def test_ignore_case_and_exclude():
    rule = parse_rule({"name": "r", "pattern": "error", "exclude": "healthcheck", "ignore_case": True})
    assert rule.match("s", "ERROR boom") is not None
    assert rule.match("s", "Error in healthcheck") is None


def test_sources_filter_by_name_or_path_glob():
    rule = parse_rule({"name": "r", "pattern": "x", "sources": ["nginx", "/var/log/app/*.log"]})
    assert rule.match("nginx", "x") is not None
    assert rule.match("other", "x") is None
    assert rule.match("app", "x", path="/var/log/app/web.log") is not None


@pytest.mark.parametrize(
    ("spec", "data", "expected"),
    [
        ("error", {"level": "error"}, True),
        ("error", {"level": "info"}, False),
        ({"in": ["error", "fatal"]}, {"level": "fatal"}, True),
        ({"not_in": ["debug"]}, {"level": "info"}, True),
        ({"not_in": ["debug"]}, {}, True),
        ({"not_equals": "info"}, {"level": "warn"}, True),
        ({"regex": "^err"}, {"level": "error"}, True),
        ({"contains": "rro"}, {"level": "error"}, True),
        ({"exists": True}, {"level": None}, True),
        ({"exists": False}, {"other": 1}, True),
        ({"exists": True}, {}, False),
    ],
)
def test_condition_ops_on_level(spec, data, expected):
    (cond,) = Condition.parse("level", spec)
    assert cond.check(data) is expected


def test_numeric_conditions_and_string_numbers():
    gte = Condition.parse("status", {"gte": 500})[0]
    assert gte.check({"status": 503})
    assert gte.check({"status": "502"})
    assert not gte.check({"status": 404})
    assert not gte.check({"status": "n/a"})
    assert not gte.check({"status": True})
    assert Condition.parse("status", 500)[0].check({"status": "500"})
    assert Condition.parse("d", {"lt": 1.5})[0].check({"d": 0.2})
    both = Condition.parse("ms", {"gt": 100, "lte": 200})
    assert all(c.check({"ms": 150}) for c in both)
    assert not all(c.check({"ms": 250}) for c in both)


def test_bool_equality_is_strict():
    cond = Condition.parse("ok", False)[0]
    assert cond.check({"ok": False})
    assert not cond.check({"ok": 0})


def test_contains_on_list():
    cond = Condition.parse("tags", {"contains": "db"})[0]
    assert cond.check({"tags": ["web", "db"]})
    assert not cond.check({"tags": ["web"]})


def test_get_field_nested_and_dotted_keys():
    data = {"http": {"status": 500, "headers": [{"k": "v"}]}, "log.level": "error"}
    assert get_field(data, "http.status") == 500
    assert get_field(data, "http.headers.0.k") == "v"
    assert get_field(data, "log.level") == "error"


def test_json_rule_requires_json_fields():
    rule = parse_rule({"name": "r", "json": {"level": "error", "status": {"gte": 500}}})
    assert rule.match("s", "plain text", None) is None
    assert rule.match("s", "{}", {"level": "error", "status": 502}) is not None
    assert rule.match("s", "{}", {"level": "error", "status": 200}) is None


def test_threshold_shorthand_and_mapping():
    assert parse_rule({"name": "a", "pattern": "x", "threshold": 3}).count == 3
    rule = parse_rule({"name": "b", "pattern": "x", "threshold": {"count": 5, "window": "2m"}, "cooldown": "1h"})
    assert (rule.count, rule.window, rule.cooldown) == (5, 120, 3600)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"pattern": "x"}, "name"),
        ({"name": "r"}, "needs a 'pattern'"),
        ({"name": "r", "pattern": "("}, "invalid pattern"),
        ({"name": "r", "pattern": "x", "patterns": ["y"]}, "either"),
        ({"name": "r", "pattern": "x", "severity": "loud"}, "severity"),
        ({"name": "r", "pattern": "x", "threshold": {"count": 0}}, "positive integer"),
        ({"name": "r", "pattern": "x", "threshold": "lots"}, "threshold"),
        ({"name": "r", "pattern": "x", "cooldown": "soon"}, "cooldown"),
        ({"name": "r", "pattern": "x", "colour": "red"}, "unknown key"),
        ({"name": "r", "json": {"level": {"like": "x"}}}, "unknown operator"),
        ({"name": "r", "json": {"level": {"in": "x"}}}, "needs a list"),
        ({"name": "r", "json": {"n": {"gt": "big"}}}, "needs a number"),
        ({"name": "r", "json": {"n": {"regex": "("}}}, "invalid regex"),
        ({"name": "r", "pattern": "x", "title": "{{ a | nope }}"}, "unknown filter"),
        ({"name": "r", "pattern": "x", "notify": [1]}, "notify"),
    ],
)
def test_parse_rule_errors(raw, message):
    with pytest.raises(RuleError, match=message):
        parse_rule(raw)
