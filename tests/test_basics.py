import pytest

from logwatch_alert import templating
from logwatch_alert.durations import format_duration, parse_duration


@pytest.mark.parametrize(
    ("text", "seconds"),
    [(30, 30), ("45", 45), ("30s", 30), ("5m", 300), ("1h30m", 5400), ("2d", 172800), ("1w", 604800), ("500ms", 0.5)],
)
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("bad", ["", "5 minutes", "m5", "-3", True, None, -1, "1h-"])
def test_parse_duration_rejects(bad):
    with pytest.raises(ValueError):
        parse_duration(bad)


def test_format_duration():
    assert format_duration(0) == "0s"
    assert format_duration(90) == "1m30s"
    assert format_duration(3600) == "1h"
    assert format_duration(90061) == "1d1h1m1s"


def test_render_variables_and_filters():
    ctx = {"name": "web", "count": 3, "fields": {"http": {"status": 502}}, "items": ["a", "b"], "flag": True}
    assert templating.render("{{ name | upper }} x{{count}}", ctx) == "WEB x3"
    assert templating.render("{{ fields.http.status }}", ctx) == "502"
    assert templating.render("{{ items.1 }}", ctx) == "b"
    assert templating.render("{{ missing }}|{{ missing | default('n/a') }}", ctx) == "|n/a"
    assert templating.render("{{ name | json }}", ctx) == '"web"'
    assert templating.render("{{ fields }}", ctx) == '{"http": {"status": 502}}'
    assert templating.render("{{ flag }}", ctx) == "true"
    assert templating.render("{{ name | truncate(2) }}", ctx) == "w…"


def test_render_cannot_reach_attributes():
    ctx = {"name": "web"}
    assert templating.render("{{ name.__class__ }}", ctx) == ""
    with pytest.raises(templating.TemplateError):
        templating.render("{{ name() }}", ctx)


def test_validate_rejects_unknown_filter():
    with pytest.raises(templating.TemplateError, match="unknown filter"):
        templating.validate("{{ name | shout }}")
    with pytest.raises(templating.TemplateError):
        templating.validate("{{ 1+1 }}")
