import logging

import pytest

from logwatch_alert.engine import Engine
from logwatch_alert.notifiers import ConfigError, Dispatcher, NotifierError, build_notifier
from logwatch_alert.rules import parse_rule

BOT_TOKEN = "123456:test-telegram-token"
SLACK_URL = "https://hooks.slack.invalid/services/T000/B000/test-slack-secret"


@pytest.fixture
def alert(clock):
    engine = Engine(
        [parse_rule({"name": "disk", "pattern": r"disk (?P<dev>\S+) full", "severity": "critical"})],
        hostname="web1",
        clock=clock,
    )
    (found,) = engine.process("syslog", "disk /dev/sda1 full")
    return found


def test_telegram(recorder, alert):
    notifier = build_notifier(
        "tg", {"type": "telegram", "bot_token": BOT_TOKEN, "chat_id": -1001}, client=recorder.client()
    )
    notifier.send(alert)
    request = recorder.requests[0]
    assert str(request.url) == f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    body = recorder.json()
    assert body["chat_id"] == "-1001"
    assert body["text"].startswith("[CRITICAL] disk on web1\n\n")
    assert "disk /dev/sda1 full" in body["text"]
    assert "disable_notification" not in body


def test_telegram_quiet_for_info(recorder, clock):
    engine = Engine([parse_rule({"name": "n", "pattern": "x", "severity": "info"})], clock=clock)
    (info,) = engine.process("s", "x")
    notifier = build_notifier(
        "tg", {"type": "telegram", "bot_token": BOT_TOKEN, "chat_id": "1"}, client=recorder.client()
    )
    notifier.send(info)
    assert recorder.json()["disable_notification"] is True


def test_slack(recorder, alert):
    notifier = build_notifier(
        "slack", {"type": "slack", "webhook_url": SLACK_URL, "channel": "#ops"}, client=recorder.client()
    )
    notifier.send(alert)
    body = recorder.json()
    assert str(recorder.requests[0].url) == SLACK_URL
    assert body["text"].startswith("*[CRITICAL] disk on web1*")
    assert body["blocks"][0]["text"]["text"] == "[CRITICAL] disk on web1"
    assert body["channel"] == "#ops"


def test_discord(recorder, alert):
    notifier = build_notifier(
        "dc", {"type": "discord", "webhook_url": "https://discord.invalid/api/webhooks/1/x"}, client=recorder.client()
    )
    notifier.send(alert)
    embed = recorder.json()["embeds"][0]
    assert embed["title"] == "[CRITICAL] disk on web1"
    assert embed["color"] == 0xE74C3C
    assert embed["timestamp"].endswith("Z")
    assert recorder.json()["allowed_mentions"] == {"parse": []}


def test_webhook_default_json(recorder, alert):
    notifier = build_notifier(
        "hook",
        {"type": "webhook", "url": "https://example.invalid/alerts", "headers": {"Authorization": "Bearer t"}},
        client=recorder.client(),
    )
    notifier.send(alert)
    request = recorder.requests[0]
    assert request.method == "POST"
    assert request.headers["Authorization"] == "Bearer t"
    assert request.headers["Content-Type"] == "application/json"
    body = recorder.json()
    assert body["rule"] == "disk"
    assert body["captures"] == {"dev": "/dev/sda1"}
    assert body["hostname"] == "web1"


def test_webhook_custom_body_template(recorder, alert):
    notifier = build_notifier(
        "hook",
        {
            "type": "webhook",
            "url": "https://example.invalid/alerts",
            "method": "put",
            "body": '{"summary": {{ title | json }}, "device": {{ dev | json }}}',
        },
        client=recorder.client(),
    )
    notifier.send(alert)
    assert recorder.requests[0].method == "PUT"
    assert recorder.json() == {"summary": "[CRITICAL] disk on web1", "device": "/dev/sda1"}


def test_notifier_message_override(recorder, alert):
    notifier = build_notifier(
        "slack",
        {"type": "slack", "webhook_url": SLACK_URL, "title": "{{ rule }}!", "message": "dev={{ dev }}"},
        client=recorder.client(),
    )
    notifier.send(alert)
    assert recorder.json()["text"] == "*disk!*\ndev=/dev/sda1"


def test_email(fake_smtp, alert):
    notifier = build_notifier(
        "mail",
        {
            "type": "email",
            "host": "smtp.example.invalid",
            "username": "alerts",
            "password": "test-password",
            "from": "alerts@example.invalid",
            "to": ["ops@example.invalid", "dev@example.invalid"],
            "subject_prefix": "[prod] ",
        },
        smtp_factory=fake_smtp,
    )
    notifier.send(alert)
    (smtp,) = fake_smtp.instances
    assert (smtp.host, smtp.port, smtp.started_tls) == ("smtp.example.invalid", 587, True)
    assert smtp.login_args == ("alerts", "test-password")
    (msg,) = smtp.messages
    assert msg["Subject"] == "[prod] [CRITICAL] disk on web1"
    assert msg["To"] == "ops@example.invalid, dev@example.invalid"
    assert msg["X-Logwatch-Rule"] == "disk"
    assert "disk /dev/sda1 full" in msg.get_content()


def test_email_ssl_defaults_port(fake_smtp):
    notifier = build_notifier(
        "mail",
        {"type": "email", "host": "h", "ssl": True, "from": "a@b.invalid", "to": "c@d.invalid"},
        smtp_factory=fake_smtp,
    )
    assert (notifier.port, notifier.starttls) == (465, False)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"type": "pager"}, "type must be one of"),
        ({"type": "telegram", "chat_id": 1}, "bot_token"),
        ({"type": "telegram", "bot_token": "x"}, "chat_id"),
        ({"type": "slack"}, "webhook_url"),
        ({"type": "slack", "webhook_url": "u", "colour": "red"}, "unknown key"),
        ({"type": "webhook", "url": "u", "method": "GET"}, "method"),
        ({"type": "webhook", "url": "u", "body": "{{ x | nope }}"}, "unknown filter"),
        ({"type": "email", "host": "h", "from": "a@b", "to": "nobody"}, "'to'"),
        ({"type": "email", "host": "h", "from": "a@b", "to": "c@d", "username": "u"}, "both username"),
        ({"type": "email", "host": "h", "from": "a@b", "to": "c@d", "ssl": True, "starttls": True}, "either"),
        ({"type": "slack", "webhook_url": "u", "min_severity": "huge"}, "min_severity"),
        ({"type": "slack", "webhook_url": "u", "timeout": 0}, "timeout"),
    ],
)
def test_notifier_config_errors(options, message):
    with pytest.raises(ConfigError, match=message):
        build_notifier("n", options)


def test_errors_never_contain_the_url_or_token(recorder, alert, caplog):
    recorder.status = 403
    notifier = build_notifier(
        "tg", {"type": "telegram", "bot_token": BOT_TOKEN, "chat_id": "1"}, client=recorder.client()
    )
    with pytest.raises(NotifierError) as info:
        notifier.send(alert)
    assert "403" in str(info.value)
    assert BOT_TOKEN not in str(info.value)
    recorder.raise_error = True
    with pytest.raises(NotifierError) as info:
        notifier.send(alert)
    assert str(info.value) == "telegram request failed: ConnectError"
    dispatcher = Dispatcher({"tg": notifier}, retries=0)
    with caplog.at_level(logging.DEBUG):
        dispatcher.send(alert)
    assert BOT_TOKEN not in caplog.text


def test_dispatcher_retries_with_backoff(recorder, alert):
    recorder.fail_times = 2
    sleeps = []
    notifier = build_notifier("s", {"type": "slack", "webhook_url": SLACK_URL}, client=recorder.client())
    dispatcher = Dispatcher({"s": notifier}, retries=2, backoff=1.5, sleep=sleeps.append)
    assert dispatcher.send(alert) == {"s": True}
    assert len(recorder.requests) == 3
    assert sleeps == [1.5, 3.0]
    recorder.fail_times = 5
    assert dispatcher.send(alert) == {"s": False}
    assert dispatcher.failed == 1


def test_dispatcher_routing_and_min_severity(recorder, clock):
    a = build_notifier("a", {"type": "slack", "webhook_url": "https://a.invalid/x"}, client=recorder.client())
    b = build_notifier(
        "b", {"type": "slack", "webhook_url": "https://b.invalid/x", "min_severity": "error"}, client=recorder.client()
    )
    engine = Engine(
        [
            parse_rule({"name": "warn", "pattern": "warn", "severity": "warning"}),
            parse_rule({"name": "only-a", "pattern": "only", "notify": ["a"], "severity": "critical"}),
            parse_rule({"name": "ghost", "pattern": "ghost", "notify": ["missing"]}),
        ],
        clock=clock,
    )
    dispatcher = Dispatcher({"a": a, "b": b})
    (warn,) = engine.process("s", "warn")
    assert dispatcher.send(warn) == {"a": True}  # b only wants error and above
    (only,) = engine.process("s", "only")
    assert dispatcher.send(only) == {"a": True}
    (ghost,) = engine.process("s", "ghost")
    assert dispatcher.send(ghost) == {"missing": False}
    dispatcher.default_notify = ["b"]
    clock.advance(10_000)
    (warn,) = engine.process("s", "warn")
    assert dispatcher.send(warn) == {}


def test_dispatcher_survives_a_crashing_notifier(alert, caplog):
    class Boom:
        name = "boom"
        type = "boom"
        _client = None

        def wants(self, alert):
            return True

        def send(self, alert):
            raise RuntimeError("bug")

    dispatcher = Dispatcher({"boom": Boom()}, retries=3, sleep=lambda s: None)
    assert dispatcher.send(alert) == {"boom": False}
    assert "crashed" in caplog.text


def test_dispatcher_dry_run_prints_json(alert):
    printed = []
    dispatcher = Dispatcher({}, dry_run=True, printer=printed.append)
    assert dispatcher.send(alert) == {}
    assert '"rule": "disk"' in printed[0]


def test_background_worker_delivers(recorder, alert):
    notifier = build_notifier("s", {"type": "slack", "webhook_url": SLACK_URL}, client=recorder.client())
    dispatcher = Dispatcher({"s": notifier}).start()
    dispatcher.submit(alert)
    dispatcher.submit(alert)
    dispatcher.stop()
    assert len(recorder.requests) == 2
    assert dispatcher.sent == 2


def test_ntfy_maps_severity_to_priority(recorder, alert):
    notifier = build_notifier(
        "push", {"type": "ntfy", "topic": "ops-alerts", "tags": "server, prod"}, client=recorder.client()
    )
    notifier.send(alert)
    request = recorder.requests[0]
    assert str(request.url) == "https://ntfy.sh/"
    assert "authorization" not in request.headers
    body = recorder.json()
    assert body["topic"] == "ops-alerts"
    assert body["title"] == "[CRITICAL] disk on web1"
    assert "disk /dev/sda1 full" in body["message"]
    assert body["priority"] == 5
    assert body["tags"] == ["server", "prod", "critical"]


def test_ntfy_self_hosted_with_token_and_fixed_priority(recorder, alert):
    notifier = build_notifier(
        "push",
        {
            "type": "ntfy",
            "topic": "alerts",
            "server": "https://ntfy.example.invalid/",
            "token": "tk_test",
            "priority": 2,
            "click": "https://grafana.example.invalid",
        },
        client=recorder.client(),
    )
    notifier.send(alert)
    request = recorder.requests[0]
    assert str(request.url) == "https://ntfy.example.invalid/"
    assert request.headers["authorization"] == "Bearer tk_test"
    assert recorder.json()["priority"] == 2
    assert recorder.json()["click"] == "https://grafana.example.invalid"


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({}, "'topic' is required"),
        ({"topic": "a/b"}, "topic must be a plain name"),
        ({"topic": "t", "server": "ntfy.sh"}, "server must be an http\\(s\\) URL"),
        ({"topic": "t", "priority": 9}, "priority must be an integer from 1 to 5"),
        ({"topic": "t", "priority": True}, "priority must be an integer from 1 to 5"),
        ({"topic": "t", "tags": [1]}, "tags must be a list of strings"),
        ({"topic": "t", "token": ""}, "token must be a non-empty string"),
    ],
)
def test_ntfy_config_errors(options, message):
    with pytest.raises(ConfigError, match=message):
        build_notifier("push", {"type": "ntfy", **options})


def test_ntfy_error_does_not_leak_token(recorder, alert):
    recorder.status = 403
    notifier = build_notifier("push", {"type": "ntfy", "topic": "t", "token": "tk_test"}, client=recorder.client())
    with pytest.raises(NotifierError) as info:
        notifier.send(alert)
    assert "HTTP 403" in str(info.value) and "tk_test" not in str(info.value)
