"""Alert senders: Telegram, Slack, Discord, ntfy, generic webhook and SMTP e-mail.

Notifier URLs often contain secrets (Telegram bot tokens, Slack/Discord webhook paths),
so errors are logged without the URL or the response body.
"""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, ClassVar

import httpx

from logwatch_alert import templating
from logwatch_alert.engine import Alert
from logwatch_alert.rules import SEVERITIES

log = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "debug": 0x95A5A6,
    "info": 0x3498DB,
    "warning": 0xF1C40F,
    "error": 0xE67E22,
    "critical": 0xE74C3C,
}


class NotifierError(Exception):
    """A notifier could not deliver an alert. The message never contains secrets."""


class ConfigError(ValueError):
    """Invalid notifier configuration."""


def _require(options: Mapping[str, Any], key: str, name: str) -> str:
    value = options.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"notifier {name!r}: '{key}' is required")
    return value.strip()


def _template(options: Mapping[str, Any], key: str, name: str) -> str | None:
    value = options.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"notifier {name!r}: '{key}' must be a string")
    try:
        templating.validate(value)
    except templating.TemplateError as exc:
        raise ConfigError(f"notifier {name!r}: {key}: {exc}") from exc
    return value


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Notifier:
    type: ClassVar[str] = ""
    allowed: ClassVar[frozenset[str]] = frozenset()
    common: ClassVar[frozenset[str]] = frozenset({"type", "message", "title", "min_severity", "timeout"})

    def __init__(self, name: str, options: Mapping[str, Any], *, client: httpx.Client | None = None) -> None:
        unknown = set(options) - self.allowed - self.common
        if unknown:
            raise ConfigError(f"notifier {name!r} ({self.type}): unknown key(s) {', '.join(sorted(unknown))}")
        self.name = name
        self.options = dict(options)
        self.message_template = _template(options, "message", name)
        self.title_template = _template(options, "title", name)
        min_severity = str(options.get("min_severity", "debug")).lower()
        if min_severity not in SEVERITIES:
            raise ConfigError(f"notifier {name!r}: min_severity must be one of {', '.join(SEVERITIES)}")
        self.min_level = SEVERITIES.index(min_severity)
        timeout = options.get("timeout", 10)
        if not isinstance(timeout, int | float) or isinstance(timeout, bool) or timeout <= 0:
            raise ConfigError(f"notifier {name!r}: timeout must be a positive number of seconds")
        self.timeout = float(timeout)
        self._client = client
        self.setup()

    def setup(self) -> None:  # pragma: no cover - overridden
        pass

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, headers={"User-Agent": "logwatch-alert"})
        return self._client

    def wants(self, alert: Alert) -> bool:
        return SEVERITIES.index(alert.severity) >= self.min_level

    def title(self, alert: Alert) -> str:
        if self.title_template:
            return " ".join(templating.render(self.title_template, alert.context).split())
        return alert.title

    def text(self, alert: Alert) -> str:
        if self.message_template:
            return templating.render(self.message_template, alert.context).strip()
        return alert.message

    def send(self, alert: Alert) -> None:
        raise NotImplementedError

    def _post(self, url: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self.client.request(kwargs.pop("method", "POST"), url, timeout=self.timeout, **kwargs)
        except httpx.HTTPError as exc:
            raise NotifierError(f"{self.type} request failed: {type(exc).__name__}") from None
        if response.status_code >= 400:
            raise NotifierError(f"{self.type} answered HTTP {response.status_code}")
        return response


class Telegram(Notifier):
    type = "telegram"
    allowed = frozenset({"bot_token", "chat_id", "api_base", "disable_notification", "message_thread_id"})

    def setup(self) -> None:
        self.token = _require(self.options, "bot_token", self.name)
        chat_id = self.options.get("chat_id")
        if chat_id is None or str(chat_id).strip() == "":
            raise ConfigError(f"notifier {self.name!r}: 'chat_id' is required")
        self.chat_id = str(chat_id).strip()
        self.api_base = str(self.options.get("api_base", "https://api.telegram.org")).rstrip("/")

    def send(self, alert: Alert) -> None:
        payload: dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": _truncate(f"{self.title(alert)}\n\n{self.text(alert)}", 4096),
            "disable_web_page_preview": True,
        }
        if self.options.get("disable_notification") or alert.severity in ("debug", "info"):
            payload["disable_notification"] = True
        if self.options.get("message_thread_id") is not None:
            payload["message_thread_id"] = self.options["message_thread_id"]
        self._post(f"{self.api_base}/bot{self.token}/sendMessage", json=payload)


class Slack(Notifier):
    type = "slack"
    allowed = frozenset({"webhook_url", "channel", "username", "icon_emoji"})

    def setup(self) -> None:
        self.url = _require(self.options, "webhook_url", self.name)

    def send(self, alert: Alert) -> None:
        title, text = self.title(alert), self.text(alert)
        payload: dict[str, Any] = {
            "text": _truncate(f"*{title}*\n{text}", 3900),
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": _truncate(title, 150)}},
                {"type": "section", "text": {"type": "mrkdwn", "text": _truncate(f"```{text}```", 2990)}},
            ],
        }
        for key in ("channel", "username", "icon_emoji"):
            if self.options.get(key):
                payload[key] = self.options[key]
        self._post(self.url, json=payload)


class Discord(Notifier):
    type = "discord"
    allowed = frozenset({"webhook_url", "username", "avatar_url"})

    def setup(self) -> None:
        self.url = _require(self.options, "webhook_url", self.name)

    def send(self, alert: Alert) -> None:
        payload: dict[str, Any] = {
            "embeds": [
                {
                    "title": _truncate(self.title(alert), 256),
                    "description": _truncate(self.text(alert), 4000),
                    "color": SEVERITY_COLORS.get(alert.severity, 0),
                    "timestamp": alert.to_dict()["last_seen"],
                }
            ],
            "allowed_mentions": {"parse": []},
        }
        for key in ("username", "avatar_url"):
            if self.options.get(key):
                payload[key] = self.options[key]
        self._post(self.url, json=payload)


NTFY_PRIORITIES = {"debug": 1, "info": 2, "warning": 3, "error": 4, "critical": 5}


class Ntfy(Notifier):
    """Publish to an ntfy topic (ntfy.sh or a self-hosted server) using JSON publishing.

    JSON publishing keeps non-ASCII titles intact, unlike the ``Title`` header.
    """

    type = "ntfy"
    allowed = frozenset({"topic", "server", "token", "tags", "priority", "click"})

    def setup(self) -> None:
        self.topic = _require(self.options, "topic", self.name)
        if "/" in self.topic or len(self.topic) > 64:
            raise ConfigError(f"notifier {self.name!r}: topic must be a plain name of at most 64 characters")
        self.server = str(self.options.get("server", "https://ntfy.sh")).strip().rstrip("/")
        if not self.server.startswith(("https://", "http://")):
            raise ConfigError(f"notifier {self.name!r}: server must be an http(s) URL")
        token = self.options.get("token")
        if token is not None and (not isinstance(token, str) or not token.strip()):
            raise ConfigError(f"notifier {self.name!r}: token must be a non-empty string")
        self.token = token.strip() if isinstance(token, str) else None
        tags = self.options.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise ConfigError(f"notifier {self.name!r}: tags must be a list of strings")
        self.tags = tags
        priority = self.options.get("priority")
        if priority is not None and (
            isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 5
        ):
            raise ConfigError(f"notifier {self.name!r}: priority must be an integer from 1 to 5")
        self.priority = priority
        click = self.options.get("click")
        if click is not None and not isinstance(click, str):
            raise ConfigError(f"notifier {self.name!r}: click must be a URL string")
        self.click = click

    def send(self, alert: Alert) -> None:
        payload: dict[str, Any] = {
            "topic": self.topic,
            "title": _truncate(self.title(alert), 250),
            "message": _truncate(self.text(alert), 4000),
            "priority": self.priority or NTFY_PRIORITIES.get(alert.severity, 3),
            "tags": [*self.tags, alert.severity],
        }
        if self.click:
            payload["click"] = self.click
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        self._post(f"{self.server}/", json=payload, headers=headers)


class Webhook(Notifier):
    """POST the alert as JSON (or a rendered ``body`` template) to any URL."""

    type = "webhook"
    allowed = frozenset({"url", "method", "headers", "body", "content_type"})

    def setup(self) -> None:
        self.url = _require(self.options, "url", self.name)
        self.method = str(self.options.get("method", "POST")).upper()
        if self.method not in ("POST", "PUT", "PATCH"):
            raise ConfigError(f"notifier {self.name!r}: method must be POST, PUT or PATCH")
        headers = self.options.get("headers") or {}
        if not isinstance(headers, Mapping):
            raise ConfigError(f"notifier {self.name!r}: headers must be a mapping")
        self.headers = {str(k): str(v) for k, v in headers.items()}
        self.body = _template(self.options, "body", self.name)
        self.content_type = str(self.options.get("content_type", "application/json"))

    def send(self, alert: Alert) -> None:
        headers = dict(self.headers)
        if self.body is None:
            data = alert.to_dict()
            data["title"], data["message"] = self.title(alert), self.text(alert)
            content = json.dumps(data, default=str).encode()
            headers.setdefault("Content-Type", "application/json")
        else:
            content = templating.render(self.body, alert.context).encode()
            headers.setdefault("Content-Type", self.content_type)
        self._post(self.url, method=self.method, content=content, headers=headers)


SMTPFactory = Callable[..., smtplib.SMTP]


class Email(Notifier):
    type = "email"
    allowed = frozenset({"host", "port", "username", "password", "starttls", "ssl", "from", "to", "subject_prefix"})

    def __init__(self, *args: Any, smtp_factory: SMTPFactory | None = None, **kwargs: Any) -> None:
        self.smtp_factory = smtp_factory
        super().__init__(*args, **kwargs)

    def setup(self) -> None:
        self.host = _require(self.options, "host", self.name)
        self.use_ssl = bool(self.options.get("ssl", False))
        self.starttls = bool(self.options.get("starttls", not self.use_ssl))
        if self.use_ssl and self.starttls:
            raise ConfigError(f"notifier {self.name!r}: choose either ssl or starttls")
        self.port = int(self.options.get("port", 465 if self.use_ssl else 587))
        self.sender = _require(self.options, "from", self.name)
        to = self.options.get("to")
        if isinstance(to, str):
            to = [to]
        if not to or not isinstance(to, list) or not all(isinstance(t, str) and "@" in t for t in to):
            raise ConfigError(f"notifier {self.name!r}: 'to' must be an address or a list of addresses")
        self.recipients = to
        self.username = self.options.get("username") or None
        self.password = self.options.get("password") or None
        if bool(self.username) != bool(self.password):
            raise ConfigError(f"notifier {self.name!r}: set both username and password, or neither")
        self.subject_prefix = str(self.options.get("subject_prefix", ""))

    def build(self, alert: Alert) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = _truncate(f"{self.subject_prefix}{self.title(alert)}", 250)
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="logwatch-alert.local")
        msg["X-Logwatch-Rule"] = alert.rule
        msg.set_content(self.text(alert))
        return msg

    def send(self, alert: Alert) -> None:
        msg = self.build(alert)
        context = ssl.create_default_context()
        try:
            if self.smtp_factory is not None:
                smtp = self.smtp_factory(self.host, self.port, timeout=self.timeout)
            elif self.use_ssl:
                smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context)
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            with smtp:
                if self.starttls:
                    smtp.starttls(context=context)
                if self.username and self.password:
                    smtp.login(self.username, self.password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotifierError(f"email delivery failed: {type(exc).__name__}") from None


NOTIFIER_TYPES: dict[str, type[Notifier]] = {cls.type: cls for cls in (Telegram, Slack, Discord, Ntfy, Webhook, Email)}


def build_notifier(name: str, options: Mapping[str, Any], **kwargs: Any) -> Notifier:
    if not isinstance(options, Mapping):
        raise ConfigError(f"notifier {name!r} must be a mapping")
    kind = options.get("type")
    cls = NOTIFIER_TYPES.get(str(kind))
    if cls is None:
        raise ConfigError(f"notifier {name!r}: type must be one of {', '.join(sorted(NOTIFIER_TYPES))}")
    return cls(name, options, **kwargs)


class Dispatcher:
    """Send alerts to the notifiers each rule asks for, with retries.

    ``Dispatcher.send`` is synchronous. :meth:`start` runs a background worker so a
    slow SMTP server never delays reading the logs; use :meth:`submit` then.
    """

    def __init__(
        self,
        notifiers: Mapping[str, Notifier],
        *,
        default_notify: list[str] | None = None,
        retries: int = 2,
        backoff: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
        dry_run: bool = False,
        printer: Callable[[str], None] = print,
    ) -> None:
        self.notifiers = dict(notifiers)
        self.default_notify = default_notify
        self.retries = retries
        self.backoff = backoff
        self.sleep = sleep
        self.dry_run = dry_run
        self.printer = printer
        self.sent = 0
        self.failed = 0
        self._queue: queue.Queue[Alert | None] = queue.Queue(maxsize=1000)
        self._thread: threading.Thread | None = None

    def targets(self, alert: Alert) -> list[str]:
        if alert.notify is not None:
            return alert.notify
        if self.default_notify is not None:
            return self.default_notify
        return list(self.notifiers)

    def send(self, alert: Alert) -> dict[str, bool]:
        if self.dry_run:
            self.printer(json.dumps(alert.to_dict(), default=str))
            return {}
        results: dict[str, bool] = {}
        for name in self.targets(alert):
            notifier = self.notifiers.get(name)
            if notifier is None:
                log.error("rule %s: notifier %r is not configured", alert.rule, name)
                results[name] = False
                continue
            if not notifier.wants(alert):
                continue
            results[name] = self._deliver(notifier, alert)
        return results

    def _deliver(self, notifier: Notifier, alert: Alert) -> bool:
        for attempt in range(self.retries + 1):
            try:
                notifier.send(alert)
            except NotifierError as exc:
                log.warning(
                    "notifier %s: %s (attempt %d/%d, rule %s)",
                    notifier.name,
                    exc,
                    attempt + 1,
                    self.retries + 1,
                    alert.rule,
                )
                if attempt < self.retries:
                    self.sleep(self.backoff * (2**attempt))
                continue
            except Exception:  # a bug in a notifier must never stop log processing
                log.exception("notifier %s crashed (rule %s)", notifier.name, alert.rule)
                break
            self.sent += 1
            log.info("alert %s sent via %s", alert.rule, notifier.name)
            return True
        self.failed += 1
        return False

    # Background mode ---------------------------------------------------------
    def start(self) -> Dispatcher:
        self._thread = threading.Thread(target=self._worker, name="dispatcher", daemon=True)
        self._thread.start()
        return self

    def submit(self, alert: Alert) -> None:
        if self._thread is None:
            self.send(alert)
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            log.error("alert queue is full, dropping alert %s", alert.rule)

    def _worker(self) -> None:
        while True:
            alert = self._queue.get()
            if alert is None:
                return
            self.send(alert)

    def stop(self, timeout: float = 30.0) -> None:
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join(timeout)
            self._thread = None

    def close(self) -> None:
        for notifier in self.notifiers.values():
            if notifier._client is not None:
                notifier._client.close()
