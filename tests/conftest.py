from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest


class Clock:
    """A fake clock: ``clock()`` returns the time, ``clock.advance(s)`` moves it."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@dataclass
class Recorder:
    """Collects requests sent through an ``httpx.MockTransport``."""

    status: int = 200
    requests: list[httpx.Request] = field(default_factory=list)
    fail_times: int = 0
    raise_error: bool = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raise_error:
            raise httpx.ConnectError("connection refused", request=request)
        if self.fail_times > 0:
            self.fail_times -= 1
            return httpx.Response(500, text="nope")
        return httpx.Response(self.status, json={"ok": True})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def json(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


class FakeSMTP:
    instances: list[FakeSMTP] = []  # noqa: RUF012

    def __init__(self, host: str, port: int, timeout: float = 10) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.started_tls = False
        self.login_args: tuple[str, str] | None = None
        self.messages: list[Any] = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def starttls(self, context: Any = None) -> None:
        self.started_tls = True

    def login(self, user: str, password: str) -> None:
        self.login_args = (user, password)

    def send_message(self, msg: Any) -> None:
        self.messages.append(msg)


@pytest.fixture
def fake_smtp() -> type[FakeSMTP]:
    FakeSMTP.instances = []
    return FakeSMTP


@pytest.fixture
def write() -> Callable[..., None]:
    def _write(path: Any, text: str, mode: str = "a") -> None:
        with open(path, mode, encoding="utf-8") as handle:
            handle.write(text)

    return _write
