"""The main loop: read every source, feed the engine, hand alerts to the dispatcher."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO

from logwatch_alert.config import Config, Source
from logwatch_alert.engine import Engine, parse_json_line
from logwatch_alert.notifiers import Dispatcher
from logwatch_alert.tailer import FileTailer, StreamReader

log = logging.getLogger(__name__)

PRUNE_EVERY = 60.0


class Runner:
    def __init__(
        self,
        config: Config,
        dispatcher: Dispatcher,
        *,
        stdin: IO[str] | None = None,
        engine: Engine | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.dispatcher = dispatcher
        self.clock = clock
        self.engine = engine or Engine(config.rules, hostname=config.settings.hostname, clock=clock)
        start_at_end = config.settings.start_at == "end"
        self.tailers: list[tuple[Source, FileTailer]] = [
            (source, FileTailer(source.path, start_at_end=start_at_end, name=source.name))
            for source in config.sources
            if source.path
        ]
        self.stdin_source = next((s for s in config.sources if s.stdin), None)
        self.reader: StreamReader | None = None
        if self.stdin_source is not None:
            self.reader = StreamReader(stdin, name=self.stdin_source.name)
        self._last_refresh = 0.0
        self._last_prune = clock()
        self.stop_event = threading.Event()

    def start(self) -> None:
        for _, tailer in self.tailers:
            tailer.refresh()
        self._last_refresh = self.clock()
        if self.reader is not None:
            self.reader.start()

    def handle(self, source: Source, line: str, path: str | None = None) -> int:
        if source.strip is not None:
            line = source.strip.sub("", line, count=1)
        if not line.strip():
            return 0
        fields = None if source.format == "text" else parse_json_line(line)
        alerts = self.engine.process(source.name, line, path=path, fields=fields, parse_json=False)
        for alert in alerts:
            log.info("rule %s fired (%s, count %d)", alert.rule, alert.group or "-", alert.count)
            self.dispatcher.submit(alert)
        return len(alerts)

    def step(self) -> int:
        """Read once from every source. Returns the number of lines handled."""
        now = self.clock()
        if now - self._last_refresh >= self.config.settings.glob_refresh:
            for _, tailer in self.tailers:
                tailer.refresh()
            self._last_refresh = now
        handled = 0
        for source, tailer in self.tailers:
            for path, line in tailer.poll():
                self.handle(source, line, path)
                handled += 1
        if self.reader is not None and self.stdin_source is not None:
            for line in self.reader.poll():
                self.handle(self.stdin_source, line)
                handled += 1
        if now - self._last_prune >= PRUNE_EVERY:
            self.engine.prune()
            self._last_prune = now
        self.heartbeat()
        return handled

    def heartbeat(self) -> None:
        path = self.config.settings.heartbeat_file
        if not path:
            return
        try:
            Path(path).touch()
        except OSError as exc:  # pragma: no cover - read-only filesystem
            log.debug("cannot touch heartbeat file: %s", exc)

    @property
    def stdin_only_and_done(self) -> bool:
        return not self.tailers and self.reader is not None and self.reader.finished

    def run(self) -> None:
        self.start()
        interval = self.config.settings.poll_interval
        log.info(
            "watching %d file source(s)%s with %d rule(s) and %d notifier(s)",
            len(self.tailers),
            " and stdin" if self.reader else "",
            len(self.config.rules),
            len(self.config.notifiers),
        )
        try:
            while not self.stop_event.is_set():
                handled = self.step()
                if self.stdin_only_and_done:
                    log.info("stdin closed, exiting")
                    break
                if handled == 0:
                    if self.reader is not None and not self.tailers:
                        self.reader.wait(interval)
                    else:
                        self.stop_event.wait(interval)
        finally:
            for _, tailer in self.tailers:
                tailer.close()


def heartbeat_age(path: str) -> float | None:
    try:
        return time.time() - os.stat(path).st_mtime
    except OSError:
        return None
