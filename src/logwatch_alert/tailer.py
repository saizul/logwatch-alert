"""Follow log files like ``tail -F``: globs, rotation (rename + create) and truncation.

The tailer polls with ``os.stat`` so it works everywhere (bind mounts, NFS, Docker
Desktop) without inotify. Call :meth:`FileTailer.poll` in a loop.
"""

from __future__ import annotations

import contextlib
import glob
import logging
import os
import queue
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import IO, BinaryIO

log = logging.getLogger(__name__)

CHUNK = 64 * 1024
MAX_LINE = 64 * 1024


def _decode(raw: bytes) -> str:
    return raw.rstrip(b"\r").decode("utf-8", errors="replace")


@dataclass
class _Followed:
    path: str
    handle: BinaryIO
    ident: tuple[int, int]
    offset: int = 0
    buffer: bytearray = field(default_factory=bytearray)

    def read_lines(self, *, flush: bool = False) -> Iterator[str]:
        while True:
            chunk = self.handle.read(CHUNK)
            if not chunk:
                break
            self.offset += len(chunk)
            self.buffer.extend(chunk)
            yield from self._split()
        if flush and self.buffer:
            line = _decode(bytes(self.buffer))
            self.buffer.clear()
            yield line

    def _split(self) -> Iterator[str]:
        while True:
            newline = self.buffer.find(b"\n", 0, MAX_LINE + 1)
            if newline == -1:
                if len(self.buffer) > MAX_LINE:
                    line = bytes(self.buffer[:MAX_LINE])
                    del self.buffer[:MAX_LINE]
                    yield _decode(line)
                    continue
                return
            line = bytes(self.buffer[:newline])
            del self.buffer[: newline + 1]
            yield _decode(line)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.handle.close()


def _ident(st: os.stat_result) -> tuple[int, int]:
    return (st.st_dev, st.st_ino)


class FileTailer:
    """Tail every file matching ``pattern`` (a path or a glob).

    ``start_at_end`` controls files that exist when the tailer starts. Files that
    appear later (new glob matches, or the new file after a rotation) are always
    read from the beginning so no line is lost.
    """

    def __init__(self, pattern: str, *, start_at_end: bool = True, name: str | None = None) -> None:
        self.pattern = os.path.expanduser(pattern)
        self.name = name or pattern
        self.start_at_end = start_at_end
        self.is_glob = glob.has_magic(self.pattern)
        self._files: dict[str, _Followed] = {}
        self._started = False

    @property
    def paths(self) -> list[str]:
        return sorted(self._files)

    def _matches(self) -> list[str]:
        if self.is_glob:
            return sorted(p for p in glob.glob(self.pattern) if os.path.isfile(p))
        return [self.pattern] if os.path.isfile(self.pattern) else []

    def _open(self, path: str, *, at_end: bool) -> None:
        try:
            handle = open(path, "rb")  # noqa: SIM115 - kept open while following
            st = os.fstat(handle.fileno())
        except OSError as exc:
            log.warning("cannot open %s: %s", path, exc.strerror or exc)
            return
        followed = _Followed(path=path, handle=handle, ident=_ident(st))
        if at_end:
            followed.offset = handle.seek(0, os.SEEK_END)
        self._files[path] = followed
        log.info("following %s%s", path, " from the end" if at_end else "")

    def refresh(self) -> None:
        """Pick up files that started matching the pattern."""
        at_end = self.start_at_end and not self._started
        for path in self._matches():
            if path not in self._files:
                self._open(path, at_end=at_end)
        self._started = True

    def poll(self) -> list[tuple[str, str]]:
        """Return new complete lines as ``(path, line)`` pairs."""
        if not self._started:
            self.refresh()
        out: list[tuple[str, str]] = []
        for path, followed in list(self._files.items()):
            out.extend((path, line) for line in self._poll_one(path, followed))
        return out

    def _poll_one(self, path: str, followed: _Followed) -> Iterator[str]:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        except OSError as exc:  # pragma: no cover - permission changes
            log.warning("cannot stat %s: %s", path, exc)
            return
        if st is not None and _ident(st) == followed.ident:
            if st.st_size < followed.offset:
                log.info("%s was truncated, reading from the start", path)
                followed.handle.seek(0)
                followed.offset = 0
                followed.buffer.clear()
            yield from followed.read_lines()
            return
        # Rotated (renamed or replaced) or deleted: drain what is left of the old file.
        yield from followed.read_lines(flush=True)
        followed.close()
        del self._files[path]
        if st is not None:
            log.info("%s was rotated, following the new file", path)
            self._open(path, at_end=False)
            new = self._files.get(path)
            if new is not None:
                yield from new.read_lines()
        else:
            log.info("%s disappeared, waiting for it to come back", path)

    def close(self) -> None:
        for followed in self._files.values():
            followed.close()
        self._files.clear()


class StreamReader:
    """Read lines from a stream (stdin, e.g. ``docker logs -f app 2>&1 |``) in a thread."""

    def __init__(self, stream: IO[str] | None = None, *, name: str = "stdin") -> None:
        self.stream = stream if stream is not None else sys.stdin
        self.name = name
        self.queue: queue.Queue[str | None] = queue.Queue(maxsize=10000)
        self.finished = False
        self._pending: list[str | None] = []
        self._thread = threading.Thread(target=self._run, name=f"reader-{name}", daemon=True)

    def start(self) -> StreamReader:
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            for line in self.stream:
                self.queue.put(line.rstrip("\r\n"))
        finally:
            self.queue.put(None)

    def _take(self, item: str | None, lines: list[str]) -> bool:
        if item is None:
            self.finished = True
            return False
        lines.append(item)
        return True

    def poll(self, limit: int = 5000) -> list[str]:
        lines: list[str] = []
        while self._pending and len(lines) < limit:
            if not self._take(self._pending.pop(0), lines):
                return lines
        while len(lines) < limit:
            try:
                item = self.queue.get_nowait()
            except queue.Empty:
                break
            if not self._take(item, lines):
                break
        return lines

    def wait(self, timeout: float) -> None:
        """Block up to ``timeout`` seconds until a line (or EOF) is available."""
        if self._pending:
            return
        try:
            self._pending.append(self.queue.get(timeout=timeout))
        except queue.Empty:
            return
