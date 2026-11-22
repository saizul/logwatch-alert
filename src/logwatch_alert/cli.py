"""Command line interface: ``logwatch-alert run | check-config | test | notify-test | packs | healthcheck``."""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import signal
import socket
import sys
import time
from collections.abc import Sequence
from typing import IO, Any

from logwatch_alert._version import __version__
from logwatch_alert.config import Config, ConfigError, Source, available_packs, load_config, load_pack, read_pack
from logwatch_alert.durations import format_duration
from logwatch_alert.engine import Alert, Engine
from logwatch_alert.notifiers import Dispatcher
from logwatch_alert.runner import Runner, heartbeat_age

DEFAULT_CONFIG = "config.yaml"
HEARTBEAT_ENV = "LOGWATCH_ALERT_HEARTBEAT"

log = logging.getLogger("logwatch_alert")


def _config_path(args: argparse.Namespace) -> str:
    return args.config or os.environ.get("LOGWATCH_ALERT_CONFIG") or DEFAULT_CONFIG


def _load(args: argparse.Namespace) -> Config:
    config = load_config(_config_path(args))
    if not config.settings.heartbeat_file and os.environ.get(HEARTBEAT_ENV):
        config.settings.heartbeat_file = os.environ[HEARTBEAT_ENV]
    return config


def _dispatcher(config: Config, *, dry_run: bool) -> Dispatcher:
    return Dispatcher(
        config.notifiers,
        default_notify=config.settings.default_notify,
        retries=config.settings.retries,
        dry_run=dry_run,
    )


def cmd_run(args: argparse.Namespace, stdin: IO[str] | None = None) -> int:
    config = _load(args)
    if args.stdin and not any(s.stdin for s in config.sources):
        config.sources.append(Source(name=args.stdin_name, stdin=True))
    if args.from_beginning:
        config.settings.start_at = "beginning"
    if not config.sources:
        raise ConfigError("no sources configured (add 'sources' to the config or pass --stdin)")
    if not config.rules:
        raise ConfigError("no rules configured (add 'rules' or 'packs' to the config)")
    if not config.notifiers and not args.dry_run:
        raise ConfigError("no notifiers configured (add 'notifiers' or use --dry-run to print alerts)")
    dispatcher = _dispatcher(config, dry_run=args.dry_run)
    if not args.dry_run:
        dispatcher.start()
    runner = Runner(config, dispatcher, stdin=stdin)

    def stop(signum: int, _frame: Any) -> None:
        log.info("received signal %d, shutting down", signum)
        runner.stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError):  # not in the main thread
            signal.signal(sig, stop)
    try:
        runner.run()
    finally:
        dispatcher.stop()
        dispatcher.close()
    log.info("processed %d line(s), fired %d alert(s)", runner.engine.lines_seen, runner.engine.alerts_fired)
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    config = _load(args)
    summary = {
        "sources": [
            {"name": s.name, **({"path": s.path} if s.path else {"stdin": True}), "format": s.format}
            for s in config.sources
        ],
        "rules": [
            {
                "name": r.name,
                "pack": r.pack,
                "severity": r.severity,
                "threshold": f"{r.count} in {format_duration(r.window)}" if r.count > 1 else "every match",
                "cooldown": format_duration(r.cooldown),
                "group_by": r.group_by or None,
                "notify": r.notify if r.notify is not None else (config.settings.default_notify or "all"),
            }
            for r in config.rules
        ],
        "notifiers": {name: n.type for name, n in config.notifiers.items()},
    }
    print(json.dumps(summary, indent=2))
    print(
        f"OK: {len(config.sources)} source(s), {len(config.rules)} rule(s), {len(config.notifiers)} notifier(s)",
        file=sys.stderr,
    )
    return 0


def _print_alert(alert: Alert, as_json: bool) -> None:
    if as_json:
        print(json.dumps(alert.to_dict(), default=str))
        return
    print(f"--- {alert.rule} [{alert.severity}] {alert.group}".rstrip())
    print(alert.title)
    print(alert.message)
    print()


def cmd_test(args: argparse.Namespace, stdin: IO[str] | None = None) -> int:
    rules = []
    if args.config or not args.pack:
        rules.extend(_load(args).rules)
    for pack in args.pack or []:
        rules.extend(load_pack(pack, default_cooldown=600))
    if not rules:
        raise ConfigError("no rules to test")
    engine = Engine(rules, hostname=args.hostname)
    fired = 0
    for name in args.files:
        source = args.source or ("stdin" if name == "-" else name)
        handle = (stdin or sys.stdin) if name == "-" else open(name, encoding="utf-8", errors="replace")  # noqa: SIM115
        try:
            for raw in handle:
                for alert in engine.process(source, raw.rstrip("\r\n"), path=None if name == "-" else name):
                    fired += 1
                    _print_alert(alert, args.json)
        finally:
            if handle is not sys.stdin and handle is not stdin:
                handle.close()
    print(f"{engine.lines_seen} line(s), {fired} alert(s) from {len(rules)} rule(s)", file=sys.stderr)
    return 0 if fired or not args.expect_alert else 1


def cmd_notify_test(args: argparse.Namespace) -> int:
    config = _load(args)
    names = args.names or list(config.notifiers)
    unknown = [n for n in names if n not in config.notifiers]
    if unknown:
        raise ConfigError(f"unknown notifier(s): {', '.join(unknown)}")
    now = time.time()
    hostname = config.settings.hostname or socket.gethostname()
    context = {"rule": "logwatch-alert-test", "severity": "info", "hostname": hostname, "count": 1, "line": "test"}
    alert = Alert(
        rule="logwatch-alert-test",
        severity="info",
        title=f"[TEST] logwatch-alert on {hostname}",
        message="This is a test alert from logwatch-alert. If you can read it, the notifier works.",
        group="",
        count=1,
        source="notify-test",
        line="test",
        samples=["test"],
        first_seen=now,
        last_seen=now,
        suppressed=0,
        notify=names,
        context=context,
    )
    dispatcher = _dispatcher(config, dry_run=False)
    dispatcher.retries = 0
    results = {}
    for name in names:
        notifier = config.notifiers[name]
        results[name] = dispatcher._deliver(notifier, alert)
        print(f"{name} ({notifier.type}): {'sent' if results[name] else 'FAILED'}")
    dispatcher.close()
    return 0 if all(results.values()) else 1


def cmd_packs(args: argparse.Namespace) -> int:
    if args.name:
        print(read_pack(args.name)[1], end="")
        return 0
    for name in available_packs():
        rules = load_pack(name, default_cooldown=600)
        print(f"{name}: {', '.join(r.name for r in rules)}")
    return 0


def cmd_healthcheck(args: argparse.Namespace) -> int:
    path = args.file or os.environ.get(HEARTBEAT_ENV)
    if not path:
        print("no heartbeat file configured (--file or LOGWATCH_ALERT_HEARTBEAT)", file=sys.stderr)
        return 1
    age = heartbeat_age(path)
    if age is None:
        print(f"unhealthy: {path} does not exist", file=sys.stderr)
        return 1
    if age > args.max_age:
        print(f"unhealthy: last heartbeat {age:.0f}s ago", file=sys.stderr)
        return 1
    print(f"healthy: last heartbeat {age:.0f}s ago")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logwatch-alert",
        description="Tail log files and stdin, match YAML rules, send alerts to Telegram, Slack, "
        "Discord, ntfy, webhooks and e-mail.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", help="config file (default: $LOGWATCH_ALERT_CONFIG or ./config.yaml)")
    parser.add_argument("--log-level", default=os.environ.get("LOGWATCH_ALERT_LOG_LEVEL", "info"))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="watch the sources and send alerts")
    p.add_argument("--dry-run", action="store_true", help="print alerts as JSON instead of sending them")
    p.add_argument("--stdin", action="store_true", help="also read lines from stdin (e.g. docker logs -f app 2>&1 |)")
    p.add_argument("--stdin-name", default="stdin", help="source name for stdin (default: stdin)")
    p.add_argument("--from-beginning", action="store_true", help="read existing files from the start")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("check-config", help="validate the config and print a summary (no secrets)")
    p.set_defaults(func=cmd_check_config)

    p = sub.add_parser("test", help="run lines from files or stdin through the rules and print alerts")
    p.add_argument("files", nargs="+", help="log files, or - for stdin")
    p.add_argument("--pack", action="append", help="test a built-in pack (repeatable); skips the config unless -c")
    p.add_argument("--source", help="source name to match rules' 'sources' against")
    p.add_argument("--hostname", default=None)
    p.add_argument("--json", action="store_true", help="print alerts as JSON lines")
    p.add_argument("--expect-alert", action="store_true", help="exit 1 if no alert fired (for CI)")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("notify-test", help="send a test alert through one or all notifiers")
    p.add_argument("names", nargs="*", help="notifier names (default: all)")
    p.set_defaults(func=cmd_notify_test)

    p = sub.add_parser("packs", help="list the built-in rule packs, or print one")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_packs)

    p = sub.add_parser("healthcheck", help="exit 0 if the heartbeat file is fresh (Docker HEALTHCHECK)")
    p.add_argument("--file", help="heartbeat file (default: $LOGWATCH_ALERT_HEARTBEAT)")
    p.add_argument("--max-age", type=float, default=120.0, help="seconds (default: 120)")
    p.set_defaults(func=cmd_healthcheck)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)  # httpx logs full URLs, which may hold tokens
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130
