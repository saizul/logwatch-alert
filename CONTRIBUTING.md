# Contributing to logwatch-alert

Thank you for helping! New rule packs, notifiers, documentation and bug reports are
all welcome. Rule packs are the easiest way to start: one YAML file and a test file.

- [Ways to contribute](#ways-to-contribute)
- [Good first issues](#good-first-issues)
- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Add a rule pack](#add-a-rule-pack)
- [Add a notifier](#add-a-notifier)
- [Guidelines](#guidelines)
- [Pull request process](#pull-request-process)

## Ways to contribute

| Size | Idea |
| --- | --- |
| 10 minutes | Fix a typo, add a FAQ entry, improve an error message |
| 30 minutes | Add a sample line that a built-in pack misses, with a test |
| 1-2 hours | A new rule pack or one of the good first issues below |
| Larger | journald source, inotify backend, Prometheus metrics (open an issue first) |

Comment on an issue before you start so nobody else picks the same one.

## Good first issues

Each of these is self-contained and touches one or two files.

1. **MySQL / MariaDB pack.** Alerts for `Too many connections`, `[ERROR] InnoDB:`,
   `Aborted connection` spikes and crash recovery messages. (`packs/mysql.yaml`, tests)
2. **PostgreSQL pack.** `FATAL:  too many connections`, `PANIC:`, `could not write to file`,
   `deadlock detected` with a threshold. (`packs/postgres.yaml`, tests)
3. **Redis pack.** `Background saving error`, `OOM command not allowed`,
   `MISCONF`. (`packs/redis.yaml`, tests)
4. **Microsoft Teams notifier.** Post a simple MessageCard/Adaptive Card to an incoming
   webhook URL. (`notifiers.py`, tests, README)
5. **`--since` for `test`.** Only replay lines newer than a duration, using a timestamp regex.
   (`cli.py`, tests)
6. **Timestamps from log lines in `test`.** Use a `timestamp` capture (ISO 8601 or syslog
   format) as the event time so thresholds behave as in production when replaying old logs.
   (`engine.py`, `cli.py`, tests)
7. **Remember file offsets across restarts.** Optional `settings.state_file` storing
   `{path: [dev, inode, offset]}` so a restart does not skip or repeat lines. (`tailer.py`,
   `runner.py`, tests)
8. **Apache / Caddy access log pack.** 5xx spike rules for the Apache combined format and
   Caddy's JSON logs (the JSON one is a nice use of `json:` conditions). (`packs/`, tests)

## Development setup

```bash
git clone https://github.com/saizul/logwatch-alert
cd logwatch-alert
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e .[dev]
pytest
ruff check . && ruff format --check .
```

Python 3.11+ is needed. Tests must not use the network: notifiers get an
`httpx.MockTransport` client (see `Recorder` in `tests/conftest.py`) and e-mail uses
`FakeSMTP`. Use the `clock` fixture instead of sleeping.

Try your rules against real lines without sending anything:

```bash
logwatch-alert test --pack ssh examples/sample-auth.log
logwatch-alert -c my-config.yaml test /var/log/nginx/access.log
logwatch-alert -c my-config.yaml run --dry-run --from-beginning
```

## Project layout

| Path | Responsibility |
| --- | --- |
| `src/logwatch_alert/tailer.py` | `FileTailer` (globs, rotation, truncation) and `StreamReader` (stdin) |
| `src/logwatch_alert/rules.py` | Rule parsing, regex patterns, JSON field conditions |
| `src/logwatch_alert/engine.py` | Sliding-window thresholds, `group_by`, cooldowns, the `Alert` object |
| `src/logwatch_alert/templating.py` | The `{{ variable \| filter }}` renderer |
| `src/logwatch_alert/notifiers.py` | Telegram, Slack, Discord, webhook, e-mail and the `Dispatcher` |
| `src/logwatch_alert/config.py` | YAML loading, `${VAR}` expansion, rule packs |
| `src/logwatch_alert/runner.py` | The main loop and heartbeat |
| `src/logwatch_alert/packs/*.yaml` | Built-in rule packs |
| `src/logwatch_alert/cli.py` | `run`, `check-config`, `test`, `notify-test`, `packs`, `healthcheck` |

## Add a rule pack

1. Collect **real sample lines** (redact hostnames, IPs and user names; use the
   documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
2. Create `src/logwatch_alert/packs/<name>.yaml` with a top-level `rules:` list. Every rule
   needs a `name` prefixed with the pack name, a `description`, a sensible `threshold`
   and `cooldown`, and a `title`/`message` that tell the reader what to do.
3. Use named groups (`(?P<ip>...)`) for anything worth showing or grouping by.
4. Add tests to `tests/test_packs.py`: lines that must fire, lines that must not, and the
   rendered title.
5. Add a row to the pack table in `README.md` and a line under "Unreleased" in `CHANGELOG.md`.

Keep regexes linear: avoid nested quantifiers such as `(.*)*` and prefer `\S+` or
`[^"]*` over `.*` in the middle of a pattern.

## Add a notifier

1. Subclass `Notifier` in `notifiers.py`: set `type`, the `allowed` option names, validate
   options in `setup()` (raise `ConfigError`), and implement `send(alert)` with `self._post(...)`.
2. Register it in `NOTIFIER_TYPES`.
3. Errors must go through `NotifierError` with a message that **never** contains the URL,
   token or response body.
4. Test the payload with the `recorder` fixture and the error path.

## Guidelines

- Keep runtime dependencies to httpx and PyYAML; discuss new ones first.
- Never log or return secrets. Alert text may contain log lines; that is expected.
- Type hints everywhere; `ruff check` and `ruff format` clean.
- Tests are fast and deterministic: no network, no `sleep` (advance the `clock`).
- Backwards compatible config: new keys get defaults; renamed keys need a deprecation path.

## Pull request process

1. Fork and create a branch (`pack/mysql`, `fix/copytruncate`).
2. Keep pull requests focused; fill in the checklist in the template.
3. Add an entry to `CHANGELOG.md` under "Unreleased".
4. A maintainer reviews within a few days.

By contributing you agree that your work is released under the MIT License and
that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).
