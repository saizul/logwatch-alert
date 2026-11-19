# logwatch-alert

[![CI](https://github.com/saizul/logwatch-alert/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/logwatch-alert/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/saizul/logwatch-alert?sort=semver)](https://github.com/saizul/logwatch-alert/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Container image](https://img.shields.io/badge/ghcr.io-saizul%2Flogwatch--alert-2496ED?logo=docker&logoColor=white)](https://github.com/saizul/logwatch-alert/pkgs/container/logwatch-alert)
![Python](https://img.shields.io/badge/python-3.11%E2%80%933.13-blue)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Tail your logs, match simple YAML rules, get one useful alert instead of a thousand.**
logwatch-alert follows log files (globs, logrotate, `copytruncate`) or `docker logs`
on stdin, matches regexes, JSON fields and thresholds such as "20 nginx 5xx in one
minute", groups and de-duplicates with cooldowns, and sends the alert to Telegram,
Slack, Discord, any webhook or e-mail. Ready-made rule packs cover nginx 5xx spikes,
PHP fatal errors, SSH brute force and OOM kills.

```text
 /var/log/nginx/*.log ─┐                                         ┌──▶ Telegram
 /var/log/auth.log    ─┼──▶ rules: regex / JSON / threshold ──▶  ├──▶ Slack, Discord
 docker logs -f app | ─┘    group_by + cooldown (dedupe)         ├──▶ webhook
                                                                 └──▶ e-mail (SMTP)
```

It is a single small process (httpx + PyYAML), needs no database, agent or SaaS, and
fits the gap between "grep in a cron job" and running a full log stack.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Rule packs](#rule-packs)
- [Configuration reference](#configuration-reference)
- [Writing rules](#writing-rules)
- [Templates](#templates)
- [Notifiers](#notifiers)
- [CLI](#cli)
- [Docker](#docker)
- [FAQ](#faq)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Development](#development)
- [License](#license)

## Features

- **Reliable tailing**: paths and globs, new files picked up automatically, rotation by
  rename (`create`), delayed create, `copytruncate`, partial lines, invalid UTF-8; works
  on bind mounts and NFS because it polls instead of using inotify
- **stdin**: `docker logs -f app 2>&1 | logwatch-alert run --stdin`, with a `strip` regex
  for Docker timestamps or `docker compose` prefixes
- **Rules in YAML**: regexes with named captures, `exclude`, JSON field conditions
  (`status: {gte: 500}`), source filters, "N matches in M minutes" thresholds
- **No alert storms**: `group_by` (per IP, per file, per line), per-group cooldowns and a
  "N more were suppressed" note in the next alert
- **Five notifiers**: Telegram, Slack, Discord, generic webhook (JSON or your own body
  template), SMTP e-mail; retries with backoff, `min_severity`, non-blocking sender
- **Rule packs** for nginx, PHP, SSH and OOM, with per-rule overrides
- **Test before you deploy**: `logwatch-alert test` replays a log file through your rules,
  `run --dry-run` prints alerts instead of sending them, `notify-test` checks a channel
- **Safe by default**: secrets from `${ENV}` only, never logged; sandboxed templates;
  read-only log mounts; non-root container with a health check

## Quick start

### 1. See what it would alert on (no config needed)

```bash
pip install logwatch-alert          # or: pipx install logwatch-alert
logwatch-alert test --pack ssh /var/log/auth.log
logwatch-alert test --pack nginx /var/log/nginx/access.log
```

### 2. Write a config

```yaml
# config.yaml
sources:
  - path: /var/log/nginx/access.log
    name: nginx
  - path: /var/log/auth.log
    name: auth
  - path: /var/log/kern.log

packs: [nginx, ssh, oom]

notifiers:
  telegram:
    type: telegram
    bot_token: ${TELEGRAM_BOT_TOKEN}
    chat_id: ${TELEGRAM_CHAT_ID}
```

### 3. Run it

```bash
export TELEGRAM_BOT_TOKEN=123456:replace-me TELEGRAM_CHAT_ID=-1001234567890
logwatch-alert -c config.yaml check-config   # validate, prints a summary without secrets
logwatch-alert -c config.yaml notify-test    # sends one test message
logwatch-alert -c config.yaml run
```

Or with Docker:

```bash
docker run -d --name logwatch-alert --restart unless-stopped \
  -e TELEGRAM_BOT_TOKEN -e TELEGRAM_CHAT_ID \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -v /var/log:/var/log:ro \
  ghcr.io/saizul/logwatch-alert:latest
```

## Rule packs

| Pack | Rule | Fires when | Default threshold / cooldown |
| --- | --- | --- | --- |
| `nginx` | `nginx-5xx-spike` | 5xx responses in the combined access log | 20 in 1m / 10m |
| | `nginx-upstream-errors` | upstream timed out, connect() failed, no live upstreams | 10 in 5m per reason / 15m |
| `php` | `php-fatal-error` | `PHP Fatal error`, `PHP Parse error` | every match, per file:line / 15m |
| | `php-memory-exhausted` | `Allowed memory size ... exhausted` | every match / 30m |
| | `php-fpm-max-children` | php-fpm pool reached `pm.max_children` | every match per pool / 30m |
| `ssh` | `ssh-brute-force` | failed password, invalid user, max auth attempts | 5 in 10m per IP / 1h |
| | `ssh-root-login` | successful SSH login as root | every match per IP / 1h |
| `oom` | `oom-kill` | kernel or cgroup OOM killer killed a process | every match per process / 30m |
| | `oom-systemd-unit` | a systemd unit lost a process to the OOM killer | every match per unit / 30m |

`logwatch-alert packs` lists them and `logwatch-alert packs ssh` prints one. Customise a
pack without copying it:

```yaml
packs:
  - nginx
  - name: ssh
    sources: [auth]              # only apply to these sources
    notify: [telegram]           # send these alerts here
    disable: [ssh-root-login]    # drop a rule
    overrides:
      ssh-brute-force:
        threshold: {count: 10, window: 5m}
        cooldown: 6h
  - ./my-team-pack.yaml          # a pack file of your own
```

## Configuration reference

The config file is YAML. Every string may use `${VAR}` or `${VAR:-default}`; write `$$`
for a literal `$`. The path comes from `-c`, `$LOGWATCH_ALERT_CONFIG` or `./config.yaml`.
A complete example is in [`examples/config.yaml`](examples/config.yaml).

### `sources[]`

| Key | Default | Description |
| --- | --- | --- |
| `path` | | File path or glob (`/var/log/app/*.log`). Either `path` or `stdin` |
| `stdin` | `false` | Read lines from stdin (also `run --stdin`) |
| `name` | the path, or `stdin` | Name used by rules' `sources` and shown in alerts |
| `format` | `auto` | `auto` parses lines that look like JSON objects, `json` the same, `text` never parses |
| `strip` | | Regex removed from the start of each line (Docker timestamps, compose prefixes) |

A plain string is short for `{path: ...}`.

### `settings`

| Key | Default | Description |
| --- | --- | --- |
| `poll_interval` | `1s` | How often files are checked |
| `glob_refresh` | `10s` | How often globs are re-expanded and missing files re-checked |
| `start_at` | `end` | `end` skips existing content (like `tail -F`); `beginning` reads it (`--from-beginning`) |
| `default_cooldown` | `10m` | Cooldown for rules that do not set one |
| `default_notify` | all notifiers | Notifiers for rules without `notify` |
| `hostname` | machine hostname | Shown as `{{ hostname }}` |
| `retries` | `2` | Extra delivery attempts per notifier (backoff 2s, 4s, ...) |
| `heartbeat_file` | `$LOGWATCH_ALERT_HEARTBEAT` | File touched every loop, used by `healthcheck` |

Durations accept `500ms`, `30s`, `5m`, `1h30m`, `2d`, `1w` or a number of seconds.

### `rules[]`

| Key | Default | Description |
| --- | --- | --- |
| `name` | required | Unique name |
| `pattern` / `patterns` | | A regex or a list (first match wins). Named groups become variables |
| `json` | | Field conditions, see below. A rule needs `pattern`, `json` or both |
| `exclude` | | Regex or list; a matching line is ignored |
| `ignore_case` | `false` | Case-insensitive `pattern` and `exclude` |
| `sources` | all | Source names or globs (also matched against the file path) |
| `threshold` | `1` | `N` or `{count: N, window: 5m}`: fire when N lines match within the window |
| `group_by` | none | Template; each value gets its own window and cooldown (`"{{ ip }}"`) |
| `cooldown` | `settings.default_cooldown` | After an alert, matches for the same group are counted but not sent |
| `severity` | `error` | `debug`, `info`, `warning`, `error`, `critical` |
| `notify` | `settings.default_notify` | List of notifier names |
| `title`, `message` | built-in | Templates, see [Templates](#templates) |
| `description` | | Free text, available as `{{ description }}` |
| `enabled` | `true` | Set `false` to keep a rule in the file but switch it off |

#### JSON conditions

When a line is a JSON object, `json:` checks its fields. Dotted paths reach nested
objects and list items (`http.request.headers.0`); a literal key with dots (`log.level`)
also works. All conditions must hold.

| Form | Meaning |
| --- | --- |
| `level: error` | equals (numbers compare loosely: `"500"` equals `500`) |
| `level: {in: [error, fatal]}` / `{not_in: [...]}` | membership |
| `level: {not_equals: debug}` | not equal (also true when the field is missing) |
| `status: {gte: 500}` / `gt`, `lt`, `lte` | numeric comparison, combine for ranges |
| `path: {regex: "^/api/"}` | regex search on the value |
| `msg: {contains: timeout}` | substring, or list membership for arrays |
| `trace_id: {exists: true}` | field present (or absent with `false`) |

## Writing rules

```yaml
rules:
  # Every match, de-duplicated per distinct line for an hour.
  - name: disk-full
    pattern: 'No space left on device'
    group_by: "{{ line }}"
    cooldown: 1h
    severity: critical

  # A threshold: 10 failed jobs in 5 minutes, one alert per queue.
  - name: worker-failures
    sources: [worker]
    pattern: 'job (?P<job>\S+) failed on queue (?P<queue>\S+)'
    threshold: {count: 10, window: 5m}
    group_by: "{{ queue }}"
    cooldown: 30m
    notify: [slack]

  # JSON logs (pino, zap, structlog, Laravel JSON, ...).
  - name: api-5xx
    json:
      level: {in: [error, fatal]}
      status: {gte: 500}
      path: {regex: "^/api/"}
    threshold: {count: 5, window: 1m}
    title: "{{ status }} on {{ path }} ({{ hostname }})"
    message: "{{ count }} failures in {{ window_human }}. Last: {{ msg | truncate(300) }}"
```

Check them against real lines before going live:

```bash
logwatch-alert -c config.yaml test /var/log/worker.log --source worker
```

How the counting works: each rule keeps a sliding window per `group_by` value. When the
window holds `count` matches, one alert is sent and the window is cleared. For the next
`cooldown`, further matches for that group are only counted; the next alert says how many
were suppressed. Idle groups are forgotten, and at most 10,000 groups per rule are kept,
so a botnet with many IPs cannot exhaust memory.

## Templates

Titles, messages, `group_by` and webhook bodies use `{{ variable }}` with optional
filters: `{{ path | truncate(80) }}`, `{{ user | default('?') }}`, `{{ title | json }}`,
`upper`, `lower`, `trim`. Only variable lookups are possible (no code), and unknown
variables render as an empty string.

| Variable | Value |
| --- | --- |
| `rule`, `description`, `severity`, `hostname` | from the rule and settings |
| `source`, `source_path` | source name, and the file path for file sources |
| `line`, `samples` | the last matching line, and up to 5 recent matching lines |
| `count`, `threshold`, `window`, `window_human`, `cooldown_human` | counting details |
| `group`, `group_suffix` | the `group_by` value, and `" (value)"` or empty |
| `first_seen`, `last_seen`, `time` | ISO 8601 UTC timestamps |
| `suppressed`, `suppressed_note` | matches swallowed by the cooldown, and a ready-made sentence |
| named regex groups | e.g. `{{ ip }}`; also under `captures.ip` |
| JSON fields | top-level fields directly (`{{ status }}`), any field under `fields` (`{{ fields.http.method }}`) |
| `title`, `message` | the rendered rule title and message (for notifier and webhook templates) |

## Notifiers

Each notifier accepts `title` and `message` templates to override the rule's text,
`min_severity` (default `debug`) and `timeout` (default 10 seconds).

```yaml
notifiers:
  telegram:
    type: telegram
    bot_token: ${TELEGRAM_BOT_TOKEN}      # from @BotFather
    chat_id: ${TELEGRAM_CHAT_ID}          # user, group (-100...) or channel id
    # message_thread_id: 42               # forum topic
    # disable_notification: true          # silent; info/debug alerts are always silent

  slack:
    type: slack
    webhook_url: ${SLACK_WEBHOOK_URL}     # Incoming Webhook URL
    min_severity: warning

  discord:
    type: discord
    webhook_url: ${DISCORD_WEBHOOK_URL}   # embed coloured by severity, mentions disabled

  pagerduty-ish:
    type: webhook
    url: https://example.com/hooks/alerts
    method: POST                          # POST, PUT or PATCH
    headers: {Authorization: "Bearer ${ALERT_TOKEN}"}
    # Without "body" the alert is sent as JSON (rule, severity, title, message, group, count,
    # source, line, samples, first_seen, last_seen, suppressed, hostname, captures, fields).
    body: '{"summary": {{ title | json }}, "severity": {{ severity | json }}, "details": {{ message | json }}}'

  email:
    type: email
    host: smtp.example.com
    port: 587                             # default 587 with STARTTLS, 465 with ssl: true
    starttls: true
    username: ${SMTP_USERNAME}
    password: ${SMTP_PASSWORD}
    from: alerts@example.com
    to: [ops@example.com]
    subject_prefix: "[prod] "
```

Delivery runs in a background thread, so a slow SMTP server never delays log reading.
Failed deliveries are retried `settings.retries` times with exponential backoff. Error
messages contain the notifier name and HTTP status only, never the URL or token.

## CLI

```text
logwatch-alert [-c CONFIG] [--log-level LEVEL] COMMAND

run            watch the sources and send alerts
               --dry-run          print alerts as JSON lines instead of sending
               --stdin            also read stdin (--stdin-name NAME)
               --from-beginning   read existing file content too
check-config   validate the config and print a summary (no secrets)
test FILE|-    replay lines through the rules and print the alerts that would fire
               --pack NAME (repeatable, works without a config), --source NAME,
               --json, --expect-alert (exit 1 if nothing fired; handy in CI)
notify-test    send a test alert through all (or the named) notifiers
packs [NAME]   list built-in packs, or print one
healthcheck    exit 0 if the heartbeat file is fresh (--max-age 120)
```

Exit codes: `0` success, `1` failed check or delivery, `2` configuration error.
When stdin is the only source, `run` exits after the input ends, so
`cat old.log | logwatch-alert -c config.yaml run --stdin --dry-run` works as a batch check.

## Docker

The image `ghcr.io/saizul/logwatch-alert` runs as a non-root user that belongs to the
`adm` group (gid 4), which can read `/var/log/auth.log`, `kern.log`, `syslog` and nginx logs
on Debian and Ubuntu hosts. It reads `/config/config.yaml` and has a `HEALTHCHECK`.

```yaml
# docker-compose.yml
services:
  logwatch-alert:
    image: ghcr.io/saizul/logwatch-alert:latest
    restart: unless-stopped
    environment:
      TELEGRAM_BOT_TOKEN: ${TELEGRAM_BOT_TOKEN}
      TELEGRAM_CHAT_ID: ${TELEGRAM_CHAT_ID}
      ALERT_HOSTNAME: web-1          # use with  settings.hostname: ${ALERT_HOSTNAME}
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - /var/log:/var/log:ro
```

Watching another container:

```bash
docker logs -f --since 1m my-app 2>&1 | \
  docker run -i --rm -e SLACK_WEBHOOK_URL \
    -v "$PWD/docker-logs.yaml:/config/config.yaml:ro" \
    ghcr.io/saizul/logwatch-alert run --stdin
```

Or tail the JSON log files Docker writes itself (needs root on the host):
`path: /var/lib/docker/containers/*/*-json.log` with `format: json` and rules on the
`log` field, e.g. `json: {log: {regex: "ERROR"}}`. See [`examples/`](examples).

## FAQ

**Will I miss lines during log rotation?** No for the usual setups: after a rename the
rest of the old file is read before following the new one, and a new file is read from
its start. With `copytruncate`, lines written between the copy and the truncate can be
missed; that is a limit of `copytruncate` itself. Prefer `create` rotation where you can.

**Does it re-send old lines after a restart?** By default it starts at the end of every
existing file, like `tail -F`, so a restart never floods you. Use `--from-beginning` to scan
existing content once.

**How do I stop alert storms?** Every rule has a cooldown (10 minutes by default) per
`group_by` value. Use a threshold for noisy events and `group_by` for per-IP or per-file
alerts. Suppressed matches are counted and reported in the next alert.

**Can it read journald?** Pipe it: `journalctl -f -o cat -u nginx | logwatch-alert run --stdin`
(or `-o json` with `format: json`). A native journald source is on the roadmap.

**Permission denied on a log file?** The image user is already in `adm`. For files owned
by another group add it with `group_add: ["<gid>"]`, or as a last resort run as root
(`user: "0"`). The mount stays read-only either way.

**Why poll instead of inotify?** Polling once a second costs almost nothing, works on
every filesystem (including Docker Desktop and NFS) and needs no extra dependency.

**Is this a replacement for Loki, Graylog or Datadog?** No. It is for a few servers where
you want useful alerts today with one small process and no storage to run.

## Roadmap

Ideas are tracked as issues; the ones marked **good first issue** are a great start.

- More packs: MySQL/MariaDB, PostgreSQL, Redis, Apache, Caddy, Traefik, WordPress (**good first issue**)
- ntfy, Microsoft Teams and Gotify notifiers (**good first issue**)
- Use timestamps from log lines when replaying with `test` (**good first issue**)
- Persist file offsets across restarts (`settings.state_file`) (**good first issue**)
- Native journald source
- Prometheus `/metrics` with lines read and alerts sent
- "Silence" rules: no alert if a line stops appearing (dead man's switch)

## Contributing

Contributions are welcome, from a sample log line that a pack misses to a new notifier.
Read [CONTRIBUTING.md](CONTRIBUTING.md) for the setup, the project layout, how to add a
rule pack and a list of good first issues. Please follow the
[Code of Conduct](CODE_OF_CONDUCT.md) and report security problems privately as described
in [SECURITY.md](SECURITY.md).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .[dev]
pytest
ruff check . && ruff format --check .
docker build -t logwatch-alert:dev .
```

## License

[MIT](LICENSE) © Saizul Amin
