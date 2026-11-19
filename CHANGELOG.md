# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-19

### Added

- File sources with globs, `tail -F` style rotation handling (rename + create, delayed
  create, `copytruncate`), partial-line buffering and a 64 KiB line cap; polling with
  `os.stat`, so no inotify is needed.
- A stdin source for `docker logs -f app 2>&1 | logwatch-alert run --stdin`, with an
  optional `strip` regex for Docker timestamps or `docker compose` prefixes.
- YAML rules: one or more regexes with named captures, `exclude` regexes, JSON field
  conditions (`equals`, `not_equals`, `in`, `not_in`, `regex`, `contains`, `exists`,
  `gt`, `gte`, `lt`, `lte`), source filters, thresholds ("N matches in M minutes"),
  `group_by` templates, per-group cooldowns with a suppressed-match count, severities.
- Safe `{{ variable | filter }}` templates for titles, messages, group keys and webhook bodies.
- Notifiers: Telegram, Slack incoming webhooks, Discord webhooks, generic webhooks (JSON or a
  custom body template) and SMTP e-mail (STARTTLS or TLS), with retries, exponential backoff,
  `min_severity` and a background sender so slow notifiers never block log reading.
- Built-in rule packs: `nginx` (5xx spikes, upstream errors), `php` (fatal and parse errors,
  memory_limit, php-fpm max_children), `ssh` (brute force per IP, root logins) and `oom`
  (kernel OOM killer, cgroup OOM, systemd units).
- `${VAR}` / `${VAR:-default}` environment expansion in the config.
- CLI: `run` (with `--dry-run`), `check-config`, `test`, `notify-test`, `packs`, `healthcheck`.
- Container image on `ghcr.io/saizul/logwatch-alert` (non-root, member of `adm`, health check).

[Unreleased]: https://github.com/saizul/logwatch-alert/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/logwatch-alert/releases/tag/v0.1.0
