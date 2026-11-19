# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## What counts as a vulnerability

- A bot token, webhook URL, SMTP password or other secret from the config appearing in
  logs, error messages or alert text
- A crafted log line that makes logwatch-alert execute code, read files it was not
  configured to read, or send alerts to a destination that is not configured
- A crafted log line or template that escapes the template sandbox (anything beyond
  dotted variable lookups and the documented filters)
- Unbounded memory or CPU use caused by log content (for example very long lines or
  millions of distinct `group_by` keys) despite the documented limits

Regular expressions in your own rules are trusted configuration; a slow regex you wrote
yourself is not a vulnerability, but a slow regex in a built-in pack is.

## Reporting

Please **do not** open a public issue. Use
[GitHub private vulnerability reporting](https://github.com/saizul/logwatch-alert/security/advisories/new)
with the version, the impact and steps to reproduce. Do not include real tokens or
private log data.

You will get an answer within 5 working days. Fixes are released as soon as
possible and credited in the changelog unless you prefer otherwise.

## Hardening checklist for operators

- Mount log directories read-only (`/var/log:/var/log:ro`).
- Keep secrets in environment variables (`${TELEGRAM_BOT_TOKEN}`), not in the YAML file.
- Run the container as the default non-root user; add groups (`group_add`) instead of
  running as root when a log file is not readable.
- Remember that alert text contains log lines: send alerts only to channels whose members
  may see those logs.
