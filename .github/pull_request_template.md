## What does this pull request do?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Type

- [ ] New or improved rule pack
- [ ] New notifier
- [ ] Tailer, engine, config or CLI change
- [ ] Bug fix
- [ ] Documentation

## Checklist

- [ ] Tests added or updated (`pytest` passes; no network, notifiers use `httpx.MockTransport` or `FakeSMTP`)
- [ ] `ruff check . && ruff format --check .` passes
- [ ] Rule packs have tests with real-looking sample lines that should and should not match
- [ ] Notifier errors and logs never contain tokens, webhook URLs or passwords
- [ ] No real secrets or private log data in tests or examples
- [ ] README and `examples/` updated for new options
- [ ] CHANGELOG.md updated under "Unreleased"
