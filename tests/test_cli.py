import io
import json
import os
import time
from pathlib import Path

import pytest

from logwatch_alert import cli
from logwatch_alert.config import parse_config
from logwatch_alert.notifiers import Dispatcher
from logwatch_alert.runner import Runner

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def write_config(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "logwatch-alert 0.1.0" in capsys.readouterr().out


def test_packs_list_and_show(capsys):
    assert cli.main(["packs"]) == 0
    out = capsys.readouterr().out
    assert "ssh: ssh-brute-force, ssh-root-login" in out
    assert cli.main(["packs", "oom"]) == 0
    assert "oom-kill" in capsys.readouterr().out


def test_test_command_with_pack(capsys):
    assert (
        cli.main(["test", "--pack", "ssh", "--hostname", "web1", "--expect-alert", str(EXAMPLES / "sample-auth.log")])
        == 0
    )
    captured = capsys.readouterr()
    assert "[WARNING] SSH brute force from 198.51.100.7 on web1" in captured.out
    assert "7 line(s), 1 alert(s)" in captured.err


def test_test_command_json_and_expect_alert_failure(tmp_path, capsys):
    log = tmp_path / "quiet.log"
    log.write_text("all good\n", encoding="utf-8")
    assert cli.main(["test", "--pack", "oom", "--expect-alert", str(log)]) == 1
    log.write_text("kernel: Out of memory: Killed process 1 (java)\n", encoding="utf-8")
    assert cli.main(["test", "--pack", "oom", "--json", str(log)]) == 0
    alert = json.loads(capsys.readouterr().out.splitlines()[0])
    assert alert["rule"] == "oom-kill" and alert["captures"]["process"] == "java"


def test_test_command_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("PHP Fatal error:  boom in /x.php:1\n"))
    assert cli.main(["test", "--pack", "php", "-"]) == 0
    assert "php-fatal-error" in capsys.readouterr().out


def test_check_config(tmp_path, capsys):
    path = write_config(
        tmp_path,
        """
sources: [/var/log/auth.log]
packs: [ssh]
notifiers:
  hook: {type: webhook, url: "https://example.invalid/${HOOK_SECRET}"}
""",
    )
    os.environ["HOOK_SECRET"] = "test-hook-secret"
    try:
        assert cli.main(["-c", path, "check-config"]) == 0
    finally:
        del os.environ["HOOK_SECRET"]
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["notifiers"] == {"hook": "webhook"}
    assert summary["rules"][0]["threshold"] == "5 in 10m"
    assert "test-hook-secret" not in captured.out
    assert "OK: 1 source(s), 2 rule(s), 1 notifier(s)" in captured.err


def test_config_error_exit_code(tmp_path, capsys):
    path = write_config(tmp_path, "rules: [{name: a}]\n")
    assert cli.main(["-c", path, "check-config"]) == 2
    assert "config error" in capsys.readouterr().err


def test_run_requires_notifiers_unless_dry_run(tmp_path, capsys):
    path = write_config(tmp_path, "sources: [/tmp/x.log]\npacks: [ssh]\n")
    assert cli.main(["-c", path, "run"]) == 2
    assert "no notifiers" in capsys.readouterr().err
    path = write_config(tmp_path, "packs: [ssh]\n")
    assert cli.main(["-c", path, "run", "--dry-run"]) == 2
    assert "no sources" in capsys.readouterr().err


def test_run_dry_run_on_stdin_exits_at_eof(tmp_path, monkeypatch, capsys):
    path = write_config(tmp_path, "packs: [oom]\nsettings: {poll_interval: 0.05}\n")
    monkeypatch.setattr("sys.stdin", io.StringIO("hello\nkernel: Out of memory: Killed process 7 (redis-server)\n"))
    assert cli.main(["-c", path, "run", "--stdin", "--dry-run"]) == 0
    alert = json.loads(capsys.readouterr().out.strip())
    assert alert["rule"] == "oom-kill"
    assert alert["source"] == "stdin"


def test_runner_tails_files_and_dispatches(tmp_path, recorder, clock):
    log = tmp_path / "app.log"
    log.write_text("ERROR old line that is skipped\n", encoding="utf-8")
    heartbeat = tmp_path / "hb"
    config = parse_config(
        {
            "sources": [{"path": str(tmp_path / "*.log"), "name": "app"}],
            "settings": {"heartbeat_file": str(heartbeat), "hostname": "h"},
            "rules": [{"name": "err", "pattern": "ERROR (?P<what>.+)", "sources": ["app"], "message": "{{ what }}"}],
            "notifiers": {"hook": {"type": "webhook", "url": "https://example.invalid/hook"}},
        },
        notifier_kwargs={"client": recorder.client()},
    )
    runner = Runner(config, Dispatcher(config.notifiers), clock=clock)
    runner.start()
    assert runner.step() == 0
    assert heartbeat.exists()
    with open(log, "a", encoding="utf-8") as handle:
        handle.write("INFO fine\nERROR database down\n")
    assert runner.step() == 2
    (request,) = recorder.requests
    body = json.loads(request.content)
    assert body["message"] == "database down"
    assert body["source"] == "app"


def test_runner_strip_and_text_format(clock):
    config = parse_config(
        {
            "sources": [{"stdin": True, "name": "web", "strip": r"^\S+\s+\| ", "format": "text"}],
            "rules": [{"name": "j", "json": {"level": "error"}}, {"name": "p", "pattern": "^boom$"}],
        }
    )
    sent = []
    dispatcher = Dispatcher({}, dry_run=True, printer=sent.append)
    runner = Runner(config, dispatcher, stdin=io.StringIO(""), clock=clock)
    runner.handle(config.sources[0], 'web-1  | {"level": "error"}')
    runner.handle(config.sources[0], "web-1  | boom")
    runner.handle(config.sources[0], "   ")
    assert [json.loads(s)["rule"] for s in sent] == ["p"]


def test_healthcheck(tmp_path, capsys):
    hb = tmp_path / "hb"
    assert cli.main(["healthcheck", "--file", str(hb)]) == 1
    hb.touch()
    assert cli.main(["healthcheck", "--file", str(hb)]) == 0
    old = time.time() - 600
    os.utime(hb, (old, old))
    assert cli.main(["healthcheck", "--file", str(hb), "--max-age", "60"]) == 1
    assert "unhealthy" in capsys.readouterr().err


def test_notify_test(tmp_path, monkeypatch, recorder, capsys):
    path = write_config(tmp_path, "notifiers:\n  hook: {type: webhook, url: 'https://example.invalid/h'}\n")
    real = cli.load_config
    monkeypatch.setattr(cli, "load_config", lambda p: real(p, notifier_kwargs={"client": recorder.client()}))
    assert cli.main(["-c", path, "notify-test"]) == 0
    assert "hook (webhook): sent" in capsys.readouterr().out
    assert json.loads(recorder.requests[0].content)["rule"] == "logwatch-alert-test"
    recorder.status = 500
    assert cli.main(["-c", path, "notify-test", "hook"]) == 1
    assert cli.main(["-c", path, "notify-test", "ghost"]) == 2
