import pytest

from logwatch_alert.config import available_packs, load_pack
from logwatch_alert.engine import Engine


def engine_for(pack, clock):
    return Engine(load_pack(pack, default_cooldown=600), hostname="web1", clock=clock)


def test_builtin_packs_are_listed():
    assert {"nginx", "php", "ssh", "oom"} <= set(available_packs())


@pytest.mark.parametrize("pack", ["nginx", "php", "ssh", "oom"])
def test_every_pack_loads(pack):
    rules = load_pack(pack, default_cooldown=600)
    assert rules
    assert all(rule.pack == pack and rule.description for rule in rules)


NGINX_OK = '203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "curl/8"'
NGINX_502 = '203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "POST /api/pay HTTP/2.0" 502 157 "-" "Mozilla/5.0"'


def test_nginx_5xx_spike(clock):
    engine = engine_for("nginx", clock)
    fired = []
    for _ in range(19):
        fired += engine.process("nginx", NGINX_502)
        fired += engine.process("nginx", NGINX_OK)
    assert fired == []
    (alert,) = engine.process("nginx", NGINX_502)
    assert alert.rule == "nginx-5xx-spike"
    assert alert.title == "[CRITICAL] nginx 5xx spike on web1"
    assert "Last: 502 POST /api/pay from 203.0.113.9" in alert.message


def test_nginx_upstream_errors(clock):
    engine = engine_for("nginx", clock)
    line = (
        "2026/10/10 13:55:36 [error] 1234#0: *5 upstream timed out (110: Connection timed out) while reading "
        'response header from upstream, client: 1.2.3.4, server: example.org, request: "GET / HTTP/1.1"'
    )
    alerts = [a for _ in range(10) for a in engine.process("nginx-error", line)]
    assert [a.rule for a in alerts] == ["nginx-upstream-errors"]
    assert alerts[0].group == "upstream timed out"


def test_php_fatal_error_grouped_by_location(clock):
    engine = engine_for("php", clock)
    line = (
        "[10-Oct-2026 13:55:36 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function foo() "
        "in /var/www/html/index.php:12"
    )
    (alert,) = engine.process("php", line)
    assert alert.rule == "php-fatal-error"
    assert alert.title == "[CRITICAL] PHP Fatal error on web1"
    assert "Location: /var/www/html/index.php:12" in alert.message
    assert engine.process("php", line) == []  # same location, cooling down
    other = "PHP Parse error:  syntax error, unexpected '}' in /var/www/html/a.php on line 3"
    (alert2,) = engine.process("php", other)
    assert "Location: /var/www/html/a.php:3" in alert2.message


def test_php_memory_and_fpm(clock):
    engine = engine_for("php", clock)
    mem = "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes)"
    assert {a.rule for a in engine.process("php", mem)} == {"php-fatal-error", "php-memory-exhausted"}
    fpm = "[10-Oct-2026 13:55:36] WARNING: [pool www] server reached pm.max_children setting (5), consider raising it"
    (alert,) = engine.process("fpm", fpm)
    assert alert.rule == "php-fpm-max-children"
    assert alert.group == "www"


def test_ssh_brute_force_per_ip(clock):
    engine = engine_for("ssh", clock)
    attacker = (
        "Oct 10 13:55:36 web1 sshd[2345]: Failed password for invalid user admin from 198.51.100.7 port 51234 ssh2"
    )
    invalid = "Oct 10 13:55:37 web1 sshd[2346]: Invalid user oracle from 198.51.100.7 port 51240"
    other = "Oct 10 13:55:38 web1 sshd[2347]: Failed password for root from 192.0.2.1 port 4000 ssh2"
    fired = []
    for line in (attacker, invalid, attacker, other, invalid, attacker):
        fired += engine.process("auth", line)
        clock.advance(30)
    assert len(fired) == 1
    assert fired[0].group == "198.51.100.7"
    assert fired[0].title == "[WARNING] SSH brute force from 198.51.100.7 on web1"
    assert "5 failed SSH logins from 198.51.100.7 in 10m (last user tried: admin)" in fired[0].message


def test_ssh_brute_force_counts(clock):
    engine = engine_for("ssh", clock)
    line = "sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
    fired = [a for _ in range(5) for a in engine.process("auth", line)]
    assert len(fired) == 1
    assert "5 failed SSH logins from 2001:db8::1 in 10m" in fired[0].message


def test_ssh_root_login(clock):
    engine = engine_for("ssh", clock)
    (alert,) = engine.process("auth", "sshd[9]: Accepted publickey for root from 203.0.113.5 port 5000 ssh2: ED25519")
    assert alert.rule == "ssh-root-login"
    assert engine.process("auth", "sshd[9]: Accepted publickey for deploy from 203.0.113.5 port 5000 ssh2") == []


@pytest.mark.parametrize(
    ("line", "process"),
    [
        ("kernel: Out of memory: Killed process 4242 (mysqld) total-vm:2000kB, anon-rss:1000kB", "mysqld"),
        ("kernel: Memory cgroup out of memory: Killed process 77 (php-fpm) total-vm:1kB", "php-fpm"),
        (
            "kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=abc,task=node,pid=99,uid=1000",
            "node",
        ),
    ],
)
def test_oom_kill(clock, line, process):
    engine = engine_for("oom", clock)
    (alert,) = engine.process("kern", line)
    assert alert.rule == "oom-kill"
    assert alert.group == process


def test_oom_systemd_unit(clock):
    engine = engine_for("oom", clock)
    (alert,) = engine.process(
        "journal", "systemd[1]: redis.service: A process of this unit has been killed by the OOM killer."
    )
    assert alert.group == "redis.service"
