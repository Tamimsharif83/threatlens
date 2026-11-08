"""Linux ``auth.log`` / ``secure`` (sshd, sudo, su, PAM, useradd/usermod, cron).

Accepted line headers:

* RFC 3164: ``Nov  8 10:00:00 host sshd[123]: message`` (no year: inferred)
* ISO / RSYSLOG_FileFormat: ``2026-11-08T10:00:00.123456+00:00 host sshd[123]: message``
* RFC 5424: ``<38>1 2026-11-08T10:00:00Z host sshd 123 - - message``

Every line is kept (``message``, ``process.name``, ``host.hostname``); well-known
messages additionally get ``event.action``, ``event.outcome``, ``user.name``,
``source.ip`` and friends, so rules can use fields instead of free text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from threatlens.normalize.schema import LINUX_AUTH, Event
from threatlens.parsers.base import ParseContext, ParseError, Parser
from threatlens.timeutil import TimestampError, parse_iso8601, parse_syslog_time

_PRI = r"(?:<(?P<pri>\d{1,3})>)?"
_PROC = r"(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)"
_RFC3164 = re.compile(
    rf"^{_PRI}(?P<mon>[A-Z][a-z]{{2}}) {{1,2}}(?P<day>\d{{1,2}}) "
    rf"(?P<clock>\d{{2}}:\d{{2}}:\d{{2}}) (?P<host>\S+) {_PROC}$"
)
_ISO = re.compile(
    rf"^{_PRI}(?P<iso>\d{{4}}-\d{{2}}-\d{{2}}[T ]\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?"
    rf"(?:Z|[+-]\d{{2}}:?\d{{2}})?) (?P<host>\S+) {_PROC}$"
)
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<iso>\S+) (?P<host>\S+) (?P<proc>\S+) (?P<pid>\S+) \S+ "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(?P<msg>.*)$"
)

Fields = dict[str, Any]
Extractor = Callable[[re.Match[str], Fields], None]
_RULES: dict[str, list[tuple[re.Pattern[str], Extractor]]] = {}


def _rule(procs: tuple[str, ...], pattern: str) -> Callable[[Extractor], Extractor]:
    compiled = re.compile(pattern)

    def register(fn: Extractor) -> Extractor:
        for proc in procs:
            _RULES.setdefault(proc, []).append((compiled, fn))
        return fn

    return register


def _set(f: Fields, action: str, outcome: str | None = None, **values: object) -> None:
    f["event.action"] = action
    if outcome:
        f["event.outcome"] = outcome
    for key, value in values.items():
        if value not in (None, ""):
            f[key.replace("__", ".")] = value


def _port(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


# ---------------------------------------------------------------- sshd

_SSHD = ("sshd", "sshd-session")


@_rule(_SSHD, r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)")
def _ssh_accepted(m: re.Match[str], f: Fields) -> None:
    _set(
        f,
        "ssh_login",
        "success",
        user__name=m[2],
        source__ip=m[3],
        source__port=_port(m[4]),
        linux__auth__method=m[1],
    )


@_rule(_SSHD, r"^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)")
def _ssh_failed(m: re.Match[str], f: Fields) -> None:
    _set(
        f,
        "ssh_login",
        "failure",
        user__name=m[3],
        source__ip=m[4],
        source__port=_port(m[5]),
        linux__auth__method=m[1],
    )
    if m[2]:
        f["linux.auth.invalid_user"] = "true"


@_rule(_SSHD, r"^Invalid user (\S*) from (\S+)(?: port (\d+))?")
def _ssh_invalid_user(m: re.Match[str], f: Fields) -> None:
    _set(
        f, "ssh_invalid_user", "failure", user__name=m[1], source__ip=m[2], source__port=_port(m[3])
    )


@_rule(
    _SSHD,
    r"^(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(\S+) "
    r"from (\S+) port (\d+)",
)
def _ssh_max_attempts(m: re.Match[str], f: Fields) -> None:
    _set(
        f,
        "ssh_max_auth_attempts",
        "failure",
        user__name=m[1],
        source__ip=m[2],
        source__port=_port(m[3]),
    )


@_rule(
    _SSHD,
    r"^(Connection closed|Connection reset) by "
    r"(?:(?:invalid |authenticating )?user (\S+) )?(\S+) port (\d+)",
)
def _ssh_closed(m: re.Match[str], f: Fields) -> None:
    _set(f, "ssh_disconnect", None, user__name=m[2], source__ip=m[3], source__port=_port(m[4]))


@_rule(_SSHD, r"^Disconnected from (?:(?:invalid |authenticating )?user (\S+) )?(\S+) port (\d+)")
def _ssh_disconnected(m: re.Match[str], f: Fields) -> None:
    _set(f, "ssh_disconnect", None, user__name=m[1], source__ip=m[2], source__port=_port(m[3]))


@_rule(_SSHD, r"^Received disconnect from (\S+) port (\d+)")
def _ssh_received_disconnect(m: re.Match[str], f: Fields) -> None:
    _set(f, "ssh_disconnect", None, source__ip=m[1], source__port=_port(m[2]))


@_rule(_SSHD, r"^Did not receive identification string from (\S+)(?: port (\d+))?")
def _ssh_no_ident(m: re.Match[str], f: Fields) -> None:
    _set(f, "ssh_no_identification", "failure", source__ip=m[1], source__port=_port(m[2]))


# ---------------------------------------------------------------- PAM (any program)

_PAM_AUTH_FAIL = re.compile(r"^pam_unix\((\S+?):auth\): authentication failure;(.*)$")
_PAM_SESSION = re.compile(
    r"^pam_unix\((\S+?):session\): session (opened|closed) for user (\S+?)(?:\(uid=\d+\))?"
    r"(?: by (\S*?)(?:\(uid=(\d+)\))?)?$"
)
_KV = re.compile(r"(\w+)=(\S*)")


def _pam(msg: str, f: Fields) -> bool:
    m = _PAM_AUTH_FAIL.match(msg)
    if m:
        kv = dict(_KV.findall(m[2]))
        _set(
            f,
            "authentication_failure",
            "failure",
            user__name=kv.get("user"),
            source__ip=kv.get("rhost"),
            linux__pam__service=m[1],
        )
        if kv.get("ruser"):
            f["linux.pam.ruser"] = kv["ruser"]
        return True
    m = _PAM_SESSION.match(msg)
    if m:
        _set(f, f"session_{m[2]}", "success", user__name=m[3], linux__pam__service=m[1])
        if m[4]:
            f["user.name"] = m[4]
            f["user.target.name"] = m[3]
        return True
    return False


# ---------------------------------------------------------------- sudo / su

_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<reason>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ;(?: GROUP=\S+ ;)?(?: TSID=\S+ ;)?(?: ENV=.*? ;)? COMMAND=(?P<cmd>.*)$"
)


@_rule(("sudo",), _SUDO.pattern)
def _sudo(m: re.Match[str], f: Fields) -> None:
    reason = (m["reason"] or "").strip()
    _set(
        f,
        "sudo_command",
        "failure" if reason else "success",
        user__name=m["user"],
        user__target__name=m["target"],
        process__command_line=m["cmd"],
        process__working_directory=m["pwd"],
        linux__tty=m["tty"],
    )
    if reason:
        f["event.reason"] = reason


@_rule(("su",), r"^(?:Successful su for (\S+) by (\S+)|FAILED su for (\S+) by (\S+))")
def _su_legacy(m: re.Match[str], f: Fields) -> None:
    if m[1]:
        _set(f, "su", "success", user__name=m[2], user__target__name=m[1])
    else:
        _set(f, "su", "failure", user__name=m[4], user__target__name=m[3])


@_rule(("su",), r"^\(to (\S+)\) (\S+) on (\S+)")
def _su_to(m: re.Match[str], f: Fields) -> None:
    _set(f, "su", "success", user__name=m[2], user__target__name=m[1], linux__tty=m[3])


# ---------------------------------------------------------------- accounts

_ACCOUNT_PROCS = (
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupdel",
    "gpasswd",
    "passwd",
    "chpasswd",
    "chage",
)


@_rule(
    _ACCOUNT_PROCS, r"^new user: name=([^,]+), UID=(\d+), GID=(\d+), home=([^,]+), shell=([^,\s]+)"
)
def _new_user(m: re.Match[str], f: Fields) -> None:
    _set(
        f,
        "user_created",
        "success",
        user__target__name=m[1],
        user__target__id=m[2],
        user__target__group__id=m[3],
        linux__home=m[4],
        linux__shell=m[5],
    )


@_rule(_ACCOUNT_PROCS, r"^new group: name=([^,]+), GID=(\d+)")
def _new_group(m: re.Match[str], f: Fields) -> None:
    _set(f, "group_created", "success", group__name=m[1], group__id=m[2])


@_rule(_ACCOUNT_PROCS, r"^add '([^']+)' to (?:shadow )?group '([^']+)'")
def _add_to_group(m: re.Match[str], f: Fields) -> None:
    _set(f, "user_added_to_group", "success", user__target__name=m[1], group__name=m[2])


@_rule(_ACCOUNT_PROCS, r"^(?:delete user|removed user|user) '([^']+)'(?: removed)?")
def _del_user(m: re.Match[str], f: Fields) -> None:
    _set(f, "user_deleted", "success", user__target__name=m[1])


@_rule(
    _ACCOUNT_PROCS,
    r"^(?:change user '([^']+)' password|pam_unix\(\S+:chauthtok\): "
    r"password changed for (\S+))",
)
def _password_changed(m: re.Match[str], f: Fields) -> None:
    _set(f, "password_changed", "success", user__target__name=m[1] or m[2])


@_rule(_ACCOUNT_PROCS, r"^(lock|unlock) user '([^']+)'")
def _lock_user(m: re.Match[str], f: Fields) -> None:
    _set(f, f"user_{m[1]}ed", "success", user__target__name=m[2])


# ---------------------------------------------------------------- cron / logind


@_rule(("CRON", "cron", "crond"), r"^\((\S+)\) CMD \((.*)\)$")
def _cron(m: re.Match[str], f: Fields) -> None:
    _set(f, "cron_command", "success", user__name=m[1], process__command_line=m[2])


@_rule(("systemd-logind",), r"^New session (\S+) of user (\S+?)\.?$")
def _logind_new(m: re.Match[str], f: Fields) -> None:
    _set(f, "session_opened", "success", user__name=m[2], linux__session__id=m[1])


@_rule(("systemd-logind",), r"^Removed session (\S+?)\.?$")
def _logind_removed(m: re.Match[str], f: Fields) -> None:
    _set(f, "session_closed", "success", linux__session__id=m[1])


class LinuxAuthParser(Parser):
    name = "linux-auth"

    def parse(self, line: str, ctx: ParseContext) -> Event:
        m = _RFC3164.match(line) or _ISO.match(line) or _RFC5424.match(line)
        if not m:
            raise ParseError("not a syslog line (RFC 3164, RFC 5424 or ISO timestamp)")
        groups = m.groupdict()
        try:
            if groups.get("iso"):
                ts = parse_iso8601(groups["iso"], ctx.tz)
            else:
                ts = parse_syslog_time(
                    groups["mon"], groups["day"], groups["clock"], ctx.tz, ctx.reference_time
                )
        except TimestampError as exc:
            raise ParseError(str(exc)) from exc

        proc = groups["proc"]
        msg = groups["msg"] or ""
        f: Fields = {
            "host.hostname": groups["host"],
            "host.name": groups["host"],
            "process.name": proc,
            "message": msg,
            "event.dataset": "linux.auth",
        }
        pid = groups.get("pid")
        if pid and pid.isdigit():
            f["process.pid"] = int(pid)
        if groups.get("pri"):
            pri = int(groups["pri"])
            f["log.syslog.facility.code"] = pri >> 3
            f["log.syslog.severity.code"] = pri & 7

        if not _pam(msg, f):
            for pattern, extract in _RULES.get(proc, ()):
                found = pattern.match(msg)
                if found:
                    extract(found, f)
                    break
        if "event.action" in f:
            f["event.category"] = (
                "iam"
                if f["event.action"].startswith(("user_", "group_", "password"))
                else "authentication"
            )
        return Event(ts=ts, fields=f, logsource=LINUX_AUTH, raw=line)
