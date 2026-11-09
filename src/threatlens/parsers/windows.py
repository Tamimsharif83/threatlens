"""Windows event log records (EVTX), as JSON.

EVTX files are binary; `threatlens.ingest.readers` turns every record into one
JSON line with the Rust ``evtx`` library, in the layout ``evtx_dump -o jsonl``
also writes::

    {"Event": {"System": {...}, "EventData": {...}}}

This parser flattens a record the way Sigma's Windows rules expect it: System
values as ``EventID``, ``Channel``, ``Computer``, ``Provider_Name`` ...; named
``EventData``/``UserData`` values under their own names (``TargetUserName``,
``Image``, ``CommandLine`` ...); unnamed data as ``Data``. A few ECS fields are
added for alert grouping, pivots and IOC extraction (``host.name``,
``user.name``, ``source.ip``, ``file.hash.*`` ...).

Flat exports are read too: one JSON object per event with ``Channel`` and
``EventID`` at the top level, as in the OTRF Security-Datasets (Mordor),
NXLog's ``to_json()`` and many Winlogbeat-to-file pipelines. Their fields
already carry the Windows names; ``Hostname`` and ``SourceName`` become
``Computer`` and ``Provider_Name``.

The channel picks the Sigma log source and so the event table:
``Security`` -> ``product: windows, service: security`` -> ``ev_windows_security``.
The channel names come from pySigma's Windows pipeline, so routing matches the
official pipelines used to compile the rules.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from sigma.pipelines.common import windows_logsource_mapping

from threatlens.normalize.schema import Event, LogSource
from threatlens.normalize.values import flatten
from threatlens.parsers.base import ParseContext, ParseError, Parser
from threatlens.timeutil import TimestampError, parse_iso8601

WINDOWS = "windows"
MAX_DATA_VALUES = 64
EMPTY = ("", "-", "(null)", "NULL")

# Short, stable names for the events analysts look at most (shown in timelines).
EVENT_ACTIONS: dict[tuple[str, int], str] = {
    ("security", 1102): "audit-log-cleared",
    ("security", 4624): "logon",
    ("security", 4625): "logon-failed",
    ("security", 4634): "logoff",
    ("security", 4648): "logon-explicit-credentials",
    ("security", 4672): "special-privileges-assigned",
    ("security", 4688): "process-created",
    ("security", 4697): "service-installed",
    ("security", 4698): "scheduled-task-created",
    ("security", 4719): "audit-policy-changed",
    ("security", 4720): "user-account-created",
    ("security", 4722): "user-account-enabled",
    ("security", 4724): "password-reset",
    ("security", 4726): "user-account-deleted",
    ("security", 4728): "added-to-global-group",
    ("security", 4732): "added-to-local-group",
    ("security", 4740): "user-account-locked-out",
    ("security", 4756): "added-to-universal-group",
    ("security", 4768): "kerberos-tgt-requested",
    ("security", 4769): "kerberos-service-ticket-requested",
    ("security", 4771): "kerberos-preauth-failed",
    ("security", 4776): "credential-validation",
    ("security", 5140): "network-share-accessed",
    ("security", 5145): "network-share-object-checked",
    ("sysmon", 1): "process-created",
    ("sysmon", 3): "network-connection",
    ("sysmon", 5): "process-terminated",
    ("sysmon", 6): "driver-loaded",
    ("sysmon", 7): "image-loaded",
    ("sysmon", 8): "remote-thread-created",
    ("sysmon", 10): "process-accessed",
    ("sysmon", 11): "file-created",
    ("sysmon", 12): "registry-object-added-or-deleted",
    ("sysmon", 13): "registry-value-set",
    ("sysmon", 15): "file-stream-created",
    ("sysmon", 22): "dns-query",
    ("sysmon", 23): "file-deleted",
    ("powershell", 4103): "powershell-module-logged",
    ("powershell", 4104): "powershell-script-block",
    ("powershell-classic", 400): "powershell-engine-started",
    ("powershell-classic", 800): "powershell-pipeline-executed",
    ("system", 104): "event-log-cleared",
    ("system", 7036): "service-state-changed",
    ("system", 7045): "service-installed",
}

# Time keys of flat exports, best first.
_FLAT_TIME_KEYS = ("TimeCreated", "@timestamp", "EventTime", "TimeGenerated", "timestamp")
# Flat-export names -> the names Sigma's Windows rules and this parser use.
_FLAT_ALIASES = {
    "Hostname": "Computer",
    "SourceName": "Provider_Name",
    "ProviderName": "Provider_Name",
}

# First present, meaningful value wins.
_USER_FIELDS = ("TargetUserName", "SubjectUserName", "User", "UserName", "AccountName")
_SOURCE_IP_FIELDS = ("IpAddress", "SourceIp", "SourceAddress", "ClientAddress", "WorkstationIp")
_DEST_IP_FIELDS = ("DestinationIp", "DestAddress")
_HASH_PART = re.compile(r"(MD5|SHA1|SHA256)=([0-9A-Fa-f]+)")


@lru_cache(maxsize=1)
def channel_services() -> dict[str, str]:
    """Lower-cased channel name -> Sigma service (``security``, ``sysmon`` ...)."""
    out: dict[str, str] = {}
    for service, channels in windows_logsource_mapping.items():
        for channel in [channels] if isinstance(channels, str) else channels:
            out.setdefault(channel.lower(), service)
    return out


def logsource_for_channel(channel: str | None) -> LogSource:
    service = channel_services().get((channel or "").lower())
    return LogSource(product=WINDOWS, service=service)


def _text(value: object) -> object:
    """An EVTX JSON value as a scalar: ``{"#text": x}`` -> x, lists joined."""
    if isinstance(value, Mapping):
        if "#text" in value:
            return _text(value["#text"])
        return json.dumps(value, ensure_ascii=False, default=str)
    if isinstance(value, list):
        parts = [_text(v) for v in value[:MAX_DATA_VALUES]]
        return "\n".join("" if p is None else str(p) for p in parts)
    return value


def _attrs(node: object) -> Mapping[str, Any]:
    if isinstance(node, Mapping):
        attrs = node.get("#attributes")
        if isinstance(attrs, Mapping):
            return attrs
    return {}


def _system_fields(system: Mapping[str, Any]) -> dict[str, Any]:
    f: dict[str, Any] = {}
    provider = _attrs(system.get("Provider"))
    for key in ("Name", "Guid", "EventSourceName"):
        if provider.get(key) not in (None, ""):
            f[f"Provider_{key}"] = provider[key]
    for key in ("EventID", "Version", "Level", "Task", "Opcode", "Keywords", "EventRecordID"):
        if key in system and system[key] is not None:
            f[key] = _text(system[key])
    qualifiers = _attrs(system.get("EventID")).get("Qualifiers")
    if qualifiers not in (None, ""):
        f["EventIDQualifiers"] = qualifiers
    for key in ("Channel", "Computer"):
        if system.get(key):
            f[key] = _text(system[key])
    execution = _attrs(system.get("Execution"))
    for key in ("ProcessID", "ThreadID"):
        if execution.get(key) is not None:
            f[f"Execution{key}"] = execution[key]
    user_id = _attrs(system.get("Security")).get("UserID")
    if user_id:
        f["UserID"] = user_id
    correlation = _attrs(system.get("Correlation"))
    for key in ("ActivityID", "RelatedActivityID"):
        if correlation.get(key):
            f[key] = correlation[key]
    return f


def _data_fields(node: object, out: dict[str, Any], prefix: str = "") -> None:
    """EventData / UserData children -> fields (UserData's wrapper element is dropped)."""
    if not isinstance(node, Mapping):
        if node not in (None, ""):
            out.setdefault("Data", _text(node))
        return
    for key, value in node.items():
        if key == "#attributes":
            continue
        if key in ("Data", "#text"):  # unnamed data: one string or a list
            if value not in (None, ""):
                out["Data"] = _text(value)
            continue
        name = f"{prefix}{key}"
        if isinstance(value, Mapping) and "#text" not in value:
            _data_fields(value, out, prefix)  # e.g. UserData.LogFileCleared.SubjectUserName
        elif value is not None:
            out[name] = _text(value)


def _first(fields: Mapping[str, Any], names: tuple[str, ...], *, ip: bool = False) -> object:
    for name in names:
        value = fields.get(name)
        if value is None or str(value).strip() in EMPTY:
            continue
        if ip:
            text = str(value).strip().removeprefix("::ffff:")
            try:
                ipaddress.ip_address(text)
            except ValueError:
                continue
            return text
        return value
    return None


def _ecs(fields: dict[str, Any], service: str | None) -> None:
    """ECS fields for grouping, pivots, IOC extraction and timelines."""
    if fields.get("Computer"):
        fields["host.name"] = fields["Computer"]
    event_id = fields.get("EventID")
    if event_id is not None:
        fields["event.code"] = str(event_id)
        action = EVENT_ACTIONS.get((service or "", _int(event_id)))
        fields["event.action"] = action or f"event-{event_id}"
    user = _first(fields, _USER_FIELDS)
    if user is not None:
        fields["user.name"] = user
    src = _first(fields, _SOURCE_IP_FIELDS, ip=True)
    if src is not None:
        fields["source.ip"] = src
    dst = _first(fields, _DEST_IP_FIELDS, ip=True)
    if dst is not None:
        fields["destination.ip"] = dst
    image = _first(fields, ("Image", "NewProcessName"))
    if image is not None:
        fields["process.executable"] = image
        fields["process.name"] = str(image).replace("/", "\\").rsplit("\\", 1)[-1]
    if fields.get("CommandLine"):
        fields["process.command_line"] = fields["CommandLine"]
    target = _first(fields, ("TargetFilename",))
    if target is not None:
        fields["file.path"] = target
        fields["file.name"] = str(target).replace("/", "\\").rsplit("\\", 1)[-1]
    hashes = fields.get("Hashes") or fields.get("Hash")
    if isinstance(hashes, str):
        for algo, value in _HASH_PART.findall(hashes):
            fields[f"file.hash.{algo.lower()}"] = value.lower()
    if fields.get("QueryName"):
        fields["dns.question.name"] = fields["QueryName"]


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return -1


class WindowsEventParser(Parser):
    name = "evtx"

    def parse(self, line: str, ctx: ParseContext) -> Event:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ParseError(f"invalid JSON: {exc}") from exc
        if isinstance(obj, dict) and "Event" not in obj and "Channel" in obj and "EventID" in obj:
            return self._parse_flat(obj, line, ctx)
        event = obj.get("Event") if isinstance(obj, dict) else None
        if not isinstance(event, dict) or not isinstance(event.get("System"), dict):
            raise ParseError("not a Windows event record (no Event.System, no Channel/EventID)")
        system: dict[str, Any] = event["System"]
        created = _attrs(system.get("TimeCreated")).get("SystemTime")
        if not created:
            raise ParseError("record has no TimeCreated/SystemTime")
        try:
            ts = parse_iso8601(str(created), ctx.tz)
        except TimestampError as exc:
            raise ParseError(f"bad timestamp {str(created)[:64]!r}: {exc}") from exc
        fields = _system_fields(system)
        data: dict[str, Any] = {}
        for section in ("EventData", "UserData"):
            if section in event:
                _data_fields(event[section], data)
        rendering = event.get("RenderingInfo")
        if isinstance(rendering, Mapping) and rendering.get("Message"):
            data.setdefault("Message", _text(rendering["Message"]))
        extra: dict[str, Any] = {}
        for key, value in data.items():
            if key in fields:  # a System name reused in EventData: keep both
                extra[f"System_{key}"] = fields[key]
            fields[key] = value
        fields.update(extra)
        logsource = logsource_for_channel(fields.get("Channel"))
        _ecs(fields, logsource.service)
        return Event(ts, fields, logsource, raw=line)

    def _parse_flat(self, obj: dict[str, Any], line: str, ctx: ParseContext) -> Event:
        created: object = next((obj[k] for k in _FLAT_TIME_KEYS if obj.get(k)), None)
        if isinstance(created, Mapping):  # {"SystemTime": "..."}
            created = created.get("SystemTime") or _attrs(created).get("SystemTime")
        if not created:
            raise ParseError("Windows event has no TimeCreated/@timestamp")
        try:
            ts = parse_iso8601(str(created), ctx.tz)
        except TimestampError as exc:
            raise ParseError(f"bad timestamp {str(created)[:64]!r}: {exc}") from exc
        fields: dict[str, Any] = {}
        for key, value in flatten(obj).items():
            if value is None or key in _FLAT_TIME_KEYS:
                continue
            fields[key] = _text(value)
        for flat, name in _FLAT_ALIASES.items():
            if flat in fields and name not in fields:
                fields[name] = fields[flat]
        event_id = _int(fields["EventID"])
        if event_id >= 0:
            fields["EventID"] = event_id
        logsource = logsource_for_channel(str(fields.get("Channel") or ""))
        _ecs(fields, logsource.service)
        return Event(ts, fields, logsource, raw=line)
