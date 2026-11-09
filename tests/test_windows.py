"""Phase 7: Windows EVTX — reading, parsing, routing with the official pySigma
Windows/Sysmon pipelines, detection, correlation, rule tests, watch folder, web."""

from __future__ import annotations

import gzip
import io
import json
import shutil
import sqlite3
import struct
import zipfile
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import page_csrf
from tests.test_web_phase1 import XSS, assert_inert, upload, wait_idle
from threatlens.cases import store as cases
from threatlens.config import Settings
from threatlens.detection.compiler import (
    NOT_APPLICABLE,
    NotApplicableError,
    compile_detection,
    tables_for,
)
from threatlens.detection.engine import BUILTIN_TABLES, DetectionEngine
from threatlens.detection.loader import load_rules
from threatlens.detection.testing import run_correlation_test, run_rule_test
from threatlens.ingest.files import ingest_path
from threatlens.ingest.pipeline import IngestOptions
from threatlens.ingest.readers import EvtxLines, allowed_filename, iter_lines, open_members
from threatlens.ingest.watch import InboxWatcher
from threatlens.parsers import ParseContext, ParseError, detect_parser, make_parser
from threatlens.parsers.windows import WindowsEventParser, logsource_for_channel
from threatlens.storage.db import connect, init_db, transaction

FIX = Path(__file__).parent / "fixtures" / "evtx"
SYSMON = FIX / "sysmon.evtx"
SECURITY = FIX / "security-short.evtx"
NEW_USER = FIX / "security-new-user.evtx"
SYSTEM = FIX / "system.evtx"
CTX = ParseContext()
MB = 1024 * 1024


def record(
    event_id: int,
    channel: str = "Security",
    data: dict[str, Any] | None = None,
    *,
    ts: str = "2026-01-05T10:00:00.1234567Z",
    record_id: int = 1,
    computer: str = "WS01",
    section: str = "EventData",
) -> str:
    """A Windows record as evtx_dump writes it (one JSON line)."""
    event: dict[str, Any] = {
        "System": {
            "Provider": {"#attributes": {"Name": "Test-Provider"}},
            "EventID": event_id,
            "TimeCreated": {"#attributes": {"SystemTime": ts}},
            "EventRecordID": record_id,
            "Channel": channel,
            "Computer": computer,
            "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 8}},
        },
    }
    if data is not None:
        event[section] = data
    return json.dumps({"Event": event})


def failed_logon(ip: str, n: int, user: str = "admin") -> str:
    return record(
        4625,
        data={"TargetUserName": user, "IpAddress": ip, "LogonType": 3},
        record_id=n,
        ts=f"2026-01-05T10:00:{n:02d}.0000000Z",
    )


# ---------------------------------------------------------------- parser


def test_parse_sysmon_process_creation() -> None:
    [first] = [line for _, line in iter_lines(EvtxLines(SYSMON, "s"))][:1]
    ev = WindowsEventParser().parse(first, CTX)
    f = ev.fields
    assert ev.logsource.table_name == "ev_windows_sysmon"
    assert f["EventID"] == 1 and f["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert f["Image"].endswith("PING.EXE") and f["ParentImage"].endswith("cmd.exe")
    assert f["Provider_Name"] == "Microsoft-Windows-Sysmon" and f["ExecutionProcessID"] == 2284
    assert f["host.name"] == "DESKTOP-2KGM189" and f["event.action"] == "process-created"
    assert f["process.name"] == "PING.EXE" and f["process.command_line"].startswith("ping")
    assert len(f["file.hash.sha256"]) == 64 and f["file.hash.md5"].islower()
    assert ev.ts == 1514293829136  # 7-digit fraction, UTC


def test_parse_security_failed_logon_and_ecs() -> None:
    ev = WindowsEventParser().parse(failed_logon("::ffff:203.0.113.9", 1), CTX)
    assert ev.logsource.table_name == "ev_windows_security"
    assert ev.fields["source.ip"] == "203.0.113.9"
    assert ev.fields["user.name"] == "admin" and ev.fields["event.action"] == "logon-failed"
    assert ev.fields["LogonType"] == 3 and ev.fields["event.code"] == "4625"
    bad_ip = WindowsEventParser().parse(
        record(4625, data={"IpAddress": "-", "TargetUserName": "-", "SubjectUserName": "bob"}),
        CTX,
    )
    assert "source.ip" not in bad_ip.fields and bad_ip.fields["user.name"] == "bob"


def test_parse_userdata_unnamed_data_and_collisions() -> None:
    p = WindowsEventParser()
    cleared = p.parse(
        record(
            1102,
            data={"LogFileCleared": {"#attributes": {"xmlns": "x"}, "SubjectUserName": "eve"}},
            section="UserData",
        ),
        CTX,
    )
    assert cleared.fields["SubjectUserName"] == "eve"
    assert cleared.fields["event.action"] == "audit-log-cleared"
    classic = p.parse(
        record(400, "Windows PowerShell", {"Data": ["Available", "None", "HostName=ConsoleHost"]}),
        CTX,
    )
    assert classic.logsource.table_name == "ev_windows_powershell_classic"
    assert "HostName=ConsoleHost" in classic.fields["Data"]
    clash = p.parse(record(1, data={"Channel": "spoofed", "Computer": "x"}), CTX)
    assert clash.fields["Channel"] == "spoofed" and clash.fields["System_Channel"] == "Security"
    qualified = p.parse(
        record(7036, "System").replace(
            '"EventID": 7036', '"EventID": {"#attributes": {"Qualifiers": 16384}, "#text": 7036}'
        ),
        CTX,
    )
    assert qualified.fields["EventID"] == 7036 and qualified.fields["EventIDQualifiers"] == 16384
    other = p.parse(record(1, "Some-Vendor/Operational"), CTX)
    assert other.logsource.table_name == "ev_windows"
    assert logsource_for_channel("microsoft-windows-sysmon/operational").service == "sysmon"
    for bad in ['{"Event": {}}', "[1]", "not json", '{"Event": {"System": {"EventID": 1}}}']:
        with pytest.raises(ParseError):
            p.parse(bad, CTX)


def test_autodetect_evtx_dump_jsonl() -> None:
    lines = [failed_logon("10.0.0.1", n) for n in range(1, 6)]
    assert detect_parser(lines, CTX).name == "evtx"
    assert make_parser("evtx").name == "evtx"


# ---------------------------------------------------------------- reading


def test_evtx_reader_plain_gz_zip_and_limits(tmp_path: Path) -> None:
    assert allowed_filename("Security.evtx") and allowed_filename("sysmon.evtx.gz")
    [m] = list(open_members(SYSMON, "sysmon.evtx", 100 * MB))
    assert m.parser == "evtx" and len(list(iter_lines(m.stream))) == 41
    gz = tmp_path / "sysmon.evtx.gz"
    gz.write_bytes(gzip.compress(SYSMON.read_bytes()))
    [m] = list(open_members(gz, gz.name, 100 * MB))
    assert m.name == "sysmon.evtx" and m.parser == "evtx"
    assert len(list(iter_lines(m.stream))) == 41
    zp = tmp_path / "logs.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(SECURITY, "dc01/Security.evtx")
        zf.writestr("dc01/Sysmon.evtx.gz", gzip.compress(SYSMON.read_bytes()))
        zf.writestr("notes.log", "hello\n")
    members = list(open_members(zp, zp.name, 100 * MB))
    assert [(m.name, m.parser) for m in members] == [
        ("logs.zip!dc01/Security.evtx", "evtx"),
        ("logs.zip!dc01/Sysmon.evtx", "evtx"),
        ("logs.zip!notes.log", None),
    ]
    from threatlens.ingest.readers import UnsafeInputError  # noqa: PLC0415

    with pytest.raises(UnsafeInputError, match="size limit"):
        list(open_members(SYSMON, "s.evtx", 1024))
    with pytest.raises(UnsafeInputError, match="limit"):
        list(open_members(gz, gz.name, 1024))


def test_damaged_evtx_is_reported_not_fatal(settings: Settings) -> None:
    data = bytearray(SYSMON.read_bytes())
    data[4096:4104] = b"\x00" * 8  # destroy the chunk magic
    struct.pack_into("<H", data, 42, 1)
    settings.ensure_dirs()
    bad = settings.data_dir / "bad.evtx"
    bad.write_bytes(bytes(data))
    init_db(settings.db_path)
    with closing(connect(settings.db_path)) as conn:
        [rep] = ingest_path(conn, bad, IngestOptions(), default_timezone="UTC", max_bytes=MB)
    assert rep.status == "done" and rep.inserted == 0 and rep.malformed >= 1
    assert "chunk" in rep.samples[0]["reason"].lower()
    garbage = settings.data_dir / "garbage.evtx"
    garbage.write_bytes(b"ElfFile\x00" + b"\xff" * 100)
    with closing(connect(settings.db_path)) as conn:
        [rep] = ingest_path(conn, garbage, IngestOptions(), default_timezone="UTC", max_bytes=MB)
    assert rep.status in ("failed", "done") and rep.inserted == 0


def test_readline_respects_size() -> None:
    lines = EvtxLines(SYSMON, "s")
    head = lines.readline(10)
    assert head == b'{"Event":{'
    rest = lines.readline()
    assert rest.endswith(b"\n") and json.loads(head + rest)["Event"]["System"]["EventID"] == 1


# ---------------------------------------------------------------- routing / compiling

CATALOG = list(BUILTIN_TABLES)
PROC_RULE = """title: Whoami run from cmd
id: 71000000-0000-0000-0000-000000000001
status: test
level: medium
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|endswith: '\\\\PING.EXE'
    ParentImage|endswith: '\\\\cmd.exe'
  condition: sel
tags: [attack.discovery, attack.t1018]
"""
FAILED_RULE = """title: Failed logon
id: 71000000-0000-0000-0000-000000000002
status: test
level: low
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4625}
  condition: sel
"""
REG_RULE = """title: Registry set by any process (Sysmon only field)
id: 71000000-0000-0000-0000-000000000003
status: test
level: low
logsource: {category: registry_set, product: windows}
detection:
  sel: {EventType: SetValue}
  condition: sel
"""
SERVICE_RULE = """title: Kernel driver service installed
id: 71000000-0000-0000-0000-000000000004
status: test
level: low
logsource: {product: windows, service: system}
detection:
  sel: {EventID: 7045, ServiceType: kernel mode driver}
  condition: sel
"""
PS_RULE = """title: Script block with Mimikatz
id: 71000000-0000-0000-0000-000000000005
status: test
level: high
logsource: {category: ps_script, product: windows}
detection:
  sel: {ScriptBlockText|contains: Invoke-Mimikatz}
  condition: sel
"""
BRUTE_CORR = """title: Many failed logons from one address
id: 71000000-0000-0000-0000-000000000006
status: test
level: high
correlation:
  type: event_count
  rules: [71000000-0000-0000-0000-000000000002]
  group-by: [IpAddress]
  timespan: 5m
  condition: {gte: 5}
  generate: true
"""


def test_routing_and_official_pipelines() -> None:
    proc = {"category": "process_creation", "product": "windows"}
    assert tables_for(proc, CATALOG) == ["ev_windows_security", "ev_windows_sysmon"]
    assert tables_for({"product": "windows", "service": "security"}, CATALOG) == [
        "ev_windows_security"
    ]
    assert tables_for({"category": "ps_script", "product": "windows"}, CATALOG) == [
        "ev_windows_powershell"
    ]
    assert tables_for({"category": "antivirus", "product": "windows"}, CATALOG) == []
    sysmon = compile_detection(PROC_RULE, "ev_windows_sysmon").sql
    assert "EventID=1" in sysmon and "Microsoft-Windows-Sysmon/Operational" in sysmon
    security = compile_detection(PROC_RULE, "ev_windows_security").sql
    assert "EventID=4688" in security and "NewProcessName" in security
    assert "ParentProcessName" in security and "Channel='Security'" in security
    with pytest.raises(NotApplicableError) as exc:
        compile_detection(REG_RULE, "ev_windows_security")
    assert str(exc.value).startswith(NOT_APPLICABLE)
    assert "EventID=13" in compile_detection(REG_RULE, "ev_windows_sysmon").sql
    ps = compile_detection(PS_RULE, "ev_windows_powershell").sql
    assert "EventID=4104" in ps and "PowerShellCore/Operational" in ps


# ---------------------------------------------------------------- detection end to end


@pytest.fixture
def env(tmp_path: Path) -> Iterator[tuple[Settings, sqlite3.Connection, DetectionEngine]]:
    s = Settings(data_dir=tmp_path / "d", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    init_db(s.db_path)
    s.rules_path.mkdir(parents=True)
    for i, text in enumerate([PROC_RULE, FAILED_RULE, REG_RULE, SERVICE_RULE, BRUTE_CORR]):
        (s.rules_path / f"r{i}.yml").write_text(text)
    with closing(connect(s.db_path)) as conn:
        engine = DetectionEngine(s)
        engine.reload(conn)
        yield s, conn, engine


def ingest(conn: sqlite3.Connection, engine: DetectionEngine, path: Path) -> None:
    reports = ingest_path(conn, path, IngestOptions(), default_timezone="UTC", max_bytes=100 * MB)
    for rep in reports:
        engine.run_ranges(conn, rep.chunks)


def alerts(conn: sqlite3.Connection, rule_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,)).fetchall()


def test_windows_rules_fire(env) -> None:  # type: ignore[no-untyped-def]
    _, conn, engine = env
    errors = dict(conn.execute("SELECT id, load_error FROM rules WHERE id LIKE '71%'").fetchall())
    assert set(errors.values()) == {None}, errors  # registry rule: only "not applicable"
    for path in (SYSMON, SECURITY, SYSTEM):
        ingest(conn, engine, path)
    [proc] = alerts(conn, "71000000-0000-0000-0000-000000000001")
    assert json.loads(proc["entities"])["host.name"] == "DESKTOP-2KGM189"
    [failed] = alerts(conn, "71000000-0000-0000-0000-000000000002")
    assert json.loads(failed["entities"])["user.name"] == "Administrator"
    reg = alerts(conn, "71000000-0000-0000-0000-000000000003")
    assert reg and all(a["event_count"] >= 1 for a in reg)
    service = alerts(conn, "71000000-0000-0000-0000-000000000004")
    assert sum(a["event_count"] for a in service) == 13
    # the not-applicable table is skipped silently, not reported as a failing rule
    assert engine.retro_hunt(conn, "71000000-0000-0000-0000-000000000003").errors == {}


def test_windows_correlation(env, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _, conn, engine = env
    log = tmp_path / "failed.jsonl"
    lines = [failed_logon("198.51.100.7", n) for n in range(1, 7)]
    lines += [failed_logon("198.51.100.8", n + 10) for n in range(1, 3)]
    log.write_text("\n".join(lines) + "\n")
    ingest(conn, engine, log)
    corr = alerts(conn, "71000000-0000-0000-0000-000000000006")
    assert len(corr) == 1 and corr[0]["kind"] == "correlation"
    assert corr[0]["event_count"] == 6
    assert json.loads(corr[0]["entities"])["IpAddress"] == "198.51.100.7"


def test_case_iocs_and_timeline_from_sysmon(env) -> None:  # type: ignore[no-untyped-def]
    _, conn, engine = env
    ingest(conn, engine, SYSMON)
    [proc] = alerts(conn, "71000000-0000-0000-0000-000000000001")
    with transaction(conn):
        case_id = cases.create(
            conn, title="ping", severity="low", actor="t", alert_ids=[proc["id"]]
        )
        cases.extract_iocs(conn, case_id, "t")
    kinds = {(r["kind"], r["value"].lower()) for r in cases.iocs(conn, case_id)}
    assert ("file_name", "ping.exe") in kinds
    assert any(k == "file_hash" and len(v) == 64 for k, v in kinds)
    entries, _ = cases.timeline(conn, case_id)
    assert any("process-created ping" in e.detail for e in entries if e.kind == "event")


# ---------------------------------------------------------------- rule tests (detection as code)


def test_rule_tests_with_evtx_and_jsonl_fixtures(tmp_path: Path) -> None:
    rules_dir, tests_dir = tmp_path / "rules", tmp_path / "tests"
    rules_dir.mkdir()
    (rules_dir / "a.yml").write_text(PROC_RULE)
    (rules_dir / "b.yml").write_text(FAILED_RULE)
    (rules_dir / "c.yml").write_text(BRUTE_CORR)
    loaded = {r.id: r for r in load_rules([(rules_dir, "user")]).rules}
    proc_dir = tests_dir / "71000000-0000-0000-0000-000000000001"
    proc_dir.mkdir(parents=True)
    # tp: one matching record (evtx_dump JSON); tn: the whole Security sample (EVTX)
    ping = next(line for _, line in iter_lines(EvtxLines(SYSMON, "s")))
    (proc_dir / "tp.jsonl").write_text(ping + "\n")
    shutil.copy(SECURITY, proc_dir / "tn.evtx")
    res = run_rule_test(loaded["71000000-0000-0000-0000-000000000001"], [tests_dir])
    assert res.status == "pass", res.messages
    (proc_dir / "tn.evtx").unlink()
    shutil.copy(SYSMON, proc_dir / "tn.evtx")  # contains the ping record -> must fail
    res = run_rule_test(loaded["71000000-0000-0000-0000-000000000001"], [tests_dir])
    assert res.status == "fail"
    corr_dir = tests_dir / "71000000-0000-0000-0000-000000000006"
    corr_dir.mkdir()
    (corr_dir / "tp.jsonl").write_text(
        "\n".join(failed_logon("192.0.2.1", n) for n in range(1, 6)) + "\n"
    )
    (corr_dir / "tn.jsonl").write_text(
        "\n".join(failed_logon(f"192.0.2.{n}", n) for n in range(1, 6)) + "\n"
    )
    res = run_correlation_test(
        loaded["71000000-0000-0000-0000-000000000006"],
        [loaded["71000000-0000-0000-0000-000000000002"]],
        [tests_dir],
    )
    assert res.status == "pass", res.messages


# ---------------------------------------------------------------- watch folder


def test_watch_folder_reads_evtx_once_and_again_when_it_grows(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path / "data", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    (s.data_dir / "inbox").mkdir()
    init_db(s.db_path)
    watcher = InboxWatcher(s, lambda: "UTC")
    target = s.data_dir / "inbox" / "dc01" / "Security.evtx"
    target.parent.mkdir()
    shutil.copy(NEW_USER, target)
    assert watcher.scan_once() == []  # first sighting: wait until it stops changing
    [rep] = watcher.scan_once()
    assert rep.inserted == 4 and rep.parser == "evtx" and rep.source == "dc01"
    assert watcher.scan_once() == []
    shutil.copy(SECURITY, target)  # replaced by a newer export (header changes)
    watcher.scan_once()
    reports = watcher.scan_once()
    assert sum(r.inserted for r in reports) == 7
    with closing(connect(s.db_path)) as conn:
        assert conn.execute("SELECT count(*) FROM ev_windows_security").fetchone()[0] == 11


# ---------------------------------------------------------------- web


def test_upload_evtx_and_xss_in_windows_fields(
    authed: TestClient, db: sqlite3.Connection, settings: Settings
) -> None:
    (settings.rules_path / "proc.yml").write_text(
        PROC_RULE.replace("Image|endswith: '\\\\PING.EXE'", "CommandLine|contains: alert")
    )
    csrf = page_csrf(authed.get("/rules").text)
    authed.post("/rules/reload", headers={"X-CSRF-Token": csrf})
    resp = upload(authed, [("sysmon.evtx", SYSMON.read_bytes())])
    assert resp.status_code == 200
    evil = record(
        1,
        "Microsoft-Windows-Sysmon/Operational",
        {
            "Image": f"C:\\{XSS}.exe",
            "ParentImage": "C:\\Windows\\cmd.exe",
            "CommandLine": XSS,
            "User": XSS,
        },
        computer=XSS,
    )
    upload(authed, [("evil.jsonl", (evil + "\n").encode())])
    wait_idle(authed)
    assert db.execute("SELECT count(*) FROM ev_windows_sysmon").fetchone()[0] == 42
    batch = db.execute("SELECT parser FROM ingest_batches WHERE file_name = 'sysmon.evtx'")
    assert batch.fetchone()[0] == "evtx"
    [alert_id] = [
        r[0]
        for r in db.execute(
            "SELECT id FROM alerts WHERE rule_id = '71000000-0000-0000-0000-000000000001'"
        )
    ]
    event_id = db.execute(
        "SELECT tl_id FROM ev_windows_sysmon WHERE CommandLine = ?", (XSS,)
    ).fetchone()[0]
    pages = [
        f"/alerts/{alert_id}",
        "/alerts",
        f"/events/ev_windows_sysmon/{event_id}",
        "/search?table=ev_windows_sysmon",
        "/ingest",
        "/rules",
    ]
    for page in pages:
        r = authed.get(page)
        assert r.status_code == 200, page
        assert_inert(r.text)
    hunt_csrf = page_csrf(authed.get("/hunt").text)
    r = authed.post(
        "/hunt",
        data={"csrf_token": hunt_csrf, "sql": "SELECT CommandLine FROM ev_windows_sysmon"},
    )
    assert_inert(r.text)


def test_ingest_page_offers_evtx(authed: TestClient) -> None:
    page = authed.get("/ingest").text
    assert ".evtx" in page and '<option value="evtx">' in page
    resp = upload(authed, [("fake.evtx", b"just text\n")])
    assert resp.status_code == 400 and "not an EVTX file" in resp.text
    resp = upload(authed, [("Security.log", SECURITY.read_bytes())])
    assert resp.status_code == 400 and "does not end in .evtx" in resp.text


def test_zip_bomb_like_evtx_in_zip_is_capped(settings: Settings) -> None:
    settings.ensure_dirs()
    init_db(settings.db_path)
    zp = settings.data_dir / "big.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("x.evtx", b"ElfFile\x00" + b"\x00" * (3 * MB))
    zp.write_bytes(buf.getvalue())
    with closing(connect(settings.db_path)) as conn:
        [rep] = ingest_path(conn, zp, IngestOptions(), default_timezone="UTC", max_bytes=MB)
    assert rep.status == "failed" and "limit" in (rep.error or "")
