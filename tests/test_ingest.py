from __future__ import annotations

import gzip
import io
import json
import sqlite3
import zipfile
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from threatlens.ingest import readers
from threatlens.ingest.files import ingest_path, source_name_for
from threatlens.ingest.pipeline import IngestOptions, OccurrenceCounter
from threatlens.ingest.readers import UnsafeInputError, allowed_filename, iter_lines, open_members
from threatlens.normalize.schema import Event, LogSource
from threatlens.parsers import FieldMapping
from threatlens.storage import events as events_mod
from threatlens.storage.db import connect, init_db, transaction
from threatlens.storage.events import EventStore, PreparedEvent, RawCodec, content_hash
from threatlens.synth import auth_lines, ecs_lines, web_lines

GB = 1024**3


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    init_db(tmp_path / "t.db")
    with closing(connect(tmp_path / "t.db")) as c:
        yield c


def write(path: Path, lines: list[str] | str) -> Path:
    text = lines if isinstance(lines, str) else "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")
    return path


def consume(path: Path, name: str, limit: int = GB) -> None:
    """Read every line of every member (raises whatever the reader raises)."""
    for member in open_members(path, name, limit):
        list(iter_lines(member.stream))


def ingest(conn: sqlite3.Connection, path: Path, **kw: object):  # type: ignore[no-untyped-def]
    opts = IngestOptions(**kw)  # type: ignore[arg-type]
    return ingest_path(conn, path, opts, default_timezone="UTC", max_bytes=GB)


# ---------------------------------------------------------------- file names & readers


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("access.log", True),
        ("access.log.1", True),
        ("access.log.2.gz", True),
        ("app.jsonl", True),
        ("events.ndjson", True),
        ("logs.zip", True),
        ("auth", True),
        ("secure-20260101", True),
        ("C:\\logs\\access.log", True),
        ("evil.exe", False),
        ("script.sh", False),
        (".hidden.log", False),
        ("notes", False),
        ("", False),
    ],
)
def test_allowed_filename(name: str, ok: bool) -> None:
    assert allowed_filename(name) is ok


def test_iter_lines_handles_bom_crlf_blank_and_long_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readers, "MAX_LINE_BYTES", 32)
    data = b"\xef\xbb\xbffirst\r\n\n   \nsecond\n" + b"x" * 100 + b"\nlast"
    out = list(iter_lines(io.BytesIO(data)))
    assert out[0] == (1, "first")
    assert out[1] == (4, "second")
    assert out[2][0] == 5 and out[2][1].startswith("\x00TOO_LONG\x00")
    assert out[3] == (6, "last")


def test_binary_files_refused(tmp_path: Path) -> None:
    for name, data in [
        ("a.log", b"MZ\x90\x00binary"),
        ("b.log", b"\x7fELF\x02\x01"),
        ("c.log", b"text\x00with nul" * 40),
        ("u.log", "a UTF-16 log line\n".encode("utf-16") * 20),
        ("d.log", b"ElfFile\x00rest"),
    ]:
        (tmp_path / name).write_bytes(data)
        with pytest.raises(UnsafeInputError):
            consume(tmp_path / name, name)


def test_a_few_nul_bytes_do_not_hide_a_log(conn: sqlite3.Connection, tmp_path: Path) -> None:
    """A TLS handshake sent to an HTTP port is logged as raw bytes, NULs included.
    One such request must not make the whole access log un-ingestable."""
    good = '192.0.2.1 - - [11/Jul/2018:09:31:57 +0300] "GET / HTTP/1.1" 200 973\n'
    tls = '192.0.2.9 - - [11/Jul/2018:09:32:02 +0300] "\x16\x03\x01\x02\x00\x01\x00" 400 -\n'
    p = tmp_path / "access.log"
    p.write_bytes((good + tls + good.replace("09:31", "09:33")).encode("latin-1"))
    [rep] = ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**20)
    assert rep.status == "done" and rep.inserted == 3


def test_zip_slip_and_absolute_paths_refused(tmp_path: Path) -> None:
    for member in ["../evil.log", "/etc/evil.log", "a/../../evil.log", "C:/evil.log"]:
        z = tmp_path / "x.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr(member, "x\n")
        with pytest.raises(UnsafeInputError, match="unsafe path"):
            consume(z, "x.zip")


def test_zip_with_nested_gzip_and_directories(tmp_path: Path) -> None:
    z = tmp_path / "logs.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("web/", "")
        zf.writestr("web/access.log", "\n".join(web_lines(10, seed=4)) + "\n")
        zf.writestr(
            "web/access.log.1.gz",
            gzip.compress(b"\n".join(line.encode() for line in web_lines(5, seed=5)) + b"\n"),
        )
    names = []
    for m in open_members(z, "logs.zip", GB):
        names.append((m.name, len(list(iter_lines(m.stream)))))
    assert names == [("logs.zip!web/access.log", 10), ("logs.zip!web/access.log.1", 5)]


def test_nested_zip_and_encrypted_refused(tmp_path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("a.log", "x\n")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
    with pytest.raises(UnsafeInputError, match="nested zip"):
        consume(outer, "outer.zip")


def test_gzip_bomb_ratio_and_size_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bomb = tmp_path / "bomb.gz"
    bomb.write_bytes(gzip.compress(b"A" * (12 * 1024 * 1024)))
    with pytest.raises(UnsafeInputError, match="ratio"):
        consume(bomb, "bomb.gz")
    monkeypatch.setattr(readers, "RATIO_GRACE", GB)  # disable the ratio check
    with pytest.raises(UnsafeInputError, match="exceeds the limit"):
        consume(bomb, "bomb.gz", 1024 * 1024)


def test_zip_declared_size_limit(tmp_path: Path) -> None:
    z = tmp_path / "big.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.log", "A" * 5000)
    with pytest.raises(UnsafeInputError, match="beyond the size limit"):
        list(open_members(z, "big.zip", 1000))


def test_corrupt_zip(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04garbage")
    with pytest.raises(UnsafeInputError, match="corrupt"):
        list(open_members(bad, "bad.zip", GB))


@pytest.mark.parametrize(
    ("member", "source"),
    [
        ("access.log", "access.log"),
        ("access.log.1.gz", "access.log"),
        ("logs.zip!web/auth.log.3", "auth.log"),
        ("x", "x"),
    ],
)
def test_source_name_for(member: str, source: str) -> None:
    assert source_name_for(member) == source


# ---------------------------------------------------------------- pipeline


def test_ingest_counts_dedup_and_report(conn: sqlite3.Connection, tmp_path: Path) -> None:
    lines = [*web_lines(120, seed=1), "GARBAGE LINE", ""]
    path = write(tmp_path / "access.log", lines)
    [rep] = ingest(conn, path)
    assert (rep.status, rep.parser, rep.source) == ("done", "apache", "access.log")
    assert (rep.lines, rep.inserted, rep.duplicates, rep.malformed) == (121, 120, 0, 1)
    assert rep.samples[0]["reason"].startswith("line does not match")
    assert rep.tables == {"ev_webserver": 120}

    [again] = ingest(conn, path)
    assert (again.inserted, again.duplicates) == (0, 120)

    row = conn.execute("SELECT * FROM ingest_batches WHERE id = ?", (rep.batch_id,)).fetchone()
    assert row["events_inserted"] == 120 and row["malformed"] == 1 and row["status"] == "done"
    assert json.loads(row["malformed_samples"])[0]["line"] == "GARBAGE LINE"
    src = conn.execute("SELECT parser, last_event_at FROM sources WHERE name = 'access.log'")
    parser, last = src.fetchone()
    assert parser == "apache" and last == rep.max_ts
    ev = conn.execute(
        'SELECT tl_batch, tl_record, "source.ip", "http.response.status_code" FROM ev_webserver '
        "ORDER BY tl_id LIMIT 1"
    ).fetchone()
    assert ev[0] == rep.batch_id and ev[1] == 1
    assert isinstance(ev[3], int)


def test_identical_lines_are_distinct_events(conn: sqlite3.Connection, tmp_path: Path) -> None:
    line = next(web_lines(1, seed=1))
    path = write(tmp_path / "dup.log", [line, line, line])
    [rep] = ingest(conn, path, parser_type="apache")
    assert rep.inserted == 3
    [rep2] = ingest(conn, path, parser_type="apache")
    assert rep2.duplicates == 3


def test_occurrence_counter_resets_on_new_timestamp() -> None:
    c = OccurrenceCounter()
    assert [c.next(1, "a"), c.next(1, "a"), c.next(1, "b"), c.next(2, "a")] == [0, 1, 0, 0]


def test_malformed_samples_capped(conn: sqlite3.Connection, tmp_path: Path) -> None:
    lines = [*web_lines(60, seed=2)] + [f"junk {i}" for i in range(50)]
    [rep] = ingest(conn, write(tmp_path / "a.log", lines), parser_type="apache")
    assert rep.malformed == 50
    assert len(rep.samples) == 20


def test_unrecognised_format_fails_batch(conn: sqlite3.Connection, tmp_path: Path) -> None:
    [rep] = ingest(conn, write(tmp_path / "x.log", ["hello world"] * 20))
    assert rep.status == "failed"
    assert "could not recognise" in (rep.error or "")


def test_unsafe_file_fails_batch(conn: sqlite3.Connection, tmp_path: Path) -> None:
    (tmp_path / "bin.log").write_bytes(b"\x7fELF\x00\x00")
    [rep] = ingest(conn, tmp_path / "bin.log")
    assert rep.status == "failed" and "binary" in (rep.error or "")


def test_mid_stream_bomb_marks_batch_failed(
    conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(readers, "RATIO_GRACE", 2 * 1024 * 1024)
    head = "\n".join(web_lines(3000, seed=7)) + "\n"  # real lines first, then the bomb
    payload = head + ("A" * 200 + "\n") * 200_000
    gz = tmp_path / "access.log.gz"
    gz.write_bytes(gzip.compress(payload.encode()))
    reports = ingest(conn, gz)
    assert reports[-1].status == "failed"
    assert "ratio" in (reports[-1].error or "")
    assert (
        conn.execute("SELECT count(*) FROM ingest_batches WHERE status = 'running'").fetchone()[0]
        == 0
    )


def test_timezone_override_applies_to_syslog(conn: sqlite3.Connection, tmp_path: Path) -> None:
    line = "Jan  5 12:00:00 h sshd[1]: Accepted publickey for alice from 1.2.3.4 port 22 ssh2"
    path = write(tmp_path / "auth.log", [line])
    [utc] = ingest(conn, path, source_name="utc-src")
    [dhaka] = ingest(conn, path, source_name="dhaka-src", timezone="Asia/Dhaka")
    assert utc.min_ts is not None and dhaka.min_ts is not None
    assert utc.min_ts - dhaka.min_ts == 6 * 3600 * 1000
    # The source remembers its timezone.
    tz = conn.execute("SELECT timezone FROM sources WHERE name = 'dhaka-src'").fetchone()[0]
    assert tz == "Asia/Dhaka"


def test_three_formats_into_three_tables(conn: sqlite3.Connection, tmp_path: Path) -> None:
    ingest(conn, write(tmp_path / "access.log", list(web_lines(50, seed=1))))
    ingest(conn, write(tmp_path / "auth.log", list(auth_lines(50, seed=1))))
    ingest(conn, write(tmp_path / "app.jsonl", list(ecs_lines(50, seed=1))))
    assert EventStore(conn).event_tables() == ["ev_ecs", "ev_linux_auth", "ev_webserver"]
    cats = conn.execute('SELECT DISTINCT "event.category" FROM ev_ecs ORDER BY 1').fetchall()
    assert [c[0] for c in cats] == ["authentication", "file", "web"]  # 1-element lists unwrapped


def test_generic_json_with_mapping(conn: sqlite3.Connection, tmp_path: Path) -> None:
    m = FieldMapping.from_yaml(
        "name: app\nlogsource: {product: app}\ntimestamp: t\nfields: {ip: source.ip}\n"
    )
    path = write(tmp_path / "a.jsonl", ['{"t": 1767600000, "ip": "1.2.3.4", "x": true}'])
    [rep] = ingest(conn, path, parser_type="json", mapping=m)
    assert rep.tables == {"ev_app": 1}
    row = conn.execute('SELECT "source.ip", x FROM ev_app').fetchone()
    assert tuple(row) == ("1.2.3.4", "true")


def test_store_raw_with_dictionary(conn: sqlite3.Connection, tmp_path: Path) -> None:
    lines = list(web_lines(1200, seed=11))
    [rep] = ingest(conn, write(tmp_path / "a.log", lines), store_raw=True)
    dict_id = conn.execute(
        "SELECT raw_dict_id FROM ingest_batches WHERE id = ?", (rep.batch_id,)
    ).fetchone()[0]
    assert dict_id is not None
    codec = events_mod.load_raw_codec(conn, dict_id)
    blobs = [r[0] for r in conn.execute("SELECT tl_raw FROM ev_webserver ORDER BY tl_id")]
    assert codec.decompress(blobs[0]) == lines[0]
    assert sum(map(len, blobs)) < sum(len(s) for s in lines) / 2  # dictionary pays off


def test_raw_codec_without_dictionary() -> None:
    assert RawCodec.train(["x"] * 3) is None
    c = RawCodec()
    assert c.decompress(c.compress("hello \u00e9")) == "hello \u00e9"


# ---------------------------------------------------------------- event store


def _ev(fields: dict[str, object], ts: int = 1, raw: str = "r") -> PreparedEvent:
    ls = LogSource(product="test")
    return PreparedEvent(Event(ts, dict(fields), ls, raw=raw), content_hash("ev_test", raw, 0))


def test_store_columns_types_and_overflow(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EventStore(conn)
    monkeypatch.setattr(events_mod, "MAX_FIELD_COLUMNS", 3)
    with transaction(conn):
        res = store.insert(
            [
                _ev(
                    {
                        "a": 1,
                        "b": 2.5,
                        "c": "x",
                        "d": "over cap",
                        "tl_id": "reserved",
                        "bad name!": 1,
                        "lst": [1, 2],
                    },
                    raw="1",
                ),
                _ev({"A": "case clash", "a": 2}, raw="2"),
            ],
            batch_id=1,
        )
    assert res.inserted == 2
    cols = store.table_columns("ev_test")
    assert {"a", "b", "c"} <= set(cols)
    assert "d" not in cols and "lst" not in cols
    rows = conn.execute("SELECT a, b, c, tl_extra FROM ev_test ORDER BY tl_id").fetchall()
    assert rows[0][:3] == (1, 2.5, "x")
    extra = json.loads(rows[0][3])
    assert extra == {"d": "over cap", "tl_id": "reserved", "bad name!": 1, "lst": [1, 2]}
    assert json.loads(rows[1][3]) == {"A": "case clash"}
    types = dict(conn.execute("SELECT field, sql_type FROM event_fields").fetchall())
    assert types == {"a": "INTEGER", "b": "REAL", "c": "TEXT"}


def test_store_pivot_index_and_nocase(conn: sqlite3.Connection) -> None:
    store = EventStore(conn)
    with transaction(conn):
        store.insert([_ev({"source.ip": "1.2.3.4", "user.name": "Alice"})], batch_id=1)
    idx = {r[1] for r in conn.execute("PRAGMA index_list(ev_test)")}
    assert "ev_test__source.ip" in idx and "ev_test__user.name" in idx
    # Sigma semantics: string equality is case-insensitive.
    assert (
        conn.execute("""SELECT count(*) FROM ev_test WHERE "user.name" = 'alice'""").fetchone()[0]
        == 1
    )


def test_bad_table_name_rejected(conn: sqlite3.Connection) -> None:
    class Weird(LogSource):
        @property
        def table_name(self) -> str:  # type: ignore[override]
            return 'ev_x"; DROP TABLE users; --'

    with pytest.raises(ValueError, match="invalid event table"):
        EventStore(conn).ensure_table(Weird(product="x"))


def test_logsource_table_names() -> None:
    assert LogSource(category="webserver").table_name == "ev_webserver"
    assert LogSource(product="linux", service="auth").table_name == "ev_linux_auth"
    assert LogSource(product="My App!", service="API v2").table_name == "ev_my_app_api_v2"
    assert LogSource().table_name == "ev_unknown"
    assert LogSource(product="x" * 100).table_name == "ev_" + "x" * 45
