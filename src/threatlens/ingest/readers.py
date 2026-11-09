"""Safe, streaming access to log files and archives.

Nothing is ever loaded whole into memory, and nothing is extracted by name:
archive members are streamed straight into the parser, so zip-slip (``../``
member names) cannot write anywhere. Decompression is capped by total size and
by compression ratio (zip/gzip bombs), and binary files are refused.

Windows EVTX files are the one binary format accepted. The Rust ``evtx``
library turns each record into one JSON line (see `EvtxLines`). It needs a
seekable file, so an EVTX file inside a ``.gz`` or ``.zip`` is first copied,
within the same size limits, to an anonymous temporary file.
"""

from __future__ import annotations

import gzip
import io
import shutil
import stat
import tempfile
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Protocol

GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
EVTX_MAGIC = b"ElfFile\x00"
BINARY_MAGICS = (b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"%PDF")
SNIFF_BYTES = 8192
MAX_TEXT_NULS = 16  # NUL bytes tolerated in a text sample (see check_text)
MAX_LINE_BYTES = 1024 * 1024
MAX_RATIO = 200  # decompressed / compressed, checked once past RATIO_GRACE bytes
RATIO_GRACE = 10 * 1024 * 1024
MAX_ZIP_MEMBERS = 10_000
TEXT_EXTENSIONS = {".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv", ".out"}
EVTX_EXTENSIONS = {".evtx"}
# Marks a record the reader could not decode; the pipeline reports it as malformed.
MALFORMED = "\x00MALFORMED\x00"
MAX_EVTX_ERRORS = 10_000  # consecutive unreadable records before giving up on a file
ARCHIVE_EXTENSIONS = {".gz", ".zip"}
# Common log names without an extension (also with rotation suffixes: auth.log.1, secure-20260101)
BARE_LOG_NAMES = {
    "auth",
    "secure",
    "messages",
    "syslog",
    "access_log",
    "error_log",
    "access",
    "error",
}


class UnsafeInputError(ValueError):
    """The input looks dangerous or is not a log file (bomb, binary, wrong type)."""


# Everything that reading/decompressing a hostile or corrupt file can raise.
READ_ERRORS: tuple[type[BaseException], ...] = (
    UnsafeInputError,
    OSError,  # includes gzip.BadGzipFile
    EOFError,
    zlib.error,
    zipfile.BadZipFile,
)


class LineSource(Protocol):
    def readline(self, size: int = -1, /) -> bytes: ...


class ByteSource(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


@dataclass(frozen=True, slots=True)
class Member:
    """One logical log stream: a plain file, a gzip payload, or a zip member."""

    name: str  # display name, e.g. "logs.zip!web/access.log"
    stream: LineSource
    parser: str | None = None  # forced parser type (EVTX records are always "evtx")


def allowed_filename(name: str) -> bool:
    """Extension allow-list for uploads (rotated names like ``access.log.1`` are fine)."""
    p = PurePosixPath(name.replace("\\", "/")).name.lower()
    if not p or p.startswith("."):
        return False
    parts = p.split(".")
    # strip rotation suffixes: .1, .2, -20260101
    while len(parts) > 1 and parts[-1].isdigit():
        parts.pop()
    base = parts[0].split("-")[0]
    ext = f".{parts[-1]}" if len(parts) > 1 else ""
    if ext == ".gz" and len(parts) > 2:  # access.log.1.gz
        return True
    allowed = TEXT_EXTENSIONS | ARCHIVE_EXTENSIONS | EVTX_EXTENSIONS
    return ext in allowed or (ext == "" and base in BARE_LOG_NAMES)


class LimitedReader(io.RawIOBase):
    """Counts decompressed bytes and refuses to go past ``limit`` or ``MAX_RATIO``."""

    def __init__(self, inner: ByteSource, limit: int, compressed_size: int | None) -> None:
        self.inner = inner
        self.limit = limit
        self.compressed_size = compressed_size
        self.count = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        data = self.inner.read(len(buffer))
        n = len(data)
        buffer[:n] = data
        self.count += n
        if self.count > self.limit:
            raise UnsafeInputError(
                f"decompressed data exceeds the limit ({self.limit // (1024 * 1024)} MB)"
            )
        if (
            self.compressed_size
            and self.count > RATIO_GRACE
            and self.count / self.compressed_size > MAX_RATIO
        ):
            raise UnsafeInputError(f"compression ratio above {MAX_RATIO}:1 (possible zip bomb)")
        return n


def check_text(head: bytes, name: str) -> None:
    if head.startswith(EVTX_MAGIC):
        raise UnsafeInputError(f"{name}: Windows EVTX data cannot be read as text")
    if head.startswith(BINARY_MAGICS):
        raise UnsafeInputError(f"{name}: binary file (executable or document), not a log")
    sample = head[:SNIFF_BYTES]
    # A few NUL bytes are normal in a web log: a client speaking TLS or garbage to a
    # plain-HTTP port gets its bytes logged as the "request". Refusing the whole file
    # for that would let one crafted request hide a log from analysis. Real binaries
    # and UTF-16 text are full of NULs.
    nul = sample.count(b"\x00")
    if nul > max(MAX_TEXT_NULS, len(sample) // 100):
        hint = " (UTF-16 text? convert it to UTF-8)" if _utf16_like(sample) else ""
        raise UnsafeInputError(f"{name}: binary data (NUL bytes), not a text log{hint}")


def _utf16_like(sample: bytes) -> bool:
    return sample[:2] in (b"\xff\xfe", b"\xfe\xff") or sample[1:200:2].count(0) > 50


class EvtxLines:
    """A `LineSource` over an EVTX file: one compact JSON line per record.

    A record or chunk that cannot be decoded becomes a `MALFORMED` line (reported
    like a malformed log line) and reading goes on with the next one.
    """

    def __init__(self, source: Path | IO[bytes], name: str) -> None:
        from evtx import PyEvtxParser  # noqa: PLC0415 - native module, loaded on demand

        try:
            parser = PyEvtxParser(
                str(source) if isinstance(source, Path) else source,
                number_of_threads=1,  # bounded memory; a chunk at a time
                indent=False,
            )
            self._records = iter(parser.records_json())
        except (RuntimeError, OSError, ValueError) as exc:
            raise UnsafeInputError(f"{name}: not a readable EVTX file: {exc}") from exc
        self._name = name
        self._buf = b""
        self._done = False

    def _fill(self) -> None:
        errors = 0
        while not self._done:
            try:
                record = next(self._records)
            except StopIteration:
                self._done = True
                return
            except RuntimeError as exc:  # a damaged record or chunk; the next may be fine
                errors += 1
                self._buf += (MALFORMED + str(exc).replace("\n", " ")[:300]).encode() + b"\n"
                if errors >= MAX_EVTX_ERRORS:
                    self._done = True
                    return
                continue
            if not isinstance(record, dict):
                continue
            data = str(record["data"]).replace("\n", " ")  # compact JSON has no newlines
            self._buf += data.encode("utf-8", "replace") + b"\n"
            return

    def readline(self, size: int = -1, /) -> bytes:
        if b"\n" not in self._buf:
            self._fill()
        end = self._buf.find(b"\n")
        end = len(self._buf) if end < 0 else end + 1
        if 0 <= size < end:
            end = size
        line, self._buf = self._buf[:end], self._buf[end:]
        return line


def _spooled_evtx(stream: ByteSource, name: str) -> Member:
    """Copy a (size-limited) decompressed EVTX stream to an anonymous temp file."""
    tmp = tempfile.TemporaryFile(prefix="tl-evtx-")  # noqa: SIM115 - closed with the member
    try:
        shutil.copyfileobj(stream, tmp, 1024 * 1024)
        tmp.seek(0)
        return Member(name, EvtxLines(tmp, name), parser="evtx")
    except BaseException:
        tmp.close()
        raise


def _buffered(raw: io.RawIOBase) -> io.BufferedReader:
    return io.BufferedReader(raw, buffer_size=256 * 1024)


def _safe_member_name(name: str) -> str:
    """Normalise a zip member name for display. Nothing is extracted, but names with
    absolute paths or ``..`` are still refused (and reported)."""
    clean = name.replace("\\", "/")
    parts = PurePosixPath(clean).parts
    if clean.startswith("/") or ".." in parts or (parts and ":" in parts[0]):
        raise UnsafeInputError(f"unsafe path in archive: {name!r}")
    return clean


def open_members(path: Path, display_name: str, max_bytes: int) -> Iterator[Member]:
    """Yield the log streams inside ``path``: itself, a gzip payload, or zip members.

    The caller must consume each member before asking for the next one.
    """
    with path.open("rb") as fh:
        head = fh.read(SNIFF_BYTES)
    size = path.stat().st_size
    if head.startswith(GZIP_MAGIC):
        with gzip.open(path, "rb") as gz:
            limited = LimitedReader(gz, max_bytes, size)
            stream = _buffered(limited)
            name = display_name.removesuffix(".gz") or display_name
            if stream.peek(len(EVTX_MAGIC)).startswith(EVTX_MAGIC):
                yield _spooled_evtx(stream, name)
            else:
                yield Member(name, stream)
        return
    if head.startswith(ZIP_MAGIC):
        yield from _zip_members(path, display_name, max_bytes)
        return
    if head.startswith(EVTX_MAGIC):
        if size > max_bytes:
            raise UnsafeInputError(f"{display_name}: EVTX file is larger than the size limit")
        yield Member(display_name, EvtxLines(path, display_name), parser="evtx")
        return
    check_text(head, display_name)
    with path.open("rb") as fh:
        yield Member(display_name, fh)


def _zip_members(path: Path, display_name: str, max_bytes: int) -> Iterator[Member]:
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise UnsafeInputError(f"{display_name}: corrupt zip file") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_MEMBERS:
            raise UnsafeInputError(f"{display_name}: too many archive members ({len(infos)})")
        declared = sum(i.file_size for i in infos)
        if declared > max_bytes:
            raise UnsafeInputError(f"{display_name}: archive expands beyond the size limit")
        budget = max_bytes
        for info in infos:
            mode = info.external_attr >> 16
            if info.is_dir() or stat.S_ISLNK(mode):
                continue
            name = _safe_member_name(info.filename)
            if info.flag_bits & 0x1:
                raise UnsafeInputError(f"{display_name}!{name}: encrypted members not supported")
            label = f"{display_name}!{name}"
            with zf.open(info) as member:
                limited = LimitedReader(member, budget, info.compress_size or None)
                stream = _buffered(limited)
                head = stream.peek(SNIFF_BYTES)[:SNIFF_BYTES]
                if head.startswith(GZIP_MAGIC):  # one level of nesting: logs.zip!a.log.gz
                    inner = gzip.GzipFile(fileobj=stream)
                    nested = LimitedReader(inner, budget, info.compress_size or None)
                    nested_stream = _buffered(nested)
                    if nested_stream.peek(len(EVTX_MAGIC)).startswith(EVTX_MAGIC):
                        yield _spooled_evtx(nested_stream, label.removesuffix(".gz"))
                    else:
                        yield Member(label.removesuffix(".gz"), nested_stream)
                    budget -= nested.count
                    continue
                if head.startswith(ZIP_MAGIC):
                    raise UnsafeInputError(f"{label}: nested zip archives are not supported")
                if head.startswith(EVTX_MAGIC):
                    yield _spooled_evtx(stream, label)
                    budget -= limited.count
                    continue
                check_text(head, label)
                yield Member(label, stream)
                budget -= limited.count


def iter_lines(stream: LineSource, start_record: int = 0) -> Iterator[tuple[int, str]]:
    """Yield ``(record_no, line)`` for every non-empty line, decoded as UTF-8.

    Lines longer than ``MAX_LINE_BYTES`` are cut and yielded with a marker so the
    parser reports them as malformed instead of the reader buffering gigabytes.
    """
    record = start_record
    first = True
    while True:
        chunk = stream.readline(MAX_LINE_BYTES + 1)
        if not chunk:
            return
        record += 1
        too_long = len(chunk) > MAX_LINE_BYTES and not chunk.endswith(b"\n")
        if too_long:
            while True:  # discard the rest of the oversized line
                rest = stream.readline(MAX_LINE_BYTES)
                if not rest or rest.endswith(b"\n"):
                    break
        if first:
            chunk = chunk.removeprefix(b"\xef\xbb\xbf")
            first = False
        line = chunk.decode("utf-8", "replace").rstrip("\r\n")
        if too_long:
            yield record, "\x00TOO_LONG\x00" + line[:200]
        elif line.strip():
            yield record, line
