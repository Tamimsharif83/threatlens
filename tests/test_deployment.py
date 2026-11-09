"""Deployment guard rails: ThreatLens must only ever be published on 127.0.0.1.

Dropping the ``127.0.0.1:`` prefix (an easy "fix" for a port conflict) would
expose the UI on every network interface, so these tests fail the build if the
Compose files or any documented ``docker run`` command stop binding to localhost.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = [ROOT / "docker-compose.yml", ROOT / "docker-compose.override.yml.example"]
DOC_FILES = [
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "CONTRIBUTING.md",
    *sorted((ROOT / "docs").rglob("*.md")),
    *sorted((ROOT / ".github").rglob("*.yml")),
]
LOCALHOST = "127.0.0.1"


def _port_entries(compose_file: Path) -> list[object]:
    data = yaml.safe_load(compose_file.read_text()) or {}
    return [
        entry
        for service in (data.get("services") or {}).values()
        for entry in (service.get("ports") or [])
    ]


def _is_localhost(entry: object) -> bool:
    if isinstance(entry, dict):  # long syntax: {host_ip: ..., published: ..., target: ...}
        return entry.get("host_ip") == LOCALHOST
    return str(entry).startswith(f"{LOCALHOST}:")


@pytest.mark.parametrize("compose_file", COMPOSE_FILES, ids=lambda p: p.name)
def test_compose_ports_bind_localhost_only(compose_file: Path) -> None:
    bad = [e for e in _port_entries(compose_file) if not _is_localhost(e)]
    assert bad == [], f"{compose_file.name} publishes ports beyond 127.0.0.1: {bad}"


def test_compose_host_port_is_configurable() -> None:
    entries = _port_entries(ROOT / "docker-compose.yml")
    assert entries == ["127.0.0.1:${TL_HOST_PORT:-8080}:8080"]


def _docker_run_commands(text: str) -> list[str]:
    """Each `docker run ...` command, with backslash line continuations joined."""
    joined = re.sub(r"\s*\\\n\s*", " ", text)
    return [m.group(0) for m in re.finditer(r"docker run\b[^\n`]*", joined)]


def test_documented_docker_run_binds_localhost_only() -> None:
    publish = re.compile(r"(?:^|\s)(?:-p|--publish)(?:\s+|=)(\S+)")
    found, bad = 0, []
    for doc in DOC_FILES:
        for command in _docker_run_commands(doc.read_text(encoding="utf-8")):
            for spec in publish.findall(command):
                found += 1
                if not spec.startswith(f"{LOCALHOST}:"):
                    bad.append(f"{doc.relative_to(ROOT)}: {spec}")
    assert found >= 3, "expected to find the documented docker run commands"
    assert bad == []


def test_guard_catches_a_regression() -> None:
    """The helpers above must actually flag an all-interfaces binding."""
    assert not _is_localhost("8080:8080")
    assert not _is_localhost("0.0.0.0:8080:8080")
    assert not _is_localhost({"published": 8080, "target": 8080})
    assert _is_localhost({"host_ip": "127.0.0.1", "published": 8080, "target": 8080})
    cmds = _docker_run_commands("docker run -d \\\n  -p 8080:8080 \\\n  img")
    assert cmds == ["docker run -d -p 8080:8080 img"]


def test_env_example_documents_host_port() -> None:
    example = (ROOT / ".env.example").read_text()
    assert re.search(r"^TL_HOST_PORT=8080$", example, re.M)
    # .env is ignored, .env.example is committed.
    git = shutil.which("git")
    if git is None:
        pytest.skip("git not available")

    def is_ignored(name: str) -> bool:
        result = subprocess.run([git, "check-ignore", "-q", name], cwd=ROOT, check=False)
        return result.returncode == 0

    assert is_ignored(".env")
    assert not is_ignored(".env.example")


def test_shipped_data_files_are_not_git_ignored() -> None:
    """Broad ignores (*.log, data/) once kept rule fixtures and ATT&CK data out of git."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("git not available")
    fixtures = sorted((ROOT / "tests" / "rules").rglob("*.*"))
    fixtures += sorted((ROOT / "src" / "threatlens" / "attack" / "data").glob("*.*"))
    assert len(fixtures) > 2
    result = subprocess.run(
        [git, "check-ignore", *[str(f) for f in fixtures]],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "", f"git-ignored files:\n{result.stdout}"
