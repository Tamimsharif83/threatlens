"""Seeded synthetic log generator (tests, demos, performance runs).

Everything is generated from a fixed seed: the same arguments always produce the
same lines. Addresses come from the documentation ranges (RFC 5737:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real host is referenced.
A small, deterministic share of lines carries attack-like activity (scanner user
agents, SQL injection probes, SSH brute force) so that detection rules have
something to find.
"""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

KINDS = ("web", "auth", "ecs")
START = datetime(2026, 1, 5, 8, 0, 0, tzinfo=UTC)

_CLIENTS = [f"198.51.100.{i}" for i in range(1, 120)]
_ATTACKERS = ["203.0.113.66", "203.0.113.77", "192.0.2.13"]
_PATHS = [
    "/",
    "/index.html",
    "/products",
    "/products/42",
    "/cart",
    "/search",
    "/login",
    "/api/v1/items",
    "/static/app.js",
    "/static/site.css",
    "/favicon.ico",
]
_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.10.1",
]
_SCANNER_UAS = ["sqlmap/1.8.11#stable (https://sqlmap.org)", "Nikto/2.5.0", "Nuclei - Open-source"]
_ATTACK_QUERIES = [
    "id=1' OR '1'='1",
    "q=<script>alert(1)</script>",
    "file=../../../../etc/passwd",
    "id=1 UNION SELECT username,password FROM users--",
]
_USERS = ["alice", "bob", "carol", "dave", "deploy"]
_BAD_USERS = ["root", "admin", "oracle", "test", "ubuntu", "postgres"]


def _apache_time(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def web_lines(n: int, seed: int = 1, start: datetime = START) -> Iterator[str]:
    """Apache/Nginx combined-format access log lines."""
    rnd = random.Random(seed)
    t = start
    for _ in range(n):
        t += timedelta(milliseconds=rnd.randint(50, 900))
        if rnd.random() < 0.03:
            ip = rnd.choice(_ATTACKERS)
            ua = rnd.choice(_SCANNER_UAS) if rnd.random() < 0.6 else rnd.choice(_UAS)
            path = rnd.choice(["/search", "/products", "/admin", "/wp-login.php", "/.env"])
            query = rnd.choice(_ATTACK_QUERIES)
            target = f"{path}?{query.replace(' ', '%20')}"
            status = rnd.choice([400, 403, 404, 500, 200])
            method = "GET"
        else:
            ip, ua = rnd.choice(_CLIENTS), rnd.choice(_UAS)
            path = rnd.choice(_PATHS)
            method = "POST" if path in ("/login", "/cart") and rnd.random() < 0.5 else "GET"
            target = f"{path}?page={rnd.randint(1, 9)}" if path == "/products" else path
            status = (
                401
                if path == "/login" and method == "POST" and rnd.random() < 0.2
                else rnd.choice([200, 200, 200, 200, 304, 404])
            )
        size = rnd.randint(150, 40_000) if status == 200 else rnd.randint(0, 600)
        user = rnd.choice(_USERS) if status == 200 and rnd.random() < 0.05 else "-"
        referer = "-" if rnd.random() < 0.6 else f"https://shop.example{rnd.choice(_PATHS)}"
        yield (
            f'{ip} - {user} [{_apache_time(t)}] "{method} {target} HTTP/1.1" {status} {size} '
            f'"{referer}" "{ua}"'
        )


def auth_lines(
    n: int, seed: int = 1, start: datetime = START, host: str = "bastion"
) -> Iterator[str]:
    """Linux auth.log lines (RFC 3164 timestamps, no year)."""
    rnd = random.Random(seed)
    t = start
    pid = 1000
    for _ in range(n):
        t += timedelta(seconds=rnd.randint(1, 40))
        pid += rnd.randint(1, 5)
        stamp = f"{t.strftime('%b')} {t.day:>2} {t.strftime('%H:%M:%S')}"
        r = rnd.random()
        if r < 0.35:  # brute force from an attacker
            ip = rnd.choice(_ATTACKERS)
            user = rnd.choice(_BAD_USERS)
            invalid = "invalid user " if user not in ("root",) else ""
            msg = (
                f"sshd[{pid}]: Failed password for {invalid}{user} from {ip} "
                f"port {rnd.randint(30000, 65000)} ssh2"
            )
        elif r < 0.55:
            user, ip = rnd.choice(_USERS), rnd.choice(_CLIENTS)
            msg = (
                f"sshd[{pid}]: Accepted publickey for {user} from {ip} "
                f"port {rnd.randint(30000, 65000)} ssh2: ED25519 SHA256:x"
            )
        elif r < 0.7:
            user = rnd.choice(_USERS)
            cmd = rnd.choice(
                [
                    "/usr/bin/systemctl restart nginx",
                    "/usr/bin/apt update",
                    "/usr/bin/cat /etc/shadow",
                    "/bin/bash",
                ]
            )
            msg = f"sudo:   {user} : TTY=pts/{rnd.randint(0, 4)} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
        elif r < 0.85:
            msg = f"CRON[{pid}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"
        elif r < 0.92:
            ip = rnd.choice(_ATTACKERS)
            msg = f"sshd[{pid}]: Invalid user {rnd.choice(_BAD_USERS)} from {ip} port {rnd.randint(30000, 65000)}"
        else:
            user = rnd.choice(_USERS)
            msg = f"systemd-logind[1]: New session {pid} of user {user}."
        yield f"{stamp} {host} {msg}"


def ecs_lines(n: int, seed: int = 1, start: datetime = START) -> Iterator[str]:
    """ECS JSON Lines from a web application (logins, uploads, API calls)."""
    rnd = random.Random(seed)
    t = start
    for i in range(n):
        t += timedelta(milliseconds=rnd.randint(100, 3000))
        attacker = rnd.random() < 0.05
        ip = rnd.choice(_ATTACKERS) if attacker else rnd.choice(_CLIENTS)
        kind = rnd.random()
        doc: dict[str, object] = {
            "@timestamp": t.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "source": {"ip": ip, "port": rnd.randint(30000, 65000)},
            "service": {"name": "shop-api"},
            "host": {"name": "app-1"},
            "http": {"request": {"id": f"req-{seed}-{i}"}},
            "user_agent": {"original": rnd.choice(_SCANNER_UAS if attacker else _UAS)},
        }
        if kind < 0.4:
            ok = not attacker and rnd.random() > 0.1
            doc["event"] = {
                "kind": "event",
                "category": ["authentication"],
                "type": ["start"],
                "action": "user-login",
                "outcome": "success" if ok else "failure",
            }
            doc["user"] = {"name": rnd.choice(_USERS if ok else _BAD_USERS)}
            doc["url"] = {"path": "/api/v1/login"}
            doc["http"] = {
                "request": {"method": "POST", "id": f"req-{seed}-{i}"},
                "response": {"status_code": 200 if ok else 401},
            }
        elif kind < 0.6:
            name = rnd.choice(
                ["invoice.pdf", "avatar.png", "shell.php" if attacker else "notes.txt"]
            )
            doc["event"] = {
                "kind": "event",
                "category": ["file"],
                "type": ["creation"],
                "action": "file-upload",
                "outcome": "success",
            }
            doc["file"] = {
                "name": name,
                "size": rnd.randint(100, 2_000_000),
                "mime_type": "application/octet-stream",
            }
            doc["user"] = {"name": rnd.choice(_USERS)}
        else:
            path = rnd.choice(["/api/v1/items", "/api/v1/cart", "/api/v1/orders"])
            query = rnd.choice(_ATTACK_QUERIES) if attacker else f"page={rnd.randint(1, 5)}"
            doc["event"] = {
                "kind": "event",
                "category": ["web"],
                "type": ["access"],
                "action": "http-request",
                "outcome": "success",
                "duration": rnd.randint(1_000_000, 900_000_000),
            }
            doc["url"] = {"path": path, "query": query, "original": f"{path}?{query}"}
            doc["http"] = {
                "request": {"method": "GET", "id": f"req-{seed}-{i}"},
                "response": {"status_code": rnd.choice([200, 200, 404, 500])},
            }
        yield json.dumps(doc, separators=(",", ":"))


GENERATORS = {"web": web_lines, "auth": auth_lines, "ecs": ecs_lines}
