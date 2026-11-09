"""Generate ThreatLens' compact ATT&CK Enterprise technique list.

Run at development time only; ThreatLens never downloads anything at runtime.

    python scripts/gen_attack_techniques.py --version 20.0

Reads MITRE's official STIX bundle (from github.com/mitre-attack/attack-stix-data)
and writes src/threatlens/attack/data/enterprise-attack.json with just what the
coverage matrix needs: tactics in matrix order, and active (not revoked, not
deprecated) techniques and sub-techniques with their tactics.

ATT&CK is © The MITRE Corporation, used under the ATT&CK Terms of Use
(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)
OUT = Path(__file__).resolve().parents[1] / "src/threatlens/attack/data/enterprise-attack.json"


def external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build(bundle: dict, version: str, url: str, digest: str) -> dict:
    objects = bundle["objects"]
    active = [o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    tactics_by_ref = {o["id"]: o for o in active if o["type"] == "x-mitre-tactic"}
    matrix = next(o for o in active if o["type"] == "x-mitre-matrix")
    tactics = [
        {
            "id": external_id(tactics_by_ref[ref]),
            "shortname": tactics_by_ref[ref]["x_mitre_shortname"],
            "name": tactics_by_ref[ref]["name"],
        }
        for ref in matrix["tactic_refs"]
        if ref in tactics_by_ref
    ]
    techniques = []
    for o in active:
        if o["type"] != "attack-pattern":
            continue
        tid = external_id(o)
        if not tid:
            continue
        phases = [
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            {
                "id": tid,
                "name": o["name"],
                "tactics": phases,
                "parent": tid.split(".")[0] if "." in tid else None,
            }
        )
    techniques.sort(
        key=lambda t: [int(p) if p.isdigit() else p for p in t["id"][1:].replace(".", " ").split()]
    )
    return {
        "source": "MITRE ATT&CK Enterprise",
        "version": version,
        "source_url": url,
        "source_sha256": digest,
        "generated": datetime.now(UTC).date().isoformat(),
        "attribution": "MITRE ATT&CK® is a registered trademark of The MITRE Corporation; "
        "content used under the ATT&CK Terms of Use.",
        "tactics": tactics,
        "techniques": techniques,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="ATT&CK version, e.g. 20.0")
    parser.add_argument("--input", type=Path, help="Use an already downloaded bundle")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    url = URL.format(version=args.version)
    if args.input:
        raw = args.input.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=120) as resp:  # dev-time only
            raw = resp.read()
    digest = hashlib.sha256(raw).hexdigest()
    data = build(json.loads(raw), args.version, url, digest)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(data['tactics'])} tactics, {len(data['techniques'])} techniques -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
