#!/usr/bin/env python3
"""Regenerates rules/ads-trackers.json from blocklist.json.

Run this after editing blocklist.json:
    python3 tools/build_rules.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
blocklist = json.loads((ROOT / "blocklist.json").read_text())

RESOURCE_TYPES = [
    "script",
    "image",
    "xmlhttprequest",
    "sub_frame",
    "ping",
    "media",
    "websocket",
    "other",
]

rules = []
for i, domain in enumerate(blocklist, start=1):
    rules.append(
        {
            "id": i,
            "priority": 1,
            "action": {"type": "block"},
            "condition": {
                "urlFilter": f"||{domain}^",
                "resourceTypes": RESOURCE_TYPES,
            },
        }
    )

out_path = ROOT / "rules" / "ads-trackers.json"
out_path.write_text(json.dumps(rules, indent=2) + "\n")
print(f"wrote {len(rules)} rules to {out_path.relative_to(ROOT)}")
