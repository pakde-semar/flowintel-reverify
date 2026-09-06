#!/usr/bin/env python3
"""
Seed Flowintel custom tags for the three case-type families.

Usage:
    python3 scripts/seed_case_types.py [--dry-run] [--delete-existing]

Env vars (override defaults):
    FLOWINTEL_URL   default: https://flowintel.iww.web.id
    FLOWINTEL_KEY   default: (empty — must be set)
"""

import os
import sys
import json
import urllib.request
import urllib.error

BASE_URL = os.environ.get("FLOWINTEL_URL", "https://flowintel.iww.web.id").rstrip("/")
API_KEY  = os.environ.get("FLOWINTEL_KEY", "aO4EEcQ50S1ouVaobz6okouwpsBUjNIqXgjyD0hP7IZuEwYkdQ94m55y2fR7")

DRY_RUN        = "--dry-run" in sys.argv
DELETE_EXISTING = "--delete-existing" in sys.argv

# ── Colour palette per family ─────────────────────────────────────────────────
#   Incident  → red family
#   Technical → blue family
#   Forensic  → purple family

TAGS = [
    # ── INCIDENT CASE ──────────────────────────────────────────────────────────
    {"name": "Incident: Phishing",            "color": "#dc3545", "icon": "fa-solid fa-fish-fins"},
    {"name": "Incident: Account Compromise",  "color": "#c0392b", "icon": "fa-solid fa-user-lock"},
    {"name": "Incident: Endpoint Compromise", "color": "#e74c3c", "icon": "fa-solid fa-laptop"},
    {"name": "Incident: Server Compromise",   "color": "#b03a2e", "icon": "fa-solid fa-server"},
    {"name": "Incident: Web Compromise",      "color": "#e95757", "icon": "fa-solid fa-globe"},
    {"name": "Incident: Data Breach",         "color": "#922b21", "icon": "fa-solid fa-database"},
    {"name": "Incident: Ransomware",          "color": "#f1948a", "icon": "fa-solid fa-lock"},
    {"name": "Incident: Network Intrusion",   "color": "#d98880", "icon": "fa-solid fa-network-wired"},
    {"name": "Incident: DDoS",                "color": "#ec7063", "icon": "fa-solid fa-bolt"},

    # ── TECHNICAL INVESTIGATION CASE ───────────────────────────────────────────
    {"name": "Investigation: Malware / Suspicious File", "color": "#1a6eb5", "icon": "fa-solid fa-bug"},
    {"name": "Investigation: Suspicious Domain",         "color": "#2471a3", "icon": "fa-solid fa-at"},
    {"name": "Investigation: Suspicious URL",            "color": "#1f618d", "icon": "fa-solid fa-link"},
    {"name": "Investigation: Suspicious IP",             "color": "#2980b9", "icon": "fa-solid fa-tower-broadcast"},
    {"name": "Investigation: Malicious Document",        "color": "#1a5276", "icon": "fa-solid fa-file-shield"},
    {"name": "Investigation: Malicious APK",             "color": "#154360", "icon": "fa-solid fa-mobile-screen-button"},
    {"name": "Investigation: C2 Infrastructure",         "color": "#2e86c1", "icon": "fa-solid fa-diagram-project"},
    {"name": "Investigation: Vulnerability Exploitation","color": "#1b4f72", "icon": "fa-solid fa-triangle-exclamation"},

    # ── FORENSIC CASE ──────────────────────────────────────────────────────────
    {"name": "Forensic: Disk Forensics",             "color": "#7d3c98", "icon": "fa-solid fa-hard-drive"},
    {"name": "Forensic: Memory Forensics",           "color": "#6c3483", "icon": "fa-solid fa-memory"},
    {"name": "Forensic: Endpoint Forensics",         "color": "#884ea0", "icon": "fa-solid fa-desktop"},
    {"name": "Forensic: Mobile Forensics",           "color": "#9b59b6", "icon": "fa-solid fa-mobile"},
    {"name": "Forensic: Log / Timeline Investigation","color": "#7b241c", "icon": "fa-solid fa-timeline"},
    {"name": "Forensic: Network Forensics",          "color": "#5b2c6f", "icon": "fa-solid fa-magnifying-glass-chart"},
]


def api(method, path, body=None):
    url = f"{BASE_URL}/api{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method,
                                  headers={"X-API-KEY": API_KEY,
                                           "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def get_existing():
    status, resp = api("GET", "/custom_tags/all")
    if status != 200:
        print(f"ERROR fetching existing tags: {resp}")
        sys.exit(1)
    return {t["name"]: t for t in resp}


def delete_tag(tid, name):
    if DRY_RUN:
        print(f"  [dry-run] DELETE #{tid} {name}")
        return
    status, resp = api("GET", f"/custom_tags/{tid}/delete")
    icon = "✓" if status == 200 else "✗"
    print(f"  {icon} deleted #{tid} {name}: {resp.get('message','')}")


def create_tag(tag):
    if DRY_RUN:
        print(f"  [dry-run] CREATE {tag['name']}")
        return
    status, resp = api("POST", "/custom_tags/add", tag)
    icon = "✓" if status == 201 else "✗"
    print(f"  {icon} {tag['name']}: {resp.get('message','')}")


def main():
    print(f"Flowintel: {BASE_URL}")
    print(f"Dry-run:   {DRY_RUN}")
    print()

    existing = get_existing()

    if DELETE_EXISTING:
        print("=== Deleting existing case-type tags ===")
        families = ("Incident:", "Investigation:", "Forensic:")
        to_delete = {n: t for n, t in existing.items() if any(n.startswith(f) for f in families)}
        if not to_delete:
            print("  (none found)")
        for name, tag in to_delete.items():
            delete_tag(tag["id"], name)
        existing = get_existing() if not DRY_RUN else existing
        print()

    print("=== Seeding case-type tags ===")
    created = skipped = 0
    for tag in TAGS:
        if tag["name"] in existing:
            print(f"  – skip (exists) {tag['name']}")
            skipped += 1
        else:
            create_tag(tag)
            created += 1

    print()
    print(f"Done. created={created}  skipped={skipped}  dry_run={DRY_RUN}")


if __name__ == "__main__":
    main()
