"""
Flowintel module: parse_auth_log
Parse web server and auth logs to detect credential stuffing and account
takeover attempts. Extracts attacker IPs, targeted usernames, timestamps,
user agents. Enriches top attacker IPs via RDAP/ASN. Writes summary to Notes.

Supported formats (auto-detected):
  nginx / apache  : Combined Log Format
  auth            : Linux /var/log/auth.log (sshd failed password)
  json            : One JSON object per line with ip/status/user fields
"""

import re
import json
import logging
import datetime
from collections import defaultdict

import requests

logger = logging.getLogger(__name__)

module_config = {
    "connector"  : "none",
    "case_task"  : "case",
    "description": (
        "Parse nginx/apache/auth/JSON logs to detect credential stuffing and ATO. "
        "Extracts attacker IPs, targeted usernames, failed login patterns. "
        "Enriches top attacker IPs and writes investigation summary to Notes."
    ),
}

_RDAP_URL = "https://rdap.org/ip/{}"
_RIPE_URL = "https://stat.ripe.net/data/prefix-overview/data.json?resource={}"
_TIMEOUT  = 8

_SUSPICIOUS_KEYWORDS = [
    "tor", "torserv", "exit", "bulletproof", "choopa", "frantech", "leaseweb",
    "serverius", "ecatel", "quasi", "novogara", "combahton", "flyservers",
]

# ─────────────────────────────────────────────────────────────────────────────
# Log parsers
# ─────────────────────────────────────────────────────────────────────────────

# nginx/apache combined: IP - - [timestamp] "METHOD /path HTTP/x" status bytes "ref" "ua"
_NGINX_RE = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+\d+(?:\s+"[^"]*"\s+"([^"]*)")?'
)

# auth.log: ... sshd[pid]: Failed password for [invalid user] USER from IP port PORT
_AUTH_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*?Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})'
)

# Login-path keywords for nginx/apache parsing
_LOGIN_PATHS = re.compile(
    r'/(login|signin|auth|wp-login|admin|user|account|session|token|oauth|api/v\d+/auth)',
    re.IGNORECASE,
)
_FAIL_STATUSES = {401, 403, 429}


def _parse_nginx(lines: list) -> list:
    events = []
    for line in lines:
        m = _NGINX_RE.match(line.strip())
        if not m:
            continue
        ip, ts, method, path, status, ua = (m.group(i) for i in range(1, 7))
        status = int(status)
        if status in _FAIL_STATUSES or _LOGIN_PATHS.search(path):
            events.append({
                "ip": ip, "timestamp": ts, "method": method,
                "path": path, "status": status, "user": None, "ua": ua or "",
            })
    return events


def _parse_auth(lines: list) -> list:
    events = []
    for line in lines:
        m = _AUTH_RE.search(line)
        if not m:
            continue
        ts, user, ip = m.group(1), m.group(2), m.group(3)
        events.append({
            "ip": ip, "timestamp": ts, "method": "SSH",
            "path": "/ssh", "status": 401, "user": user, "ua": "",
        })
    return events


def _parse_json_lines(lines: list) -> list:
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            ip     = d.get("ip") or d.get("remote_addr") or d.get("client_ip", "")
            status = int(d.get("status") or d.get("status_code") or 0)
            user   = d.get("user") or d.get("username") or d.get("email") or d.get("login")
            path   = d.get("path") or d.get("uri") or d.get("url") or ""
            ts     = str(d.get("time") or d.get("timestamp") or d.get("@timestamp") or "")
            ua     = d.get("user_agent") or d.get("ua") or ""
            if ip and (status in _FAIL_STATUSES or _LOGIN_PATHS.search(path) or user):
                events.append({
                    "ip": ip, "timestamp": ts, "method": d.get("method", ""),
                    "path": path, "status": status, "user": user, "ua": ua,
                })
        except Exception:
            continue
    return events


def _detect_format(lines: list) -> str:
    sample = "\n".join(lines[:20])
    if _NGINX_RE.search(sample):
        return "nginx"
    if _AUTH_RE.search(sample):
        return "auth"
    try:
        json.loads(lines[0].strip())
        return "json"
    except Exception:
        pass
    return "nginx"  # fallback


# ─────────────────────────────────────────────────────────────────────────────
# IP enrichment
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_ip(ip: str) -> dict:
    result = {"ip": ip, "network": None, "country": None, "asn": None, "holder": None}
    try:
        r = requests.get(_RDAP_URL.format(ip), timeout=_TIMEOUT,
                         headers={"Accept": "application/json"})
        if r.ok:
            d = r.json()
            result["network"] = d.get("name") or d.get("handle")
            result["country"] = d.get("country")
    except Exception:
        pass
    try:
        r2 = requests.get(_RIPE_URL.format(ip), timeout=_TIMEOUT)
        if r2.ok:
            asns = r2.json().get("data", {}).get("asns", [])
            if asns:
                result["asn"]    = str(asns[0].get("asn", ""))
                result["holder"] = asns[0].get("holder", "")
    except Exception:
        pass
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Note formatting
# ─────────────────────────────────────────────────────────────────────────────

def _write_note(case_id: int, note: str, db_session) -> None:
    try:
        from app.case import common_core as _CC
        case_orm = _CC.get_case(case_id)
        if case_orm:
            existing = case_orm.notes or ""
            case_orm.notes = (existing + "\n\n---\n\n" + note).strip()
            db_session.session.commit()
    except Exception as exc:
        logger.warning("Note write failed: %s", exc)


def _format_note(fmt, total_lines, events, ip_stats, user_stats,
                 threshold, enriched_ips, top_uas) -> str:
    ts_now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    attackers = [(ip, data) for ip, data in ip_stats.items() if data["count"] >= threshold]
    attackers.sort(key=lambda x: -x[1]["count"])

    lines = [
        f"## Auth Log Analysis",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Parsed at (UTC) | `{ts_now}` |",
        f"| Log format | `{fmt}` |",
        f"| Total lines | {total_lines} |",
        f"| Failed auth events | {len(events)} |",
        f"| Unique attacker IPs | {len(ip_stats)} |",
        f"| IPs above threshold (≥{threshold} fails) | {len(attackers)} |",
        f"| Unique targeted usernames | {len(user_stats)} |",
    ]

    # Top attacker IPs
    if attackers:
        lines += [
            f"",
            f"### Top attacker IPs (≥{threshold} failed attempts)",
            f"",
            f"| IP | Attempts | ASN | Holder | Country | UA variants |",
            f"|----|----------|-----|--------|---------|-------------|",
        ]
        for ip, data in attackers[:25]:
            info = enriched_ips.get(ip, {})
            asn     = info.get("asn") or "—"
            holder  = info.get("holder") or info.get("network") or "—"
            country = info.get("country") or "—"
            uas     = len(data.get("uas", set()))
            lines.append(
                f"| `{ip}` | {data['count']} | AS{asn} | {holder} | {country} | {uas} |"
            )
        if len(attackers) > 25:
            lines.append(f"| _…{len(attackers) - 25} more_ | | | | | |")

    # Targeted usernames
    if user_stats:
        top_users = sorted(user_stats.items(), key=lambda x: -x[1])[:20]
        lines += [
            f"",
            f"### Most targeted usernames / paths",
            f"",
            f"| Username / Path | Attempts |",
            f"|----------------|----------|",
        ]
        for user, count in top_users:
            lines.append(f"| `{user}` | {count} |")

    # User-agents (detect single-UA bulk attacks = bot)
    if top_uas:
        lines += [f"", f"### Top user agents (bot detection)", f""]
        for ua, count in top_uas[:5]:
            lines.append(f"- `{ua[:100]}` — {count} request(s)")

    # Assessment
    # Suspicious IPs (Tor, bulletproof, etc.)
    suspicious = [
        (ip, enriched_ips[ip])
        for ip, _ in attackers
        if ip in enriched_ips and any(
            kw in (enriched_ips[ip].get("holder") or "").lower()
            for kw in _SUSPICIOUS_KEYWORDS
        )
    ]
    if suspicious:
        lines += [f"", f"### Suspicious origins (botnet / Tor / bulletproof hosting)", f""]
        for ip, info in suspicious:
            lines.append(f"- ⚠️ `{ip}` — AS{info.get('asn','—')} {info.get('holder','—')}")

    lines += [f"", f"### Assessment signals"]
    if len(attackers) > 0:
        top_ip, top_data = attackers[0]
        top_info = enriched_ips.get(top_ip, {})
        lines.append(f"- ⚠️ Top attacker `{top_ip}` made **{top_data['count']}** failed attempts "
                     f"(AS{top_info.get('asn','—')} {top_info.get('holder','—')})")
    if suspicious:
        lines.append(f"- 🚨 **{len(suspicious)} IP(s) from Tor / bulletproof / botnet ASNs** — likely automated credential stuffing")
    if len(attackers) >= 10:
        lines.append(f"- ⚠️ **{len(attackers)} IPs** above threshold — likely coordinated credential stuffing")
    if len(user_stats) > 50:
        lines.append(f"- ⚠️ **{len(user_stats)} unique usernames** targeted — account enumeration detected")

    lines += ["", "_Parsed by flowintel-reverify `parse_auth_log` module._"]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    payload:
      log_text   : string — raw log content (required)
      log_format : "nginx" | "apache" | "auth" | "json" | "auto" (default: auto)
      threshold  : int — minimum fails to flag as attacker (default: 5)
      enrich_top : int — enrich top N attacker IPs via RDAP/ASN (default: 20)
    """
    payload    = payload or {}
    log_text   = payload.get("log_text", "")
    log_format = payload.get("log_format", "auto").lower()
    threshold  = int(payload.get("threshold", 5))
    enrich_top = int(payload.get("enrich_top", 20))
    case_id    = case.get("id") if isinstance(case, dict) else case.id

    if not log_text:
        return {"error": "No log_text provided. Pass raw log content in payload."}

    lines = log_text.splitlines()

    # Auto-detect format
    fmt = log_format if log_format != "auto" else _detect_format(lines)

    # Parse
    if fmt in ("nginx", "apache"):
        events = _parse_nginx(lines)
    elif fmt == "auth":
        events = _parse_auth(lines)
    elif fmt == "json":
        events = _parse_json_lines(lines)
    else:
        return {"error": f"Unknown format: {fmt}. Use nginx, apache, auth, json, or auto."}

    if not events:
        return {"message": f"No failed auth events found in {len(lines)} lines ({fmt} format)."}

    # Aggregate per IP
    ip_stats   = defaultdict(lambda: {"count": 0, "users": set(), "uas": set(), "paths": set()})
    user_stats = defaultdict(int)

    for ev in events:
        ip = ev["ip"]
        ip_stats[ip]["count"] += 1
        if ev.get("user"):
            ip_stats[ip]["users"].add(ev["user"])
            user_stats[ev["user"]] += 1
        elif ev.get("path"):
            ip_stats[ip]["paths"].add(ev["path"])
            user_stats[ev["path"]] += 1
        if ev.get("ua"):
            ip_stats[ip]["uas"].add(ev["ua"])

    # Top UAs
    ua_counts = defaultdict(int)
    for ev in events:
        if ev.get("ua"):
            ua_counts[ev["ua"]] += 1
    top_uas = sorted(ua_counts.items(), key=lambda x: -x[1])[:10]

    # Enrich top attacker IPs
    top_attackers = sorted(ip_stats.items(), key=lambda x: -x[1]["count"])[:enrich_top]
    enriched_ips  = {}
    for ip, _ in top_attackers:
        enriched_ips[ip] = _enrich_ip(ip)

    # Write note
    note = _format_note(fmt, len(lines), events, ip_stats, user_stats,
                        threshold, enriched_ips, top_uas)
    if db_session:
        _write_note(case_id, note, db_session)

    attackers = [(ip, d) for ip, d in ip_stats.items() if d["count"] >= threshold]
    return {
        "total_lines"      : len(lines),
        "log_format"       : fmt,
        "failed_events"    : len(events),
        "unique_ips"       : len(ip_stats),
        "attackers_above_threshold": len(attackers),
        "unique_users"     : len(user_stats),
        "top_attackers"    : [
            {"ip": ip, "attempts": d["count"],
             "asn": enriched_ips.get(ip, {}).get("asn"),
             "holder": enriched_ips.get(ip, {}).get("holder")}
            for ip, d in top_attackers[:10]
        ],
    }


def introspection():
    return {
        "name"       : "parse_auth_log",
        "description": module_config["description"],
        "type"       : "analyze",
        "payload"    : [
            {"name": "log_text",   "type": "string",  "description": "Raw log content (required)"},
            {"name": "log_format", "type": "string",  "description": "nginx | apache | auth | json | auto (default: auto)"},
            {"name": "threshold",  "type": "integer", "description": "Min failed attempts to flag IP as attacker (default: 5)"},
            {"name": "enrich_top", "type": "integer", "description": "Enrich top N IPs via RDAP/ASN (default: 20)"},
        ],
    }


def module_config_def():
    return module_config
