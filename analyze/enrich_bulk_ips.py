"""
Flowintel module: enrich_bulk_ips
Enrich a list of IP addresses in bulk — designed for DDoS source analysis.
Groups results by ASN, flags suspicious origins, writes a summary to case Notes.
Individual enrichment notes are NOT written (too noisy); only the grouped summary.
"""

import re
import logging
from collections import defaultdict

import requests

logger = logging.getLogger(__name__)

module_config = {
    "connector"  : "none",
    "case_task"  : "case",
    "description": (
        "Bulk IP enrichment for DDoS analysis — group source IPs by ASN/country, "
        "identify top attack origins, flag suspicious ASNs. Designed for cases with "
        "many source IPs from logs or netflow data."
    ),
}

_IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RDAP_URL  = "https://rdap.org/ip/{}"
_RIPE_URL  = "https://stat.ripe.net/data/prefix-overview/data.json?resource={}"
_TIMEOUT   = 8

# ASNs commonly associated with botnets, bulletproof hosting, Tor exits
_SUSPICIOUS_ASN_KEYWORDS = [
    "tor", "exit", "bulletproof", "choopa", "frantech", "leaseweb",
    "serverius", "ecatel", "quasi", "novogara", "combahton",
]


# ─────────────────────────────────────────────────────────────────────────────
# IP enrichment (lightweight — ASN + country only, no full RDAP)
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_ip_fast(ip: str) -> dict:
    """Return {asn, holder, country, network} for one IP. Fast, no Lookyloo."""
    result = {"ip": ip, "asn": None, "holder": None, "country": None, "network": None}
    try:
        r = requests.get(_RDAP_URL.format(ip), timeout=_TIMEOUT,
                         headers={"Accept": "application/json"})
        if r.ok:
            d = r.json()
            result["network"] = d.get("name") or d.get("handle")
            result["country"] = d.get("country")
            for entity in d.get("entities", []):
                for v in entity.get("vcardArray", [["", []]])[1]:
                    if isinstance(v, list) and "adr" in str(v):
                        pass
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


def _is_suspicious(holder: str) -> bool:
    if not holder:
        return False
    h = holder.lower()
    return any(kw in h for kw in _SUSPICIOUS_ASN_KEYWORDS)


# ─────────────────────────────────────────────────────────────────────────────
# Note helpers
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


def _extract_ips_from_notes(case_id: int) -> list:
    try:
        from app.case import common_core as _CC
        case_orm = _CC.get_case(case_id)
        notes = case_orm.notes if case_orm else ""
        return list(set(_IP_RE.findall(notes or "")))
    except Exception:
        return []


def _format_note(ips_input, enriched, by_asn, by_country, suspicious, skipped) -> str:
    lines = [
        f"## Bulk IP Enrichment",
        f"",
        f"**Input:** {len(ips_input)} IPs | "
        f"**Enriched:** {len(enriched)} | "
        f"**Skipped (private/invalid):** {skipped} | "
        f"**Suspicious ASNs:** {len(suspicious)}",
        f"",
    ]

    # Top ASNs
    lines += [
        f"### Top ASNs ({len(by_asn)} unique)",
        f"",
        f"| ASN | Holder | IPs | Country | Flag |",
        f"|-----|--------|-----|---------|------|",
    ]
    for asn, data in sorted(by_asn.items(), key=lambda x: -len(x[1]["ips"]))[:20]:
        flag = "⚠️ SUSPICIOUS" if _is_suspicious(data["holder"]) else ""
        countries = ", ".join(sorted(data["countries"]))
        lines.append(
            f"| AS{asn} | {data['holder'] or '—'} | {len(data['ips'])} | {countries} | {flag} |"
        )

    # Top countries
    lines += [
        f"",
        f"### Country distribution ({len(by_country)} countries)",
        f"",
        f"| Country | IPs |",
        f"|---------|-----|",
    ]
    for country, count in sorted(by_country.items(), key=lambda x: -x[1])[:15]:
        lines.append(f"| {country or '—'} | {count} |")

    # Suspicious IPs
    if suspicious:
        lines += [
            f"",
            f"### Suspicious IPs ({len(suspicious)})",
            f"",
            f"⚠️ These IPs belong to ASNs associated with botnets, bulletproof hosting, or Tor exits:",
            f"",
        ]
        for ip, holder in suspicious[:30]:
            lines.append(f"- `{ip}` — {holder}")
        if len(suspicious) > 30:
            lines.append(f"- _…{len(suspicious) - 30} more_")

    lines += ["", "_Enriched by flowintel-reverify `enrich_bulk_ips` module._"]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Private IP filter
# ─────────────────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    try:
        parts = list(map(int, ip.split(".")))
        return (
            parts[0] == 10
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
            or parts[0] == 127
            or parts[0] == 0
        )
    except Exception:
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    payload:
      ips      : list of IP strings — if omitted, auto-extracted from case Notes
      max_ips  : int — cap on how many IPs to enrich (default: 100)
    """
    payload  = payload or {}
    max_ips  = int(payload.get("max_ips", 100))
    case_id  = case.get("id") if isinstance(case, dict) else case.id

    # Resolve IP list
    ips_raw = payload.get("ips") or []
    if not ips_raw:
        ips_raw = _extract_ips_from_notes(case_id)

    # Deduplicate + filter private
    seen, ips_public = set(), []
    skipped = 0
    for ip in ips_raw:
        ip = ip.strip()
        if ip in seen:
            continue
        seen.add(ip)
        if _is_private(ip):
            skipped += 1
        else:
            ips_public.append(ip)

    if not ips_public:
        return {"message": "No public IPs found. Pass 'ips' in payload or run enrich_observable first."}

    ips_to_enrich = ips_public[:max_ips]
    if len(ips_public) > max_ips:
        logger.info("Capping enrichment at %d IPs (total: %d)", max_ips, len(ips_public))

    # Enrich
    enriched   = []
    by_asn     = defaultdict(lambda: {"holder": None, "ips": [], "countries": set()})
    by_country = defaultdict(int)
    suspicious = []

    for ip in ips_to_enrich:
        info = _enrich_ip_fast(ip)
        enriched.append(info)

        asn    = info.get("asn") or "unknown"
        holder = info.get("holder") or ""
        country = info.get("country") or "unknown"

        by_asn[asn]["holder"] = holder
        by_asn[asn]["ips"].append(ip)
        by_asn[asn]["countries"].add(country)
        by_country[country] += 1

        if _is_suspicious(holder):
            suspicious.append((ip, holder))

    # Write summary note
    note = _format_note(ips_public, enriched, by_asn, by_country, suspicious, skipped)
    if db_session:
        _write_note(case_id, note, db_session)

    return {
        "total_input"    : len(ips_raw),
        "public_ips"     : len(ips_public),
        "enriched"       : len(enriched),
        "skipped_private": skipped,
        "unique_asns"    : len(by_asn),
        "unique_countries": len(by_country),
        "suspicious_count": len(suspicious),
        "top_asns"       : [
            {"asn": k, "holder": v["holder"], "ip_count": len(v["ips"])}
            for k, v in sorted(by_asn.items(), key=lambda x: -len(x[1]["ips"]))[:10]
        ],
    }


def introspection():
    return {
        "name"       : "enrich_bulk_ips",
        "description": module_config["description"],
        "type"       : "analyze",
        "payload"    : [
            {"name": "ips",     "type": "list",    "description": "List of IP strings to enrich (auto-extracted from Notes if omitted)"},
            {"name": "max_ips", "type": "integer", "description": "Max IPs to enrich (default: 100)"},
        ],
    }


def module_config_def():
    return module_config
