"""
Flowintel module: correlate_observables
Category: analyze

Cross-case correlation for observables extracted from enrichment findings.
Scans Notes of all other cases in this Flowintel instance for matching
IPs, hashes (MD5/SHA1/SHA256), and ASNs.

Payload:
  observables  : list of strings to search for (type auto-detected)
                 if omitted, values are auto-extracted from the current case Notes
  types        : list of types to auto-extract from Notes when no observables given
                 ["ip", "hash", "asn"] — default: all three
  create_links : bool — create Flowintel case links for matching cases (default: true)
  min_overlap  : int  — minimum shared observables to include a case in results (default: 1)
"""

import re
import logging
import datetime as _dt

logger = logging.getLogger(__name__)

module_config = {
    "connector": "none",
    "case_task": "case",
    "description": (
        "Cross-case correlation: scans Notes of all other cases for overlapping "
        "IPs, hashes (MD5/SHA1/SHA256), and ASNs. Creates case links for matches. "
        "Observables auto-extracted from current case Notes if not supplied in payload."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Observable extraction from free text
# ─────────────────────────────────────────────────────────────────────────────

_RE_IPV4   = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_RE_MD5    = re.compile(r'\b([0-9a-fA-F]{32})\b')
_RE_SHA1   = re.compile(r'\b([0-9a-fA-F]{40})\b')
_RE_SHA256 = re.compile(r'\b([0-9a-fA-F]{64})\b')
_RE_ASN    = re.compile(r'\b(AS\d{1,10})\b')

# IPs to exclude from correlation (too generic / infrastructure)
_EXCLUDED_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "192.168.0.0", "10.0.0.0",
}

def _extract_from_text(text: str, types: list) -> dict[str, set]:
    """Extract observables from free text. Returns {type: set(value)}."""
    found = {"ip": set(), "hash": set(), "asn": set()}
    if not text:
        return found

    if "ip" in types:
        for m in _RE_IPV4.finditer(text):
            ip = m.group(1)
            if ip not in _EXCLUDED_IPS:
                # Rough validity check
                if all(0 <= int(o) <= 255 for o in ip.split(".")):
                    found["ip"].add(ip)

    if "hash" in types:
        # SHA256 first (64 chars) to avoid false matches against shorter patterns
        for m in _RE_SHA256.finditer(text):
            found["hash"].add(m.group(1).lower())
        # Then SHA1 — exclude anything already matched as SHA256 suffix
        sha256_vals = found["hash"].copy()
        for m in _RE_SHA1.finditer(text):
            v = m.group(1).lower()
            if not any(v in s for s in sha256_vals):
                found["hash"].add(v)
        # MD5 last
        for m in _RE_MD5.finditer(text):
            v = m.group(1).lower()
            if not any(v in s for s in found["hash"]):
                found["hash"].add(v)

    if "asn" in types:
        for m in _RE_ASN.finditer(text):
            found["asn"].add(m.group(1).upper())

    return found


def _detect_type(value: str) -> str:
    v = value.strip().lower()
    if _RE_ASN.match(value.strip()):
        return "asn"
    if _RE_IPV4.fullmatch(value.strip()):
        return "ip"
    if len(v) in (32, 40, 64) and re.fullmatch(r'[0-9a-f]+', v):
        return "hash"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Case link helpers
# ─────────────────────────────────────────────────────────────────────────────

def _link_exists(case_id_1: int, case_id_2: int, db_session) -> bool:
    try:
        from app.db_class.db import Case_Link_Case
        a, b = sorted([case_id_1, case_id_2])
        existing = db_session.session.query(Case_Link_Case).filter(
            ((Case_Link_Case.case_id_1 == a) & (Case_Link_Case.case_id_2 == b)) |
            ((Case_Link_Case.case_id_1 == b) & (Case_Link_Case.case_id_2 == a))
        ).first()
        return existing is not None
    except Exception:
        return False


def _create_link(case_id_1: int, case_id_2: int, db_session) -> bool:
    try:
        from app.db_class.db import Case_Link_Case
        if _link_exists(case_id_1, case_id_2, db_session):
            return False  # already linked
        a, b = sorted([case_id_1, case_id_2])
        link = Case_Link_Case(case_id_1=a, case_id_2=b)
        db_session.session.add(link)
        db_session.session.commit()
        return True
    except Exception as exc:
        logger.warning("Could not create case link %s↔%s: %s", case_id_1, case_id_2, exc)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Correlation scan
# ─────────────────────────────────────────────────────────────────────────────

def _scan_all_cases(current_case_id: int, search_values: set, user, db_session) -> list:
    """
    Scan Notes of all other cases for any value in search_values.
    Returns list of {case_id, title, matches: [{value, type}], already_linked}.
    """
    results = []
    try:
        from app.case import common_core as _CC
        from app.db_class.db import Case
        all_cases = Case.query.filter(Case.id != current_case_id).all()
    except Exception as exc:
        logger.warning("Could not query cases: %s", exc)
        return results

    # Normalise search set to lowercase for hash matching
    search_lower = {v.lower() for v in search_values}
    search_norm  = search_values | search_lower

    for case_orm in all_cases:
        notes = case_orm.notes or ""
        if not notes.strip():
            continue
        notes_lower = notes.lower()
        matched = []
        for val in search_values:
            # Case-insensitive search for IPs/ASNs; lower for hashes
            needle = val.lower() if len(val) in (32, 40, 64) else val
            haystack = notes_lower if len(val) in (32, 40, 64) else notes
            if needle in haystack:
                matched.append({"value": val, "type": _detect_type(val)})

        if matched:
            already = _link_exists(current_case_id, case_orm.id, db_session)
            results.append({
                "case_id"       : case_orm.id,
                "title"         : case_orm.title or f"Case #{case_orm.id}",
                "last_modif"    : str(case_orm.last_modif)[:10] if case_orm.last_modif else "",
                "matches"       : matched,
                "already_linked": already,
            })

    # Sort by number of matches descending
    results.sort(key=lambda r: len(r["matches"]), reverse=True)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Note writer
# ─────────────────────────────────────────────────────────────────────────────

def _write_note(case, note_text: str, db_session):
    if not db_session:
        return
    try:
        case_id = case.get("id") if isinstance(case, dict) else case.id
        from app.case import common_core as _CC
        case_orm = _CC.get_case(case_id)
        if case_orm:
            case_orm.notes = (case_orm.notes or "") + "\n\n" + note_text
            case_orm.last_modif = _dt.datetime.now()
            db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not write correlation note: %s", exc)


def _format_note(current_case_id: int, search_values: set,
                 corr_results: list, linked: list) -> str:
    lines = [
        f"## Correlation: Case #{current_case_id}",
        f"",
        f"Searched {len(search_values)} observable(s) across all cases.",
        "",
    ]

    if not corr_results:
        lines.append("No matching observables found in other cases.")
        return "\n".join(lines)

    lines.append(f"Found overlap in **{len(corr_results)}** case(s):")
    lines.append("")

    for r in corr_results:
        n = len(r["matches"])
        label = f"{n} shared observable" + ("s" if n > 1 else "")
        link_status = "link already existed" if r["already_linked"] else (
            "case link created ✓" if r["case_id"] in linked else "case link skipped"
        )
        lines.append(f"### Case #{r['case_id']} — {r['title']} ({label})")
        if r["last_modif"]:
            lines.append(f"_Last modified: {r['last_modif']}_")
        for m in r["matches"]:
            lines.append(f"- `{m['value']}` ({m['type']})")
        lines.append(f"_{link_status}_")
        lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    payload:
      observables  : list of strings to search for (auto-detected type)
                     if omitted, auto-extracted from current case Notes
      types        : ["ip", "hash", "asn"] — types to auto-extract (default: all)
      create_links : bool — create case links for matches (default: true)
      min_overlap  : int  — minimum shared observables to include a case (default: 1)
    """
    payload      = payload or {}
    create_links = payload.get("create_links", True)
    min_overlap  = int(payload.get("min_overlap", 1))
    types        = payload.get("types", ["ip", "hash", "asn"])

    case_id = case.get("id") if isinstance(case, dict) else case.id

    # 1. Determine what to search for
    if payload.get("observables"):
        search_values = {str(v).strip() for v in payload["observables"] if v}
    else:
        # Auto-extract from current case Notes
        try:
            from app.case import common_core as _CC
            case_orm = _CC.get_case(case_id)
            notes_text = case_orm.notes if case_orm else ""
        except Exception:
            notes_text = ""
        extracted = _extract_from_text(notes_text, types)
        search_values = set()
        for vals in extracted.values():
            search_values.update(vals)

    if not search_values:
        return {"message": "No observables found to correlate. Run enrich_observable first, or pass 'observables' in payload."}

    # 2. Scan all other cases
    corr_results = _scan_all_cases(case_id, search_values, user, db_session)

    # Filter by min_overlap
    corr_results = [r for r in corr_results if len(r["matches"]) >= min_overlap]

    # 3. Create case links
    linked_case_ids = []
    if create_links and db_session:
        for r in corr_results:
            if not r["already_linked"]:
                created = _create_link(case_id, r["case_id"], db_session)
                if created:
                    linked_case_ids.append(r["case_id"])

    # 4. Write note
    note = _format_note(case_id, search_values, corr_results, linked_case_ids)
    _write_note(case, note, db_session)

    return {
        "searched"     : len(search_values),
        "matched_cases": len(corr_results),
        "linked"       : linked_case_ids,
        "correlations" : [
            {
                "case_id": r["case_id"],
                "title"  : r["title"],
                "matches": r["matches"],
            }
            for r in corr_results
        ],
    }


def introspection():
    return module_config
