"""
Flowintel module: enrich_observable
Category: analyze

Enriches a domain, IP address, or file hash against open sources.
No API key required for any source.

  Domain → RDAP registration data + CIRCL passive DNS
  IP     → RDAP network info + RIPE Stat ASN/prefix
  Hash   → TLSH + ssdeep fuzzy match against local Flowintel uploads corpus

Payload:
  type         : "domain" | "ip" | "hash"  (auto-detected if omitted)
  value        : the observable to enrich
  corpus_path  : path to scan for fuzzy hash matching
                 (default: /opt/flowintel/uploads/files/)
"""

import os
import re
import hashlib
import logging
import datetime as _dt
import requests

logger = logging.getLogger(__name__)

module_config = {
    "connector": "none",
    "case_task": "case",
    "description": (
        "Enrich a domain, IP, or hash observable against open sources (no API key required). "
        "Domain/IP: RDAP + CIRCL passive DNS + RIPE Stat ASN. "
        "Hash: TLSH + ssdeep fuzzy match against local upload corpus."
    ),
}

_DEFAULT_CORPUS = "/opt/flowintel/uploads/files"
_TIMEOUT = 10

_RE_IP4    = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_RE_DOMAIN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
_RE_MD5    = re.compile(r'^[0-9a-fA-F]{32}$')
_RE_SHA1   = re.compile(r'^[0-9a-fA-F]{40}$')
_RE_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')


# ─────────────────────────────────────────────────────────────────────────────
# Type detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_type(value: str) -> str:
    v = value.strip()
    if _RE_IP4.match(v):
        return "ip"
    if _RE_MD5.match(v) or _RE_SHA1.match(v) or _RE_SHA256.match(v):
        return "hash"
    if _RE_DOMAIN.match(v):
        return "domain"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Domain enrichment
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_domain(domain: str) -> dict:
    result = {"domain": domain, "rdap": {}, "passive_dns": []}

    # RDAP
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            result["rdap"] = {
                "registrar"    : next((e.get("identifier") for e in data.get("entities", [])
                                       if "registrar" in e.get("roles", [])), None),
                "status"       : data.get("status", []),
                "registered"   : _rdap_date(data, "registration"),
                "expires"      : _rdap_date(data, "expiration"),
                "nameservers"  : [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
            }
    except Exception as exc:
        result["rdap"]["error"] = str(exc)

    # CIRCL passive DNS
    try:
        r = requests.get(
            f"https://www.circl.lu/pdns/query/{domain}",
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            seen = set()
            for line in r.text.strip().splitlines():
                try:
                    import json
                    obj = json.loads(line)
                    key = (obj.get("rrtype"), obj.get("rdata"))
                    if key not in seen:
                        seen.add(key)
                        result["passive_dns"].append({
                            "type"      : obj.get("rrtype"),
                            "value"     : obj.get("rdata"),
                            "time_first": obj.get("time_first_datetime", ""),
                            "time_last" : obj.get("time_last_datetime", ""),
                            "count"     : obj.get("count", 0),
                        })
                except Exception:
                    pass
            result["passive_dns"] = sorted(
                result["passive_dns"], key=lambda x: x.get("count", 0), reverse=True
            )[:20]
    except Exception as exc:
        result["passive_dns_error"] = str(exc)

    return result


def _rdap_date(data: dict, event_action: str) -> str:
    for ev in data.get("events", []):
        if ev.get("eventAction") == event_action:
            return ev.get("eventDate", "")
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# IP enrichment
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_ip(ip: str) -> dict:
    result = {"ip": ip, "rdap": {}, "asn": {}}

    # RDAP
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", timeout=_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            result["rdap"] = {
                "name"   : data.get("name", ""),
                "country": data.get("country", ""),
                "type"   : data.get("type", ""),
                "cidr"   : next(iter(data.get("cidr0_cidrs", [])), {}).get("v4prefix", ""),
                "status" : data.get("status", []),
            }
    except Exception as exc:
        result["rdap"]["error"] = str(exc)

    # RIPE Stat — ASN prefix overview (no auth required)
    try:
        r = requests.get(
            "https://stat.ripe.net/data/prefix-overview/data.json",
            params={"resource": ip},
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            asns = data.get("asns", [])
            result["asn"] = {
                "prefix": data.get("resource", ""),
                "asns"  : [{"asn": a.get("asn"), "holder": a.get("holder")} for a in asns],
                "is_less_specific": data.get("is_less_specific", False),
            }
    except Exception as exc:
        result["asn"]["error"] = str(exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Hash enrichment — fuzzy match against local corpus
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_hash(hash_value: str, corpus_path: str) -> dict:
    result = {
        "hash"  : hash_value,
        "tlsh"  : {"matches": [], "error": None},
        "ssdeep": {"matches": [], "error": None},
    }

    # Find the file in the corpus that matches the exact hash
    target_path = _find_file_by_hash(hash_value, corpus_path)
    if not target_path:
        result["error"] = f"File with hash {hash_value} not found in corpus {corpus_path}"
        return result

    raw = open(target_path, "rb").read()

    # TLSH fuzzy matching
    try:
        import tlsh as _tlsh
        target_tlsh = _tlsh.hash(raw)
        if target_tlsh and target_tlsh != "TNULL":
            for path in _corpus_files(corpus_path, exclude=target_path):
                try:
                    candidate = open(path, "rb").read()
                    candidate_tlsh = _tlsh.hash(candidate)
                    if candidate_tlsh and candidate_tlsh != "TNULL":
                        score = _tlsh.diff(target_tlsh, candidate_tlsh)
                        if score <= 200:
                            result["tlsh"]["matches"].append({
                                "file" : os.path.basename(path),
                                "path" : path,
                                "score": score,
                                "tlsh" : candidate_tlsh,
                            })
                except Exception:
                    pass
            result["tlsh"]["matches"].sort(key=lambda x: x["score"])
            result["tlsh"]["hash"] = target_tlsh
    except ImportError:
        result["tlsh"]["error"] = "python-tlsh not available"
    except Exception as exc:
        result["tlsh"]["error"] = str(exc)

    # ssdeep fuzzy matching
    try:
        import ssdeep as _ssdeep
        target_ssdeep = _ssdeep.hash(raw)
        for path in _corpus_files(corpus_path, exclude=target_path):
            try:
                candidate = open(path, "rb").read()
                candidate_ssdeep = _ssdeep.hash(candidate)
                score = _ssdeep.compare(target_ssdeep, candidate_ssdeep)
                if score >= 30:
                    result["ssdeep"]["matches"].append({
                        "file"  : os.path.basename(path),
                        "path"  : path,
                        "score" : score,
                        "ssdeep": candidate_ssdeep,
                    })
            except Exception:
                pass
        result["ssdeep"]["matches"].sort(key=lambda x: x["score"], reverse=True)
        result["ssdeep"]["hash"] = target_ssdeep
    except ImportError:
        result["ssdeep"]["error"] = "ssdeep not available"
    except Exception as exc:
        result["ssdeep"]["error"] = str(exc)

    return result


def _find_file_by_hash(hash_value: str, corpus_path: str) -> str | None:
    hash_value = hash_value.lower()
    algo = (hashlib.md5 if len(hash_value) == 32
            else hashlib.sha1 if len(hash_value) == 40
            else hashlib.sha256)
    for path in _corpus_files(corpus_path):
        try:
            digest = algo(open(path, "rb").read()).hexdigest()
            if digest == hash_value:
                return path
        except Exception:
            pass
    return None


def _corpus_files(corpus_path: str, exclude: str = None):
    if not os.path.isdir(corpus_path):
        return
    for name in os.listdir(corpus_path):
        path = os.path.join(corpus_path, name)
        if os.path.isfile(path) and path != exclude:
            yield path


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
        logger.warning("Could not write enrichment note to case: %s", exc)


def _format_domain_note(r: dict) -> str:
    lines = [f"## Enrichment: `{r['domain']}` (domain)", ""]
    rdap = r.get("rdap", {})
    if rdap and "error" not in rdap:
        lines += [
            "**RDAP registration:**",
            f"- Registrar: {rdap.get('registrar') or '—'}",
            f"- Registered: {rdap.get('registered') or '—'}",
            f"- Expires: {rdap.get('expires') or '—'}",
            f"- Status: {', '.join(rdap.get('status', [])) or '—'}",
            f"- Nameservers: {', '.join(rdap.get('nameservers', [])) or '—'}",
            "",
        ]
    pdns = r.get("passive_dns", [])
    if pdns:
        lines.append("**CIRCL Passive DNS (recent resolutions):**")
        for rec in pdns[:10]:
            lines.append(
                f"- `{rec['type']}` → `{rec['value']}` "
                f"(last seen: {rec['time_last'][:10] if rec['time_last'] else '?'}, "
                f"count: {rec['count']})"
            )
        lines.append("")
    return "\n".join(lines)


def _format_ip_note(r: dict) -> str:
    lines = [f"## Enrichment: `{r['ip']}` (IP address)", ""]
    rdap = r.get("rdap", {})
    if rdap and "error" not in rdap:
        lines += [
            "**RDAP network info:**",
            f"- Name: {rdap.get('name') or '—'}",
            f"- Country: {rdap.get('country') or '—'}",
            f"- CIDR: {rdap.get('cidr') or '—'}",
            f"- Type: {rdap.get('type') or '—'}",
            "",
        ]
    asn = r.get("asn", {})
    if asn and "error" not in asn:
        lines.append("**RIPE Stat ASN:**")
        for a in asn.get("asns", []):
            lines.append(f"- AS{a['asn']} — {a['holder']}")
        if not asn.get("asns"):
            lines.append("- No ASN data found")
        lines.append("")
    return "\n".join(lines)


def _format_hash_note(r: dict) -> str:
    lines = [f"## Enrichment: `{r['hash']}` (hash — fuzzy match)", ""]
    if r.get("error"):
        lines.append(f"_{r['error']}_")
        return "\n".join(lines)

    tlsh = r.get("tlsh", {})
    if tlsh.get("hash"):
        lines.append(f"**TLSH:** `{tlsh['hash']}`")
    if tlsh.get("matches"):
        lines.append("**TLSH matches (score ≤ 200, lower = more similar):**")
        for m in tlsh["matches"][:5]:
            lines.append(f"- `{m['file']}` — score {m['score']}")
    elif not tlsh.get("error"):
        lines.append("**TLSH:** no similar files found in local corpus")
    if tlsh.get("error"):
        lines.append(f"**TLSH error:** {tlsh['error']}")
    lines.append("")

    ssdeep = r.get("ssdeep", {})
    if ssdeep.get("hash"):
        lines.append(f"**ssdeep:** `{ssdeep['hash']}`")
    if ssdeep.get("matches"):
        lines.append("**ssdeep matches (score ≥ 30, higher = more similar):**")
        for m in ssdeep["matches"][:5]:
            lines.append(f"- `{m['file']}` — score {m['score']}")
    elif not ssdeep.get("error"):
        lines.append("**ssdeep:** no similar files found in local corpus")
    if ssdeep.get("error"):
        lines.append(f"**ssdeep error:** {ssdeep['error']}")
    lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    payload:
      type        : "domain" | "ip" | "hash"  (auto-detected if omitted)
      value       : observable to enrich
      corpus_path : path for fuzzy hash scan (default: /opt/flowintel/uploads/files/)
    """
    payload     = payload or {}
    value       = payload.get("value", "").strip()
    obs_type    = payload.get("type", "").lower() or _detect_type(value)
    corpus_path = payload.get("corpus_path", _DEFAULT_CORPUS)

    if not value:
        return {"message": "No value provided. Pass 'value' in payload."}
    if obs_type == "unknown":
        return {"message": f"Cannot detect type for value: {value!r}. Pass 'type' explicitly."}

    if obs_type == "domain":
        result   = _enrich_domain(value)
        note     = _format_domain_note(result)
    elif obs_type == "ip":
        result   = _enrich_ip(value)
        note     = _format_ip_note(result)
    elif obs_type == "hash":
        result   = _enrich_hash(value, corpus_path)
        note     = _format_hash_note(result)
    else:
        return {"message": f"Unsupported type: {obs_type}. Use 'domain', 'ip', or 'hash'."}

    _write_note(case, note, db_session)

    return {
        "type"   : obs_type,
        "value"  : value,
        "result" : result,
    }


def introspection():
    return module_config
