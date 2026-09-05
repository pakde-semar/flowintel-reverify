"""
Flowintel module: enrich_observable
Category: analyze

Enriches a domain, IP address, URL, or file hash against open sources.
No API key required for any source.

  Domain → RDAP registration data + CIRCL passive DNS
  IP     → RDAP network info + RIPE Stat ASN/prefix
  URL    → Lookyloo (CIRCL public instance): redirect chain, IPs contacted, screenshot link
  Hash   → TLSH + ssdeep fuzzy match against local Flowintel uploads corpus

Payload:
  type         : "domain" | "ip" | "url" | "hash"  (auto-detected if omitted)
  value        : the observable to enrich
  corpus_path  : path to scan for fuzzy hash matching
                 (default: /opt/flowintel/uploads/files/)
  lookyloo_url : Lookyloo instance base URL
                 (default: https://lookyloo.circl.lu)
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
        "Enrich a domain, IP, URL, or hash observable against open sources (no API key required). "
        "Domain/IP: RDAP + CIRCL passive DNS + RIPE Stat ASN. "
        "URL: Lookyloo (CIRCL public) — redirect chain, IPs contacted, screenshot link. "
        "Hash: TLSH + ssdeep fuzzy match against local upload corpus."
    ),
}

_DEFAULT_CORPUS   = "/opt/flowintel/uploads/files"
_DEFAULT_LOOKYLOO = "https://lookyloo.circl.lu"
_TIMEOUT          = 10
_LOOKYLOO_WAIT    = 60   # max seconds to wait for capture

_RE_IP4    = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_RE_DOMAIN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
_RE_URL    = re.compile(r'^https?://', re.IGNORECASE)
_RE_MD5    = re.compile(r'^[0-9a-fA-F]{32}$')
_RE_SHA1   = re.compile(r'^[0-9a-fA-F]{40}$')
_RE_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')


# ─────────────────────────────────────────────────────────────────────────────
# Type detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_type(value: str) -> str:
    v = value.strip()
    if _RE_URL.match(v):
        return "url"
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
# URL enrichment — Lookyloo
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_url(url: str, lookyloo_base: str) -> dict:
    import time
    base    = lookyloo_base.rstrip("/")
    result  = {"url": url, "lookyloo_base": base, "uuid": None,
               "status": None, "redirects": [], "ips": [],
               "final_url": None, "error": None}

    # 1. Submit URL
    try:
        r = requests.post(
            f"{base}/submit",
            json={"url": url, "listing": False},
            timeout=_TIMEOUT,
        )
        if r.status_code not in (200, 201):
            result["error"] = f"Submit failed: HTTP {r.status_code}"
            return result
        uuid = r.text.strip().strip('"')
        result["uuid"] = uuid
    except Exception as exc:
        result["error"] = f"Submit error: {exc}"
        return result

    # 2. Poll until done (max _LOOKYLOO_WAIT seconds)
    deadline = time.time() + _LOOKYLOO_WAIT
    while time.time() < deadline:
        try:
            sr = requests.get(f"{base}/status/{uuid}", timeout=_TIMEOUT)
            data = sr.json()
            status = data.get("status") or data.get("status_code")
            result["status"] = status
            # Lookyloo returns "done" or status_code 0 when complete
            if str(status).lower() in ("done", "0", "0.0") or status == 0:
                break
        except Exception:
            pass
        time.sleep(5)
    else:
        result["error"] = f"Capture timed out after {_LOOKYLOO_WAIT}s — check {base}/capture/{uuid}"
        return result

    # 3. Fetch JSON result
    try:
        jr = requests.get(f"{base}/json/{uuid}", timeout=_TIMEOUT)
        data = jr.json()

        # Redirect chain
        redirects = data.get("redirects", [])
        if not redirects:
            # Try nested structure
            try:
                nodes = data.get("nodes", {})
                for node in nodes.values():
                    url_node = node.get("urls", [])
                    redirects.extend(url_node)
            except Exception:
                pass
        result["redirects"] = redirects[:20]

        # Final URL
        result["final_url"] = (redirects[-1] if redirects else url)

        # IPs contacted
        ips = []
        try:
            for hostname, info in data.get("hostnames", {}).items():
                for ip in info.get("ips", []):
                    ips.append({"hostname": hostname, "ip": ip})
        except Exception:
            pass
        result["ips"] = ips[:20]

        # Screenshot URL (viewable in browser)
        result["screenshot_url"] = f"{base}/screenshot/{uuid}"
        result["capture_url"]    = f"{base}/capture/{uuid}"

    except Exception as exc:
        result["error"] = f"Result fetch error: {exc}"

    return result


def _format_url_note(r: dict) -> str:
    lines = [f"## Enrichment: `{r['url']}` (URL — Lookyloo)", ""]

    if r.get("error"):
        lines += [f"**Error:** {r['error']}", ""]
        if r.get("uuid"):
            lines += [f"**Capture:** {r['lookyloo_base']}/capture/{r['uuid']}", ""]
        return "\n".join(lines)

    if r.get("capture_url"):
        lines += [f"**Capture:** [{r['capture_url']}]({r['capture_url']})"]
    if r.get("screenshot_url"):
        lines += [f"**Screenshot:** [{r['screenshot_url']}]({r['screenshot_url']})"]
    lines.append("")

    if r.get("final_url") and r["final_url"] != r["url"]:
        lines += [f"**Final URL (after redirects):** `{r['final_url']}`", ""]

    redirects = r.get("redirects", [])
    if len(redirects) > 1:
        lines.append("**Redirect chain:**")
        for i, u in enumerate(redirects):
            lines.append(f"{i + 1}. `{u}`")
        lines.append("")

    ips = r.get("ips", [])
    if ips:
        lines.append("**IPs contacted:**")
        for entry in ips:
            lines.append(f"- `{entry['ip']}` — {entry['hostname']}")
        lines.append("")

    return "\n".join(lines)


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
      type         : "domain" | "ip" | "url" | "hash"  (auto-detected if omitted)
      value        : observable to enrich
      corpus_path  : path for fuzzy hash scan (default: /opt/flowintel/uploads/files/)
      lookyloo_url : Lookyloo instance (default: https://lookyloo.circl.lu)
    """
    payload      = payload or {}
    value        = payload.get("value", "").strip()
    obs_type     = payload.get("type", "").lower() or _detect_type(value)
    corpus_path  = payload.get("corpus_path", _DEFAULT_CORPUS)
    lookyloo_url = payload.get("lookyloo_url", _DEFAULT_LOOKYLOO)

    if not value:
        return {"message": "No value provided. Pass 'value' in payload."}
    if obs_type == "unknown":
        return {"message": f"Cannot detect type for value: {value!r}. Pass 'type' explicitly."}

    if obs_type == "domain":
        result = _enrich_domain(value)
        note   = _format_domain_note(result)
    elif obs_type == "ip":
        result = _enrich_ip(value)
        note   = _format_ip_note(result)
    elif obs_type == "url":
        result = _enrich_url(value, lookyloo_url)
        note   = _format_url_note(result)
    elif obs_type == "hash":
        result = _enrich_hash(value, corpus_path)
        note   = _format_hash_note(result)
    else:
        return {"message": f"Unsupported type: {obs_type}. Use 'domain', 'ip', 'url', or 'hash'."}

    _write_note(case, note, db_session)

    return {
        "type"   : obs_type,
        "value"  : value,
        "result" : result,
    }


def introspection():
    return module_config
