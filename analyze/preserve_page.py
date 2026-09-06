"""
Flowintel module: preserve_page
Forensic snapshot of a web page — screenshot, HTML source, external resource
inventory, SHA-256 integrity hashes, UTC timestamp, optional Wayback Machine
submission. Designed for defacement, script injection, and XSS evidence collection.
"""

import os
import re
import uuid
import hashlib
import datetime
import logging
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

module_config = {
    "connector"  : "none",
    "case_task"  : "case",
    "description": (
        "Forensic snapshot — Playwright screenshot, HTML source, external resource "
        "inventory, SHA-256 integrity hashes, UTC timestamp, Wayback Machine submission. "
        "Use before a defaced or injected page is restored."
    ),
}

_WAYBACK_API = "https://web.archive.org/save"
_FILE_FOLDER = os.path.join(os.getcwd(), "uploads", "files")


# ─────────────────────────────────────────────────────────────────────────────
# Capture
# ─────────────────────────────────────────────────────────────────────────────

def _capture(url: str) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"error": "playwright not installed — run: pip install playwright && playwright install chromium"}

    result = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        page = browser.new_page(viewport={"width": 1280, "height": 900})

        requests_made = []
        page.on("request", lambda req: requests_made.append(req.url))

        try:
            page.goto(url, timeout=30000, wait_until="networkidle")
        except Exception as exc:
            logger.warning("Page load timeout/warning for %s: %s", url, exc)

        result["html"]          = page.content()
        result["screenshot"]    = page.screenshot(full_page=True)
        result["title"]         = page.title()
        result["final_url"]     = page.url
        result["requests_made"] = requests_made
        browser.close()

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Analysis helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_external(html: str, page_domain: str) -> list:
    """Return external script/iframe/resource URLs not belonging to page_domain."""
    patterns = [
        r'<script[^>]+src=["\']([^"\']+)["\']',
        r'<iframe[^>]+src=["\']([^"\']+)["\']',
        r'<link[^>]+href=["\']([^"\']+)["\']',
        r'<img[^>]+src=["\']([^"\']+)["\']',
    ]
    seen, found = set(), []
    for pat in patterns:
        for m in re.finditer(pat, html, re.IGNORECASE):
            raw = m.group(1).strip()
            if raw.startswith("//"):
                raw = "https:" + raw
            if raw.startswith("http") and page_domain not in raw and raw not in seen:
                seen.add(raw)
                found.append(raw)
    return found


def _group_by_domain(urls: list) -> dict:
    counts = {}
    for u in urls:
        try:
            d = urlparse(u).netloc
            counts[d] = counts.get(d, 0) + 1
        except Exception:
            pass
    return counts


# ─────────────────────────────────────────────────────────────────────────────
# Wayback Machine
# ─────────────────────────────────────────────────────────────────────────────

def _submit_wayback(url: str) -> dict:
    try:
        r = requests.post(
            _WAYBACK_API,
            data={"url": url, "capture_all": "on"},
            headers={"User-Agent": "flowintel-preserve/1.0"},
            timeout=30,
            allow_redirects=True,
        )
        if r.status_code in (200, 302):
            archive_url = r.url if "web.archive.org/web/" in r.url else None
            if not archive_url:
                loc = r.headers.get("Content-Location", "")
                if loc:
                    archive_url = f"https://web.archive.org{loc}"
            return {"url": archive_url or f"https://web.archive.org/save/{url}"}
        return {"error": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# File persistence
# ─────────────────────────────────────────────────────────────────────────────

def _save_file(case_id: int, name: str, data: bytes, file_type: str,
               db_session) -> str | None:
    try:
        file_uuid = str(uuid.uuid4())
        os.makedirs(_FILE_FOLDER, exist_ok=True)
        with open(os.path.join(_FILE_FOLDER, file_uuid), "wb") as fh:
            fh.write(data)

        from app.db_class.db import File
        record = File(
            uuid=file_uuid,
            name=name,
            case_id=case_id,
            upload_date=datetime.datetime.utcnow(),
            file_size=len(data),
            file_type=file_type,
        )
        db_session.session.add(record)
        db_session.session.commit()
        return file_uuid
    except Exception as exc:
        logger.warning("File save failed: %s", exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Note formatting
# ─────────────────────────────────────────────────────────────────────────────

def _format_note(url, ts, title, final_url, html_hash, shot_hash,
                 external, all_requests, wayback,
                 shot_uuid, html_uuid) -> str:
    lines = [
        f"## Preserve: `{url}`",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Timestamp (UTC) | `{ts}` |",
        f"| Page title | {title or '—'} |",
        f"| Final URL | `{final_url}` |",
        f"| HTML SHA-256 | `{html_hash}` |",
        f"| Screenshot SHA-256 | `{shot_hash}` |",
    ]

    if shot_uuid:
        lines.append(f"| Screenshot file | `{shot_uuid}.png` (Files tab) |")
    if html_uuid:
        lines.append(f"| HTML source file | `{html_uuid}.html` (Files tab) |")

    if wayback.get("url"):
        lines.append(f"| Wayback Machine | {wayback['url']} |")
    elif wayback.get("error"):
        lines.append(f"| Wayback Machine | failed — {wayback['error']} |")

    # External scripts — most important for injection cases
    if external:
        lines += [
            f"",
            f"### External scripts / resources ({len(external)})",
            f"",
            f"⚠️ These resources are loaded from **outside** the page domain — review for injected content:",
            f"",
        ]
        for r in external[:25]:
            lines.append(f"- `{r}`")
        if len(external) > 25:
            lines.append(f"- _…{len(external) - 25} more_")

    # Network requests grouped by domain
    if all_requests:
        domains = _group_by_domain(all_requests)
        page_domain = urlparse(url).netloc
        external_domains = {d: c for d, c in domains.items() if page_domain not in d}
        if external_domains:
            lines += [
                f"",
                f"### All external domains contacted ({len(external_domains)})",
                f"",
            ]
            for d, c in sorted(external_domains.items(), key=lambda x: -x[1])[:20]:
                lines.append(f"- `{d}` — {c} request(s)")

    lines += [
        f"",
        f"_Captured by flowintel-reverify `preserve_page` module._",
    ]
    return "\n".join(lines)


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


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    payload:
      url        : URL to preserve (required)
      wayback    : bool — submit to Wayback Machine (default: true)
      save_files : bool — attach screenshot + HTML to case Files tab (default: true)
    """
    payload    = payload or {}
    url        = payload.get("url", "").strip()
    do_wayback = payload.get("wayback", True)
    save_files = payload.get("save_files", True)

    if not url:
        return {"error": "No URL provided. Pass 'url' in payload."}

    case_id = case.get("id") if isinstance(case, dict) else case.id
    ts      = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Capture page
    capture = _capture(url)
    if "error" in capture:
        return {"error": capture["error"]}

    html_bytes = capture["html"].encode("utf-8")
    shot_bytes = capture["screenshot"]
    html_hash  = _sha256(html_bytes)
    shot_hash  = _sha256(shot_bytes)
    title      = capture.get("title", "")
    final_url  = capture.get("final_url", url)
    requests_made = capture.get("requests_made", [])

    # 2. Extract external resources
    page_domain = urlparse(url).netloc
    external    = _extract_external(capture["html"], page_domain)

    # 3. Save screenshot + HTML as case files
    shot_uuid = html_uuid = None
    if save_files and db_session:
        shot_uuid = _save_file(
            case_id, f"snapshot_{case_id}.png", shot_bytes, "image/png", db_session)
        html_uuid = _save_file(
            case_id, f"source_{case_id}.html", html_bytes, "text/html", db_session)

    # 4. Wayback Machine
    wayback = _submit_wayback(url) if do_wayback else {}

    # 5. Write note
    note = _format_note(url, ts, title, final_url, html_hash, shot_hash,
                        external, requests_made, wayback, shot_uuid, html_uuid)
    if db_session:
        _write_note(case_id, note, db_session)

    return {
        "url"              : url,
        "timestamp"        : ts,
        "title"            : title,
        "final_url"        : final_url,
        "html_sha256"      : html_hash,
        "screenshot_sha256": shot_hash,
        "external_scripts" : external,
        "total_requests"   : len(requests_made),
        "wayback"          : wayback,
        "screenshot_uuid"  : shot_uuid,
        "html_uuid"        : html_uuid,
    }


def introspection():
    return {
        "name"       : "preserve_page",
        "description": module_config["description"],
        "type"       : "analyze",
        "payload"    : [
            {"name": "url",        "type": "string",  "description": "URL to preserve (required)"},
            {"name": "wayback",    "type": "boolean", "description": "Submit to Wayback Machine (default: true)"},
            {"name": "save_files", "type": "boolean", "description": "Attach screenshot + HTML to case Files tab (default: true)"},
        ],
    }


def module_config_def():
    return module_config
