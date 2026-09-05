"""
Flowintel module: assess_case
Category: analyze

Analyst assessment gate. Records the analyst's decision on the current case,
applies a custom tag, updates case status, and writes a structured audit note.

Decisions:
  confirmed      → publishes the MISP draft event (if one exists), applies Approved status
  needs-ghidra   → insufficient evidence; escalate to deep binary analysis
  needs-angr     → vulnerability confirmed by Ghidra; need proof of exploitability
  false-positive → findings dismissed; no further action

Payload:
  decision : str  — one of: confirmed | needs-ghidra | needs-angr | false-positive
  rationale: str  — optional analyst note explaining the decision
"""

import re
import logging
import datetime as _dt

logger = logging.getLogger(__name__)

module_config = {
    "connector": "none",
    "case_task": "case",
    "description": (
        "Analyst assessment gate: records decision (confirmed / needs-ghidra / "
        "needs-angr / false-positive), applies custom tag, updates case status, "
        "and writes a structured audit note."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Decision → tag + status mapping
# ─────────────────────────────────────────────────────────────────────────────

_DECISIONS = {
    "confirmed": {
        "tag_name"  : "confirmed",
        "tag_color" : "#28a745",
        "tag_icon"  : "check-circle",
        "status_id" : 8,           # Approved
        "label"     : "Confirmed",
        "note_header": "CONFIRMED ✓ — IOCs verified. MISP event will be published.",
    },
    "needs-ghidra": {
        "tag_name"  : "needs-ghidra",
        "tag_color" : "#fd7e14",
        "tag_icon"  : "search",
        "status_id" : 9,           # Request Review
        "label"     : "Needs Ghidra",
        "note_header": "ESCALATED → Ghidra — insufficient evidence from automated triage.",
    },
    "needs-angr": {
        "tag_name"  : "needs-angr",
        "tag_color" : "#dc3545",
        "tag_icon"  : "bug",
        "status_id" : 9,           # Request Review
        "label"     : "Needs angr",
        "note_header": "ESCALATED → angr — Ghidra confirmed a vulnerability; proof of exploitability required.",
    },
    "false-positive": {
        "tag_name"  : "false-positive",
        "tag_color" : "#6c757d",
        "tag_icon"  : "times-circle",
        "status_id" : 5,           # Rejected
        "label"     : "False Positive",
        "note_header": "FALSE POSITIVE — findings dismissed; no further action.",
    },
}

_ASSESSMENT_TAG_NAMES = {d["tag_name"] for d in _DECISIONS.values()}


# ─────────────────────────────────────────────────────────────────────────────
# Tag helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_tag(tag_name: str, color: str, icon: str, db_session) -> int | None:
    """Return id of the named custom tag, creating it if it doesn't exist."""
    try:
        from app.db_class.db import Custom_Tags
        import uuid as _uuid
        tag = Custom_Tags.query.filter_by(name=tag_name).first()
        if tag:
            return tag.id
        tag = Custom_Tags(
            name=tag_name,
            color=color,
            icon=icon,
            is_active=True,
            uuid=str(_uuid.uuid4()),
        )
        db_session.session.add(tag)
        db_session.session.commit()
        return tag.id
    except Exception as exc:
        logger.warning("Could not ensure custom tag %r: %s", tag_name, exc)
        return None


def _clear_assessment_tags(case_id: int, db_session):
    """Remove all assessment custom tags from the case."""
    try:
        from app.db_class.db import Custom_Tags, Case_Custom_Tags
        assessment_tags = Custom_Tags.query.filter(
            Custom_Tags.name.in_(_ASSESSMENT_TAG_NAMES)
        ).all()
        tag_ids = {t.id for t in assessment_tags}
        if not tag_ids:
            return
        existing = Case_Custom_Tags.query.filter(
            Case_Custom_Tags.case_id == case_id,
            Case_Custom_Tags.custom_tag_id.in_(tag_ids),
        ).all()
        for row in existing:
            db_session.session.delete(row)
        db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not clear assessment tags for case %s: %s", case_id, exc)


def _attach_tag(case_id: int, tag_id: int, db_session):
    try:
        from app.db_class.db import Case_Custom_Tags
        row = Case_Custom_Tags(case_id=case_id, custom_tag_id=tag_id)
        db_session.session.add(row)
        db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not attach tag %s to case %s: %s", tag_id, case_id, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Status + note helpers
# ─────────────────────────────────────────────────────────────────────────────

def _update_status(case_orm, status_id: int, db_session):
    try:
        case_orm.status_id = status_id
        case_orm.last_modif = _dt.datetime.now()
        db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not update case status: %s", exc)


def _write_note(case_orm, note_text: str, db_session):
    try:
        case_orm.notes = (case_orm.notes or "") + "\n\n" + note_text
        case_orm.last_modif = _dt.datetime.now()
        db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not write assessment note: %s", exc)


def _format_note(decision_key: str, meta: dict, rationale: str,
                 analyst_name: str, case_id: int,
                 misp_result: dict = None) -> str:
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"## Assessment: Case #{case_id}",
        f"",
        f"**{meta['note_header']}**",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Decision | {meta['label']} |",
        f"| Analyst  | {analyst_name} |",
        f"| Time     | {ts} |",
    ]
    if rationale:
        lines += [
            f"",
            f"**Rationale:**",
            f"> {rationale}",
        ]
    if decision_key == "confirmed":
        if misp_result and misp_result.get("published"):
            url = misp_result["event_url"]
            lines += [
                f"",
                f"**MISP event published ✓** — [{url}]({url})",
            ]
        elif misp_result and not misp_result.get("published"):
            lines += [
                f"",
                f"_MISP publish: {misp_result.get('error', 'unknown error')}_",
            ]
        lines += [
            f"",
            f"_Next step: review IOCs in MISP and distribute as needed._",
        ]
    elif decision_key == "needs-ghidra":
        lines += [
            f"",
            f"_Next step: open binary in Ghidra for deep decompilation and flow analysis._",
        ]
    elif decision_key == "needs-angr":
        lines += [
            f"",
            f"_Next step: run angr symbolic execution to confirm exploitability and generate PoC._",
        ]
    elif decision_key == "false-positive":
        lines += [
            f"",
            f"_No further action required on this case._",
        ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# MISP publish (Opsi B — publish draft event when decision = confirmed)
# ─────────────────────────────────────────────────────────────────────────────

_RE_MISP_EVENT_URL = re.compile(
    r'https?://[^\s\]]+/events/view/(\d+)'
)

def _get_misp_credentials(db_session):
    """Return (PyMISP, base_url) from the first available connector instance."""
    try:
        from pymisp import PyMISP
        from app.db_class.db import Connector_Instance, User_Connector_Instance
        import warnings
        warnings.filterwarnings("ignore", message=".*InsecureRequestWarning.*")

        inst = Connector_Instance.query.first()
        if not inst:
            return None, None

        api_key = inst.global_api_key
        if not api_key:
            ui = User_Connector_Instance.query.filter_by(instance_id=inst.id).first()
            api_key = ui.api_key if ui else None
        if not api_key:
            return None, None

        misp = PyMISP(inst.url, api_key, ssl=False)
        return misp, inst.url
    except Exception as exc:
        logger.warning("Could not connect to MISP: %s", exc)
        return None, None


def _get_misp_event_id(case_id: int, db_session):
    """
    Return MISP event identifier (UUID or numeric ID) for this case.
    First checks Case_Connector_Instance (MISP-sync path).
    Falls back to extracting the event URL from case Notes.
    """
    try:
        from app.db_class.db import Case_Connector_Instance
        cci = Case_Connector_Instance.query.filter_by(case_id=case_id).first()
        if cci and cci.identifier:
            return cci.identifier
    except Exception:
        pass

    # Fallback: extract from Notes
    try:
        from app.case import common_core as _CC
        case_orm = _CC.get_case(case_id)
        notes = case_orm.notes if case_orm else ""
        m = _RE_MISP_EVENT_URL.search(notes or "")
        if m:
            return int(m.group(1))  # numeric event ID
    except Exception:
        pass

    return None


def _publish_misp_event(case_id: int, db_session) -> dict:
    """
    Publish the MISP draft event linked to this case.
    Returns {"published": True, "event_url": ...}
    or      {"published": False, "error": ...}
    """
    misp, base_url = _get_misp_credentials(db_session)
    if not misp:
        return {"published": False, "error": "No MISP connector configured"}

    event_id = _get_misp_event_id(case_id, db_session)
    if not event_id:
        return {"published": False, "error": "No MISP event linked to this case — run reverify_binary with push_to_misp first"}

    try:
        result = misp.publish(event_id)
        if isinstance(result, dict) and result.get("errors"):
            return {"published": False, "error": str(result["errors"])}
        # Build view URL — if event_id is numeric use directly, else fetch numeric id
        if isinstance(event_id, int):
            event_url = f"{base_url}/events/view/{event_id}"
        else:
            ev = misp.get_event(event_id, pythonify=True)
            event_url = f"{base_url}/events/view/{ev.id}" if ev else base_url
        return {"published": True, "event_url": event_url}
    except Exception as exc:
        return {"published": False, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    payload:
      decision : str  — confirmed | needs-ghidra | needs-angr | false-positive
      rationale: str  — optional analyst note
    """
    payload = payload or {}
    decision_key = payload.get("decision", "").strip().lower()

    if decision_key not in _DECISIONS:
        return {
            "error": (
                f"Invalid decision {decision_key!r}. "
                f"Must be one of: {', '.join(_DECISIONS)}"
            )
        }

    if not db_session:
        return {"error": "db_session required"}

    meta      = _DECISIONS[decision_key]
    rationale = payload.get("rationale", "").strip()
    case_id   = case.get("id") if isinstance(case, dict) else case.id

    analyst_name = "unknown"
    try:
        analyst_name = user.email if hasattr(user, "email") else str(user)
    except Exception:
        pass

    # Load case ORM object
    try:
        from app.case import common_core as _CC
        case_orm = _CC.get_case(case_id)
        if not case_orm:
            return {"error": f"Case #{case_id} not found"}
    except Exception as exc:
        return {"error": f"Could not load case: {exc}"}

    # 1. Ensure the tag exists (create if new)
    tag_id = _ensure_tag(meta["tag_name"], meta["tag_color"], meta["tag_icon"], db_session)

    # 2. Remove any previous assessment tags
    _clear_assessment_tags(case_id, db_session)

    # 3. Attach the new tag
    if tag_id:
        _attach_tag(case_id, tag_id, db_session)

    # 4. Update case status
    _update_status(case_orm, meta["status_id"], db_session)

    # 5. Publish MISP event if confirmed
    misp_result = None
    if decision_key == "confirmed" and db_session:
        misp_result = _publish_misp_event(case_id, db_session)

    # 6. Write structured audit note
    note = _format_note(decision_key, meta, rationale, analyst_name, case_id,
                        misp_result=misp_result)
    _write_note(case_orm, note, db_session)

    result = {
        "case_id"  : case_id,
        "decision" : decision_key,
        "label"    : meta["label"],
        "tag"      : meta["tag_name"],
        "status_id": meta["status_id"],
        "rationale": rationale,
    }
    if misp_result:
        result["misp"] = misp_result
    return result


def introspection():
    return module_config
