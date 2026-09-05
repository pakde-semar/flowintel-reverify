"""
Flowintel module: assess_case
Category: analyze

Analyst assessment gate. Records the analyst's decision on the current case,
applies a custom tag, updates case status, and writes a structured audit note.

Decisions:
  confirmed      → case is verified; IOCs ready for MISP push
  needs-ghidra   → insufficient evidence; escalate to deep binary analysis
  needs-angr     → vulnerability confirmed by Ghidra; need proof of exploitability
  false-positive → findings dismissed; no further action

Payload:
  decision : str  — one of: confirmed | needs-ghidra | needs-angr | false-positive
  rationale: str  — optional analyst note explaining the decision
"""

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
        "note_header": "CONFIRMED ✓ — IOCs verified, ready for MISP push.",
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
                 analyst_name: str, case_id: int) -> str:
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
        lines += [
            f"",
            f"_Next step: review enrichment notes, then push approved IOCs to MISP._",
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

    # 5. Write structured audit note
    note = _format_note(decision_key, meta, rationale, analyst_name, case_id)
    _write_note(case_orm, note, db_session)

    return {
        "case_id"  : case_id,
        "decision" : decision_key,
        "label"    : meta["label"],
        "tag"      : meta["tag_name"],
        "status_id": meta["status_id"],
        "rationale": rationale,
    }


def introspection():
    return module_config
