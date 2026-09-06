import os
import datetime
import uuid

from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from . import reverify_tool_blueprint
from app.case.CaseCore import CaseModel
from app.case import common_core as CommonModel
from app.db_class.db import db, Case, File

UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
FILE_FOLDER = os.path.join(UPLOAD_FOLDER, "files")

def _allowed(filename):
    return True  # reverify detects format from magic bytes, not extension


@reverify_tool_blueprint.route("/", methods=["GET"])
@login_required
def index():
    return render_template("reverify_tool/index.html")


@reverify_tool_blueprint.route("/analyze", methods=["POST"])
@login_required
def analyze():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    depth        = request.form.get("depth", "quick")
    push_to_misp = request.form.get("push_to_misp") == "true"
    uploaded_file = request.files.get("binary")

    # ── Validation ────────────────────────────────────────────────────────────
    if not title:
        flash("Case title is required.", "danger")
        return redirect(url_for("reverify_tool.index"))

    if not uploaded_file or not uploaded_file.filename:
        flash("Please upload a binary file.", "danger")
        return redirect(url_for("reverify_tool.index"))

    from werkzeug.utils import secure_filename
    filename = secure_filename(uploaded_file.filename)
    if not _allowed(filename):
        flash(f"File type not allowed: {filename}", "danger")
        return redirect(url_for("reverify_tool.index"))

    # ── 1. Create case ────────────────────────────────────────────────────────
    form_dict = {
        "title": title,
        "description": description or f"Binary analysis — {filename}",
        "deadline_date": "",
        "deadline_time": "",
        "time_required": "",
        "is_private": False,
        "privileged_case": False,
        "ticket_id": "",
        "hedgedoc_url": "",
        "tags": [],
        "clusters": [],
        "custom_tags": [],
    }
    case = CaseModel.create_case(form_dict, current_user)
    if not case:
        flash("Failed to create case.", "danger")
        return redirect(url_for("reverify_tool.index"))

    # ── 2. Save uploaded file ─────────────────────────────────────────────────
    os.makedirs(FILE_FOLDER, exist_ok=True)
    file_uuid = str(uuid.uuid4())
    file_data = uploaded_file.read()
    file_path = os.path.join(FILE_FOLDER, file_uuid)

    with open(file_path, "wb") as fh:
        fh.write(file_data)

    file_type = uploaded_file.content_type or (
        filename.rsplit(".", 1)[-1] if "." in filename else "application/octet-stream"
    )
    f = File(
        name=filename,
        case_id=case.id,
        uuid=file_uuid,
        upload_date=datetime.datetime.now(tz=datetime.timezone.utc),
        file_size=len(file_data),
        file_type=file_type,
    )
    db.session.add(f)
    db.session.commit()
    CommonModel.save_history(case.uuid, current_user, f"File '{filename}' uploaded for reverify analysis")

    # ── 3. Run reverify analysis ──────────────────────────────────────────────
    try:
        from app.utils.utils import get_modules_list
        modules, _ = get_modules_list()
        handler = modules.get("reverify_binary")
        if handler:
            case_dict = case.to_json()
            case_dict["tasks"] = []
            result = handler.handler(
                instance={},
                case=case_dict,
                user={"id": current_user.id, "email": current_user.email},
                case_model=CaseModel,
                db_session=db,
                payload={"file_path": file_path, "depth": depth,
                         "display_name": filename, "push_to_misp": push_to_misp},
            )
            if result and "message" in result and "findings" not in result:
                flash(f"Reverify error: {result['message']}", "warning")
            else:
                msg = "Analysis complete — results saved to case Notes."
                if push_to_misp:
                    misp_url = result.get("misp_event_url")
                    misp_err = result.get("misp_error")
                    if misp_url:
                        msg += f" MISP event: {misp_url}"
                    elif misp_err:
                        msg += f" MISP push failed: {misp_err}"
                flash(msg, "success")
        else:
            flash("reverify_binary module not found.", "warning")
    except Exception as exc:
        flash(f"Analysis error: {exc}", "warning")

    return redirect(f"/case/{case.id}")


@reverify_tool_blueprint.route("/push_misp", methods=["GET"])
@login_required
def push_misp_form():
    cases = Case.query.order_by(Case.id.desc()).limit(50).all()
    cases_with_files = []
    for c in cases:
        files = File.query.filter_by(case_id=c.id).all()
        if files:
            cases_with_files.append({"case": c, "files": files})
    return render_template("reverify_tool/push_misp.html", cases=cases_with_files)


@reverify_tool_blueprint.route("/push_misp", methods=["POST"])
@login_required
def push_misp_submit():
    case_id = request.form.get("case_id", type=int)
    file_uuid = request.form.get("file_uuid", "").strip()
    depth = request.form.get("depth", "quick")

    if not case_id or not file_uuid:
        flash("Please select a case and file.", "danger")
        return redirect(url_for("reverify_tool.push_misp_form"))

    case_orm = Case.query.get(case_id)
    file_orm = File.query.filter_by(uuid=file_uuid, case_id=case_id).first()
    if not case_orm or not file_orm:
        flash("Case or file not found.", "danger")
        return redirect(url_for("reverify_tool.push_misp_form"))

    file_path = os.path.join(FILE_FOLDER, file_uuid)
    if not os.path.exists(file_path):
        flash(f"File not found on disk: {file_uuid}", "danger")
        return redirect(url_for("reverify_tool.push_misp_form"))

    try:
        from app.utils.utils import get_modules_list
        modules, _ = get_modules_list()
        handler = modules.get("reverify_binary")
        if not handler:
            flash("reverify_binary module not found.", "warning")
            return redirect(url_for("reverify_tool.push_misp_form"))

        case_dict = case_orm.to_json()
        case_dict["tasks"] = []
        result = handler.handler(
            instance={},
            case=case_dict,
            user={"id": current_user.id, "email": current_user.email},
            case_model=CaseModel,
            db_session=db,
            payload={
                "file_path": file_path,
                "depth": depth,
                "display_name": file_orm.name,
                "push_to_misp": True,
            },
        )
        misp_url = result.get("misp_event_url") if result else None
        misp_err = result.get("misp_error") if result else "unknown error"
        if misp_url:
            flash(f"MISP event created: {misp_url}", "success")
        else:
            flash(f"MISP push failed: {misp_err}", "danger")
    except Exception as exc:
        flash(f"Error: {exc}", "danger")

    return redirect(f"/case/{case_id}")


import re as _re


def _extract_observables(findings: dict, depth: str) -> list:
    """Return a deduplicated list of enrichable values from reverify findings."""
    seen, obs = set(), []

    def add(v):
        v = v.strip()
        if v and v not in seen:
            seen.add(v); obs.append(v)

    for h in (findings.get("md5"), findings.get("sha256")):
        if h:
            add(h)

    candidates = findings.get("suspicious_strings") if depth == "full" else findings.get("strings", [])
    ip_re     = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_re    = _re.compile(r'https?://[^\s\'"<>]{4,}')
    domain_re = _re.compile(
        r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|info|biz|xyz|top|club|online|site)\b',
        _re.I)

    for entry in (candidates or []):
        val = entry.get("value", "") if isinstance(entry, dict) else str(entry)
        for m in url_re.findall(val):   add(m)
        for m in ip_re.findall(val):    add(m)
        for m in domain_re.findall(val):
            if not _re.match(r'^\d+\.\d+\.\d+\.\d+$', m): add(m)

    return obs


@reverify_tool_blueprint.route("/run_pipeline", methods=["POST"])
@login_required
def run_pipeline():
    case_id   = request.form.get("case_id", type=int)
    file_uuid = request.form.get("file_uuid", "").strip()
    depth     = request.form.get("depth", "quick")

    if not case_id or not file_uuid:
        flash("Please select a case and file.", "danger")
        return redirect(url_for("reverify_tool.push_misp_form"))

    case_orm = Case.query.get(case_id)
    file_orm = File.query.filter_by(uuid=file_uuid, case_id=case_id).first()
    if not case_orm or not file_orm:
        flash("Case or file not found.", "danger")
        return redirect(url_for("reverify_tool.push_misp_form"))

    file_path = os.path.join(FILE_FOLDER, file_uuid)
    if not os.path.exists(file_path):
        flash(f"File not found on disk: {file_uuid}", "danger")
        return redirect(url_for("reverify_tool.push_misp_form"))

    try:
        from app.utils.utils import get_modules_list
        modules, _ = get_modules_list()

        user_dict = {"id": current_user.id, "email": current_user.email}
        case_dict = case_orm.to_json(); case_dict["tasks"] = []
        steps_ok, steps_fail = [], []

        # Step 1: reverify_binary
        handler = modules.get("reverify_binary")
        if not handler:
            flash("reverify_binary module not found.", "warning")
            return redirect(url_for("reverify_tool.push_misp_form"))

        rb_result = handler.handler(
            instance={}, case=case_dict, user=user_dict,
            case_model=CaseModel, db_session=db,
            payload={"file_path": file_path, "depth": depth,
                     "display_name": file_orm.name, "push_to_misp": True},
        )
        misp_url = rb_result.get("misp_event_url") if rb_result else None
        steps_ok.append(f"reverify_binary — MISP event: {misp_url}" if misp_url
                        else "reverify_binary — analysis written to Notes")

        # Step 2: enrich_observable
        eo = modules.get("enrich_observable")
        if eo and rb_result:
            observables = _extract_observables(rb_result.get("findings", {}), depth)
            enriched, failed = 0, 0
            for val in observables:
                try:
                    eo.handler(instance={}, case=case_dict, user=user_dict,
                               case_model=CaseModel, db_session=db,
                               payload={"value": val})
                    enriched += 1
                except Exception:
                    failed += 1
            steps_ok.append(f"enrich_observable — {enriched} enriched" +
                            (f", {failed} failed" if failed else ""))
        else:
            steps_fail.append("enrich_observable — module not found")

        # Step 3: correlate_observables
        co = modules.get("correlate_observables")
        if co:
            co_result = co.handler(instance={}, case=case_dict, user=user_dict,
                                   case_model=CaseModel, db_session=db, payload={})
            hits = co_result.get("matches_found", 0) if co_result else 0
            steps_ok.append(f"correlate_observables — {hits} case overlap(s)")
        else:
            steps_fail.append("correlate_observables — module not found")

        # Step 4: suggest_assessment
        sa = modules.get("suggest_assessment")
        if sa:
            sa_result = sa.handler(instance={}, case=case_dict, user=user_dict,
                                   case_model=CaseModel, db_session=db, payload={})
            decision = sa_result.get("decision", "?") if sa_result else "?"
            steps_ok.append(f"suggest_assessment → {decision}")
        else:
            steps_fail.append("suggest_assessment — module not found")

        for msg in steps_ok:
            flash(f"✓ {msg}", "success")
        for msg in steps_fail:
            flash(f"✗ {msg}", "warning")

    except Exception as exc:
        flash(f"Pipeline error: {exc}", "danger")

    return redirect(f"/case/{case_id}")
