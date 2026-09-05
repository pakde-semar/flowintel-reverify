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

ALLOWED_EXTENSIONS = {
    "exe", "dll", "so", "elf", "bin", "out", "o",
    "sys", "drv", "scr", "com", "bat", "sh",
    "apk", "dex", "jar", "pyc", "pyd",
}


def _allowed(filename):
    if "." not in filename:
        return True  # binary without extension — OK
    ext = filename.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS


@reverify_tool_blueprint.route("/", methods=["GET"])
@login_required
def index():
    return render_template("reverify_tool/index.html")


@reverify_tool_blueprint.route("/analyze", methods=["POST"])
@login_required
def analyze():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    depth = request.form.get("depth", "quick")
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

    # add current user to case
    CommonModel.add_user_case(case, current_user, current_user)

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
                payload={"file_path": file_path, "depth": depth},
            )
            if result and "message" in result and "findings" not in result:
                flash(f"Reverify error: {result['message']}", "warning")
            else:
                flash("Analysis complete — results saved to case Notes.", "success")
        else:
            flash("reverify_binary module not found.", "warning")
    except Exception as exc:
        flash(f"Analysis error: {exc}", "warning")

    return redirect(f"/case/{case.id}")
