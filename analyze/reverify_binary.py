"""
Flowintel module: reverify_binary
Category: analyze

Analyzes binary files attached to a Flowintel case using Reverify.
Extracts: file type, architecture, sections, imports, strings, entry-point disassembly.

Payload options:
  file_path   : absolute path to binary on the server (required if no case attribute)
  depth       : "quick" | "full" (default: "quick")
                quick = parse + strings
                full  = parse + strings + disasm entry point + pattern scan

Case attribute fallback:
  Looks for attributes with type "filename" or "malware-sample" in case objects/tasks.
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)

module_config = {
    "connector": "reverify",
    "case_task": "case",
    "description": (
        "Analyze a binary file with Reverify — anti-hallucination RE toolkit. "
        "Extracts file type, architecture, sections, imports/exports, strings, "
        "and entry-point disassembly. Results are returned to the case as structured findings."
    ),
}

# ── Reverify import (must be installed in the same Python env as Flowintel,
#    or the path below must be added to sys.path) ──────────────────────────
REVERIFY_VENV = os.environ.get("REVERIFY_VENV", "/opt/flowintel/env/lib/python3.12/site-packages")
if REVERIFY_VENV not in sys.path:
    sys.path.insert(0, REVERIFY_VENV)

try:
    from reverify.binary import parse_binary as _parse_binary
    from reverify.cli import extract_strings as _extract_strings
    from reverify.disasm import Disassembler as _Disassembler
    _REVERIFY_OK = True
except ImportError:
    _REVERIFY_OK = False
    logger.error("reverify not found. Install it at %s or set REVERIFY_VENV env var.", REVERIFY_VENV)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _find_binary_in_case(case: dict) -> str | None:
    """Return the first binary path found in case object attributes."""
    for obj in case.get("objects", []):
        for attr in obj.get("attributes", []):
            if attr.get("object_relation") in ("filename", "malware-sample", "filepath", "path"):
                val = attr.get("value", "")
                if val and os.path.isfile(val):
                    return val
    for task in case.get("tasks", []):
        for note in task.get("notes", []):
            # notes may embed a path as "path:/absolute/path"
            content = note.get("note", "") or ""
            if content.startswith("path:") and os.path.isfile(content[5:].strip()):
                return content[5:].strip()
    return None


def _safe_str(val) -> str:
    if val is None:
        return "unknown"
    return str(val)


def _analyze_quick(binary_path: str) -> dict:
    """Parse header + extract strings."""
    raw = open(binary_path, "rb").read()
    info = _parse_binary(raw)
    strings = _extract_strings(raw, min_len=5)

    sections = [s.name for s in (info.sections or []) if s.name]
    imports_raw = info.imports or {}
    imports = []
    for lib, funcs in imports_raw.items():
        imports.extend(funcs if isinstance(funcs, list) else [lib])
    imports = imports[:30]
    exports = [_safe_str(e) for e in (info.exports or [])][:20]

    strings_preview = []
    for s in (strings or [])[:50]:
        strings_preview.append({"offset": s["offset"], "encoding": s["type"], "value": s["string"]})

    return {
        "file_type"   : _safe_str(info.format),
        "architecture": _safe_str(info.arch),
        "bits"        : _safe_str(info.bits),
        "entry_point" : hex(info.entrypoint) if info.entrypoint else "unknown",
        "file_size"   : os.path.getsize(binary_path),
        "sections"    : sections,
        "imports"     : imports,
        "exports"     : exports,
        "strings"     : strings_preview,
        "strings_total": len(strings or []),
    }


def _analyze_full(binary_path: str, base_info: dict) -> dict:
    """Add disassembly of entry point + suspicious string heuristics."""
    # Disasm entry point (80 bytes)
    entry_raw = base_info.get("entry_point", "0x0")
    try:
        offset = int(entry_raw, 16)
    except (ValueError, TypeError):
        offset = 0

    disasm_result = []
    try:
        raw = open(binary_path, "rb").read()
        arch = base_info.get("architecture", "x86_64")
        bits = str(base_info.get("bits", "64"))
        disasm_arch = f"{arch}" if "64" in bits else arch.replace("_64", "")
        d = _Disassembler(disasm_arch)
        chunk = raw[offset:offset + 80]
        instrs = d.disassemble(chunk, base_address=offset)
        for instr in (instrs or [])[:20]:
            disasm_result.append({
                "address": hex(instr.address),
                "mnemonic": instr.mnemonic,
                "op_str": instr.op_str,
            })
    except Exception as exc:
        disasm_result = [{"error": str(exc)}]

    # Suspicious string heuristics
    suspicious_keywords = [
        "cmd.exe", "powershell", "http://", "https://", "base64",
        "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
        "RegOpenKey", "\\\\", "HKEY_", "socket", "connect", "bind",
        "wget", "curl", "/etc/passwd", "chmod", "crontab",
    ]
    suspicious_strings = [
        s for s in base_info.get("strings", [])
        if any(kw.lower() in s["value"].lower() for kw in suspicious_keywords)
    ]

    base_info["disasm_entry"] = disasm_result
    base_info["suspicious_strings"] = suspicious_strings
    base_info["suspicious_count"] = len(suspicious_strings)
    return base_info


# ─────────────────────────────────────────────────────────────────────────────
# Module entry points
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    instance : connector instance (not used — reverify runs locally)
    case     : Flowintel case dict
    user     : current user dict
    payload  : {
        "file_path": "/absolute/path/to/binary",   # optional
        "depth":     "quick" | "full"               # default: quick
      }
    """
    if not _REVERIFY_OK:
        return {"message": "reverify library not available. Check REVERIFY_VENV path."}

    payload = payload or {}
    depth = payload.get("depth", "quick")

    # 1. Resolve binary path
    binary_path = payload.get("file_path") or _find_binary_in_case(case)
    if not binary_path:
        return {
            "message": (
                "No binary found. Pass 'file_path' in payload, or add a case object "
                "attribute with relation 'filename'/'malware-sample'/'filepath'."
            )
        }

    if not os.path.isfile(binary_path):
        return {"message": f"File not found: {binary_path}"}

    # 2. Run analysis
    try:
        findings = _analyze_quick(binary_path)
        if depth == "full":
            findings = _analyze_full(binary_path, findings)
    except Exception as exc:
        logger.exception("reverify analysis failed for %s", binary_path)
        return {"message": f"Analysis error: {exc}"}

    # 3. Build summary for Flowintel display
    display_name = payload.get("display_name") or os.path.basename(binary_path)
    summary_lines = [
        f"File       : {display_name}  ({findings['file_size']:,} bytes)",
        f"Type       : {findings['file_type']}",
        f"Arch       : {findings['architecture']} {findings['bits']}-bit",
        f"EntryPoint : {findings['entry_point']}",
        f"Sections   : {', '.join(findings['sections'][:8]) or 'none'}",
        f"Imports    : {len(findings['imports'])} functions",
        f"Strings    : {findings['strings_total']} total",
    ]
    if depth == "full":
        summary_lines.append(f"Suspicious : {findings.get('suspicious_count', 0)} strings flagged")

    summary = "\n".join(summary_lines)

    # 4. Write results as case note (visible in Flowintel web UI)
    findings["_display_name"] = display_name
    _write_note_to_case(case, summary, findings, depth, case_model, db_session)

    return {
        "summary": summary,
        "depth": depth,
        "binary": display_name,
        "findings": findings,
    }


def _write_note_to_case(case, summary, findings, depth, case_model, db_session):
    """Append analysis results as a Markdown note to the case (direct DB write)."""
    if not db_session:
        return
    try:
        fname = findings.pop("_display_name", findings.get("file_type", "binary"))
        note_lines = [
            f"## Reverify: `{fname}` — {findings.get('file_type', '?')} {findings.get('architecture', '')} {findings.get('bits', '')}bit",
            "",
            f"```\n{summary}\n```",
            "",
        ]
        if findings.get("imports"):
            note_lines += ["**Imports (top 15):** " + ", ".join(f"`{i}`" for i in findings["imports"][:15]), ""]
        if depth == "full" and findings.get("disasm_entry"):
            note_lines.append("**Entry point disasm:**")
            note_lines.append("```asm")
            for instr in findings["disasm_entry"][:10]:
                if "error" not in instr:
                    note_lines.append(f"{instr['address']}  {instr['mnemonic']:<10} {instr['op_str']}")
            note_lines.append("```")
            note_lines.append("")
        if depth == "full" and findings.get("suspicious_strings"):
            note_lines.append("**Suspicious strings:**")
            for s in findings["suspicious_strings"][:10]:
                note_lines.append(f"- `{s['value']}` (offset {s['offset']})")
            note_lines.append("")

        note_text = "\n".join(note_lines)
        case_id = case.get("id") if isinstance(case, dict) else case.id

        # Direct DB write — bypasses save_history which needs an ORM User object
        from app.case import common_core as _CommonModel
        case_orm = _CommonModel.get_case(case_id)
        if case_orm:
            case_orm.notes = (case_orm.notes or "") + "\n\n" + note_text
            import datetime as _dt
            case_orm.last_modif = _dt.datetime.now()
            db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not write reverify note to case: %s", exc)


def introspection():
    return module_config
