"""
Flowintel module: reverify_binary
Category: analyze

Analyzes binary files attached to a Flowintel case using Reverify.
Extracts: file type, architecture, sections, imports, strings, entry-point disassembly.
Optionally pushes structured MISP objects to the connected MISP instance.
Optionally auto-generates a YARA rule from extracted IOCs and saves it to the case note.

Payload options:
  file_path     : absolute path to binary on the server (required if no case attribute)
  depth         : "quick" | "full" (default: "quick")
                  quick = parse + strings
                  full  = parse + strings + disasm entry point + pattern scan
  push_to_misp  : true | false (default: false)
                  Push results as MISP objects to the first available MISP connector
  generate_yara : true | false (default: true)
                  Auto-generate a YARA rule from hashes + suspicious strings

Case attribute fallback:
  Looks for attributes with type "filename" or "malware-sample" in case objects/tasks.
"""

import os
import sys
import logging
import hashlib
import re
import datetime as _dt

logger = logging.getLogger(__name__)

module_config = {
    "connector": "reverify",
    "case_task": "case",
    "description": (
        "Analyze a binary file with Reverify — anti-hallucination RE toolkit. "
        "Extracts file type, architecture, sections, imports/exports, strings, "
        "and entry-point disassembly. Results are returned to the case as structured findings "
        "and optionally pushed to MISP as file/pe/elf objects."
    ),
}

# ── Reverify import ──────────────────────────────────────────────────────────
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
# Analysis helpers
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

    # Hashes
    md5    = hashlib.md5(raw).hexdigest()
    sha1   = hashlib.sha1(raw).hexdigest()
    sha256 = hashlib.sha256(raw).hexdigest()

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
        "md5"         : md5,
        "sha1"        : sha1,
        "sha256"      : sha256,
    }


def _analyze_full(binary_path: str, base_info: dict) -> dict:
    """Add disassembly of entry point + suspicious string heuristics."""
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
# YARA rule generator
# ─────────────────────────────────────────────────────────────────────────────

def _generate_yara_rule(findings: dict, display_name: str) -> str:
    """
    Generate a YARA rule from Reverify findings.

    Uses:
      - MD5 + SHA256 hashes (via YARA 'hash' module) for exact file matching
      - Suspicious strings (URLs, IPs, domains, registry keys, patterns) for family hunting

    The generated rule matches on hash OR any suspicious string, so it catches
    both the exact sample and potential variants that share behavioral indicators.
    """
    # Sanitize into a valid YARA rule identifier
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', display_name.replace('.', '_'))
    if not rule_name or rule_name[0].isdigit():
        rule_name = 'sample_' + rule_name
    rule_name = rule_name or 'ReverifyRule'

    md5    = findings.get('md5', '')
    sha256 = findings.get('sha256', '')
    date   = _dt.date.today().isoformat()

    lines = [
        'import "hash"',
        '',
        f'rule {rule_name} {{',
        '    meta:',
        f'        description = "Auto-generated by flowintel-reverify from {display_name}"',
        f'        generated_by = "flowintel-reverify"',
        f'        date = "{date}"',
    ]
    if md5:
        lines.append(f'        hash_md5 = "{md5}"')
    if sha256:
        lines.append(f'        hash_sha256 = "{sha256}"')

    # Build string patterns from suspicious strings (full mode) or all strings (quick mode)
    candidates = findings.get('suspicious_strings') or findings.get('strings') or []
    str_vars   = []
    seen       = set()

    for s in candidates[:30]:
        val = s.get('value', '').strip()
        # Skip too-short or duplicate values
        if not val or len(val) < 5 or val in seen:
            continue
        # Skip binary/unprintable content
        if not all(0x20 <= ord(c) < 0x7f for c in val):
            continue
        seen.add(val)
        escaped = val.replace('\\', '\\\\').replace('"', '\\"')
        var     = f'$s{len(str_vars)}'
        offset  = s.get('offset', '?')
        str_vars.append((var, escaped, offset))

    # strings section (only if we have something)
    if str_vars:
        lines += ['', '    strings:']
        for var, escaped, offset in str_vars:
            lines.append(f'        {var} = "{escaped}"  // offset {offset}')

    # condition section
    lines += ['', '    condition:']
    cond_parts = []
    if md5:
        cond_parts.append(f'hash.md5(0, filesize) == "{md5}"')
    if sha256:
        cond_parts.append(f'hash.sha256(0, filesize) == "{sha256}"')
    if str_vars:
        cond_parts.append('any of ($s*)')

    if cond_parts:
        lines.append('        ' + '\n        or '.join(cond_parts))
    else:
        lines.append('        true  // fallback: no strings and no hashes extracted')

    lines.append('}')
    rule_text = '\n'.join(lines)

    # Optional: validate with yara-python if available (non-fatal if missing)
    try:
        import yara as _yara
        _yara.compile(source=rule_text)
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("Generated YARA rule failed to compile: %s", exc)

    return rule_text


# ─────────────────────────────────────────────────────────────────────────────
# MISP push
# ─────────────────────────────────────────────────────────────────────────────

def _get_misp_credentials(db_session):
    """Return (url, api_key) from the first available MISP connector instance."""
    try:
        from app.db_class.db import Connector_Instance, User_Connector_Instance
        inst = Connector_Instance.query.first()
        if not inst:
            return None, None
        url = inst.url
        api_key = inst.global_api_key
        if not api_key:
            ui = User_Connector_Instance.query.filter_by(instance_id=inst.id).first()
            api_key = ui.api_key if ui else None
        return url, api_key
    except Exception as exc:
        logger.warning("Could not retrieve MISP credentials: %s", exc)
        return None, None


def _push_to_misp(binary_path, display_name, findings, depth, case, db_session, case_model=None):
    """
    Build MISP objects from reverify findings and push to MISP.
    Returns (misp_event_url, error_message).
    """
    try:
        from pymisp import MISPEvent, MISPObject, PyMISP
    except ImportError:
        return None, "PyMISP not available"

    url, api_key = _get_misp_credentials(db_session)
    if not url or not api_key:
        return None, "No MISP connector configured"

    try:
        misp = PyMISP(url, api_key, ssl=False)
    except Exception as exc:
        return None, f"MISP connection failed: {exc}"

    # ── Build event ──────────────────────────────────────────────────────────
    event = MISPEvent()
    case_title = case.get("title", "Binary Analysis") if isinstance(case, dict) else str(case)
    event.info         = f"[Reverify] {display_name} — {case_title}"
    event.distribution = 0   # org only
    event.threat_level_id = 2  # medium
    event.analysis     = 1   # ongoing

    file_type = findings.get("file_type", "").upper()
    arch      = findings.get("architecture", "")
    bits      = str(findings.get("bits", "64"))
    entry     = findings.get("entry_point", "unknown")

    # ── Object: file ─────────────────────────────────────────────────────────
    file_obj = MISPObject("file")
    file_obj.add_attribute("filename",     value=display_name)
    file_obj.add_attribute("size-in-bytes", value=findings["file_size"])
    file_obj.add_attribute("md5",          value=findings["md5"])
    file_obj.add_attribute("sha1",         value=findings["sha1"])
    file_obj.add_attribute("sha256",       value=findings["sha256"])
    if file_type:
        file_obj.add_attribute("mimetype", value=_mimetype_from_type(file_type, bits))
    event.add_object(file_obj)

    # ── Object: pe / elf + sections ──────────────────────────────────────────
    if "PE" in file_type:
        pe_obj = MISPObject("pe")
        pe_obj.add_attribute("type",          value="PE32+" if "64" in bits else "PE32")
        pe_obj.add_attribute("machine-type",  value=arch)
        pe_obj.add_attribute("number-sections", value=len(findings.get("sections", [])))
        if entry != "unknown":
            pe_obj.add_attribute("entrypoint-address", value=entry)
        # Imports as text blob (no dedicated attribute in pe template)
        if findings.get("imports"):
            imp_text = ", ".join(findings["imports"][:30])
            pe_obj.add_attribute("text", value=f"Imports: {imp_text}", comment="from reverify")
        event.add_object(pe_obj)

        for sec_name in findings.get("sections", []):
            sec = MISPObject("pe-section")
            sec.add_attribute("name", value=sec_name)
            event.add_object(sec)

    elif "ELF" in file_type:
        elf_obj = MISPObject("elf")
        elf_obj.add_attribute("arch", value=arch)
        if entry != "unknown":
            elf_obj.add_attribute("entrypoint-address", value=entry)
        elf_obj.add_attribute("number-sections", value=len(findings.get("sections", [])))
        event.add_object(elf_obj)

        for sec_name in findings.get("sections", []):
            sec = MISPObject("elf-section")
            sec.add_attribute("name", value=sec_name)
            event.add_object(sec)

    # ── Standalone attributes: suspicious strings (full mode) ────────────────
    if depth == "full":
        _RE_URL    = re.compile(r'https?://[^\s"\'<>]{4,}')
        _RE_IP     = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
        _RE_DOMAIN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$')

        for s in findings.get("suspicious_strings", []):
            val = s["value"].strip()
            m = _RE_URL.search(val)
            if m:
                event.add_attribute("url", value=m.group(),
                                    category="Network activity",
                                    comment=f"offset {s['offset']}")
            elif _RE_IP.match(val):
                event.add_attribute("ip-dst", value=val,
                                    category="Network activity",
                                    comment=f"offset {s['offset']}")
            elif "HKEY_" in val:
                event.add_attribute("regkey", value=val,
                                    category="Persistence mechanism",
                                    comment=f"offset {s['offset']}")
            elif _RE_DOMAIN.match(val):
                event.add_attribute("domain", value=val,
                                    category="Network activity",
                                    comment=f"offset {s['offset']}")
            else:
                event.add_attribute("pattern-in-file", value=val,
                                    category="Payload delivery",
                                    comment=f"offset {s['offset']}")

        # Disasm entry point as text attribute
        if findings.get("disasm_entry"):
            asm_lines = []
            for instr in findings["disasm_entry"][:10]:
                if "error" not in instr:
                    asm_lines.append(f"{instr['address']}  {instr['mnemonic']:<10} {instr['op_str']}")
            if asm_lines:
                event.add_attribute("text", value="\n".join(asm_lines),
                                    category="Artifacts dropped",
                                    comment="Entry point disasm (reverify)")

    # ── Push to MISP ─────────────────────────────────────────────────────────
    try:
        result = misp.add_event(event)
        if isinstance(result, dict) and "errors" in result:
            return None, str(result["errors"])
        event_id = result.get("Event", {}).get("id") if isinstance(result, dict) else None
        misp_url = f"{url}/events/view/{event_id}" if event_id else url
    except Exception as exc:
        return None, f"MISP push error: {exc}"

    # ── Sync objects & attributes back into Flowintel case MISP tab ──────────
    if event_id and case_model and db_session:
        try:
            _sync_misp_event_to_case(
                misp=misp,
                event_id=event_id,
                case=case,
                case_model=case_model,
                db_session=db_session,
                instance_url=url,
            )
        except Exception as exc:
            logger.warning("MISP→Flowintel sync failed (event still created): %s", exc)

    return misp_url, None


def _sync_misp_event_to_case(misp, event_id, case, case_model, db_session, instance_url):
    """Re-fetch created MISP event and write its objects/attributes into Flowintel's DB."""
    from app.utils import misp_object_helper
    from app.db_class.db import (
        Connector_Instance, Misp_Attribute, Misp_Attribute_Instance_Uuid
    )

    fetched = misp.get_event(event_id, pythonify=True)
    if not fetched or hasattr(fetched, "errors"):
        return

    inst = Connector_Instance.query.filter_by(url=instance_url).first()
    instance_id = inst.id if inst else 1
    case_id = case.get("id") if isinstance(case, dict) else case.id

    # Objects
    object_uuid_list = {}
    for obj in getattr(fetched, "objects", []):
        loc = misp_object_helper.create_misp_object(case_id, obj)
        object_uuid_list.update(loc)

    if object_uuid_list:
        case_model.result_misp_object_module(
            object_uuid_list, instance_id=instance_id, case_id=case_id
        )

    # Standalone attributes (event-level, not inside an object)
    standalone_attr_uuid_list = []
    for ev_attr in getattr(fetched, "attributes", []):
        if ev_attr.object_id and int(ev_attr.object_id) != 0:
            continue
        sa = Misp_Attribute(
            case_misp_object_id=None,
            case_id=case_id,
            value=str(ev_attr.value),
            type=ev_attr.type,
            object_relation="",
            comment=ev_attr.comment or "",
            ids_flag=ev_attr.to_ids or False,
            disable_correlation=getattr(ev_attr, "disable_correlation", False) or False,
        )
        db_session.session.add(sa)
        db_session.session.commit()
        standalone_attr_uuid_list.append({"attribute_id": sa.id, "uuid": ev_attr.uuid})

    if standalone_attr_uuid_list:
        case_model.result_standalone_attr_module(
            standalone_attr_uuid_list, instance_id=instance_id, case_id=case_id
        )


def _mimetype_from_type(file_type: str, bits: str) -> str:
    ft = file_type.upper()
    if "PE" in ft:
        return "application/vnd.microsoft.portable-executable"
    if "ELF" in ft:
        return "application/x-executable"
    if "MACHO" in ft or "MACH-O" in ft:
        return "application/x-mach-binary"
    return "application/octet-stream"


# ─────────────────────────────────────────────────────────────────────────────
# Flowintel note writer
# ─────────────────────────────────────────────────────────────────────────────

def _write_note_to_case(case, summary, findings, depth, case_model, db_session,
                        misp_event_url=None, yara_rule=None):
    """Append analysis results as a Markdown note to the case (direct DB write)."""
    if not db_session:
        return
    try:
        fname = findings.pop("_display_name", findings.get("file_type", "binary"))
        note_lines = [
            f"## Reverify: `{fname}` — {findings.get('file_type','?')} "
            f"{findings.get('architecture','')} {findings.get('bits','')}bit",
            "",
            f"```\n{summary}\n```",
            "",
            f"**Hashes:** MD5 `{findings.get('md5','?')}` · SHA256 `{findings.get('sha256','?')}`",
            "",
        ]
        if findings.get("imports"):
            note_lines += [
                "**Imports (top 15):** " + ", ".join(f"`{i}`" for i in findings["imports"][:15]),
                "",
            ]
        if depth == "full" and findings.get("disasm_entry"):
            note_lines.append("**Entry point disasm:**")
            note_lines.append("```asm")
            for instr in findings["disasm_entry"][:10]:
                if "error" not in instr:
                    note_lines.append(f"{instr['address']}  {instr['mnemonic']:<10} {instr['op_str']}")
            note_lines += ["```", ""]
        if depth == "full" and findings.get("suspicious_strings"):
            note_lines.append("**Suspicious strings:**")
            for s in findings["suspicious_strings"][:10]:
                note_lines.append(f"- `{s['value']}` (offset {s['offset']})")
            note_lines.append("")
        if misp_event_url:
            note_lines += [f"**MISP Event:** [{misp_event_url}]({misp_event_url})", ""]
        if yara_rule:
            note_lines += [
                "---",
                "",
                "### YARA Rule (auto-generated)",
                "",
                "```yara",
                yara_rule,
                "```",
                "",
                "_Generated from hashes and suspicious strings extracted by Reverify._",
                "_Save as `.yar` and run: `yara rule.yar /path/to/scan/`_",
                "",
            ]

        note_text = "\n".join(note_lines)
        case_id = case.get("id") if isinstance(case, dict) else case.id

        from app.case import common_core as _CommonModel
        case_orm = _CommonModel.get_case(case_id)
        if case_orm:
            case_orm.notes = (case_orm.notes or "") + "\n\n" + note_text
            case_orm.last_modif = _dt.datetime.now()
            db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not write reverify note to case: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Module entry points
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    """
    instance     : connector instance (not used — reverify runs locally)
    case         : Flowintel case dict
    user         : current user dict
    payload      : {
        "file_path"     : "/absolute/path/to/binary",   # optional
        "depth"         : "quick" | "full",              # default: quick
        "push_to_misp"  : true | false,                  # default: false
        "generate_yara" : true | false,                  # default: true
        "display_name"  : "original_filename.exe",       # optional
      }
    """
    if not _REVERIFY_OK:
        return {"message": "reverify library not available. Check REVERIFY_VENV path."}

    payload = payload or {}
    depth         = payload.get("depth", "quick")
    push_to_misp  = payload.get("push_to_misp", False)
    generate_yara = payload.get("generate_yara", True)

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

    # 3. Build text summary
    display_name = payload.get("display_name") or os.path.basename(binary_path)
    summary_lines = [
        f"File       : {display_name}  ({findings['file_size']:,} bytes)",
        f"Type       : {findings['file_type']}",
        f"Arch       : {findings['architecture']} {findings['bits']}-bit",
        f"EntryPoint : {findings['entry_point']}",
        f"Sections   : {', '.join(findings['sections'][:8]) or 'none'}",
        f"Imports    : {len(findings['imports'])} functions",
        f"Strings    : {findings['strings_total']} total",
        f"MD5        : {findings['md5']}",
        f"SHA256     : {findings['sha256']}",
    ]
    if depth == "full":
        summary_lines.append(f"Suspicious : {findings.get('suspicious_count', 0)} strings flagged")

    summary = "\n".join(summary_lines)

    # 4. Push to MISP (optional)
    misp_event_url = None
    misp_error     = None
    if push_to_misp:
        misp_event_url, misp_error = _push_to_misp(
            binary_path, display_name, findings, depth, case, db_session, case_model
        )
        if misp_error:
            logger.warning("MISP push failed: %s", misp_error)

    # 5. Generate YARA rule (optional, default: True)
    yara_rule = None
    if generate_yara:
        try:
            yara_rule = _generate_yara_rule(findings, display_name)
        except Exception as exc:
            logger.warning("YARA rule generation failed: %s", exc)

    # 6. Write Markdown note to case (includes YARA rule if generated)
    findings["_display_name"] = display_name
    _write_note_to_case(case, summary, findings, depth, case_model, db_session,
                        misp_event_url=misp_event_url, yara_rule=yara_rule)

    result = {
        "summary"     : summary,
        "depth"       : depth,
        "binary"      : display_name,
        "findings"    : findings,
    }
    if generate_yara and yara_rule:
        result["yara_rule"] = yara_rule
    if push_to_misp:
        result["misp_event_url"] = misp_event_url
        if misp_error:
            result["misp_error"] = misp_error

    return result


def introspection():
    return module_config
