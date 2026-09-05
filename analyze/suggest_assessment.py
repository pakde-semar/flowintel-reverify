"""
Flowintel module: suggest_assessment
Category: analyze

Rule-based assessment suggestion. Reads the current case notes, applies a
scored signal table, and writes a suggestion note recommending one of:
  confirmed | needs-ghidra | needs-angr | uncertain

Does NOT record a decision — run assess_case to do that.
"""

import re
import logging
import datetime as _dt

logger = logging.getLogger(__name__)

module_config = {
    "connector": "none",
    "case_task": "case",
    "description": (
        "Rule-based assessment suggestion: scans case notes for signals "
        "(high entropy, injection APIs, KNOWN MALICIOUS, vulnerability keywords) "
        "and suggests confirmed / needs-ghidra / needs-angr with scored reasoning."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Signal table: (key, regex, weight, direction, description)
# weight > 0  → contributes to `direction`
# weight < 0  → contributes to `confirmed`
# ─────────────────────────────────────────────────────────────────────────────

_SIGNALS = [
    ("high_entropy_8",    r"entropy[:\s]+[89]\.\d",
     3, "needs-ghidra", "Section entropy > 8.0 (likely packed/encrypted)"),

    ("high_entropy_7",    r"entropy[:\s]+7\.[5-9]",
     2, "needs-ghidra", "Section entropy 7.5–7.9 (possibly packed)"),

    ("process_injection", r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread",
     3, "needs-ghidra", "Process injection APIs (VirtualAlloc, CreateRemoteThread)"),

    ("low_level_alloc",   r"VirtualProtect|NtAllocateVirtualMemory",
     1, "needs-ghidra", "Low-level memory allocation APIs"),

    ("crypto_imports",    r"CryptDecrypt|CryptImportKey|CryptGenRandom|BCryptDecrypt",
     2, "needs-ghidra", "In-memory crypto APIs (payload may be encrypted)"),

    ("known_malicious",   r"KNOWN MALICIOUS",
     3, "needs-ghidra", "Hash flagged KnownMalicious in CIRCL hashlookup"),

    ("no_strings",        r"no printable strings|0 strings",
     2, "needs-ghidra", "No extractable strings (obfuscated binary)"),

    ("packer_sections",   r"UPX0|UPX1|\.packed|\.aPLib",
     2, "needs-ghidra", "Packer section names detected (UPX, aPLib)"),

    ("correlation_found", r"Found overlap in \*\*\d+\*\* case",
     1, "needs-ghidra", "Correlation with other cases — possible campaign"),

    ("vuln_overflow",     r"buffer overflow|stack overflow|heap overflow|off.by.one",
     4, "needs-angr",   "Buffer/heap overflow or off-by-one (post-Ghidra finding)"),

    ("vuln_uaf",          r"use.after.free|UAF",
     4, "needs-angr",   "Use-after-free vulnerability"),

    ("vuln_format",       r"format string",
     3, "needs-angr",   "Format string vulnerability"),

    ("rop_chain",         r"ROP chain|return.oriented|gadget",
     3, "needs-angr",   "ROP chain / return-oriented programming gadgets"),

    ("cve_reference",     r"CVE-\d{4}-\d+",
     2, "needs-angr",   "CVE reference found — known vulnerability"),

    ("nsrl_clean",        r"trust: 100|NSRL",
     -3, "confirmed",   "Hash known clean (NSRL / trust 100)"),

    ("no_iocs",           r"No IOCs|0 IOCs",
     -1, "confirmed",   "No IOCs extracted"),
]

_RE_FLAGS = re.IGNORECASE


# ─────────────────────────────────────────────────────────────────────────────
# Scoring engine
# ─────────────────────────────────────────────────────────────────────────────

def _score_notes(notes):
    ghidra_score    = 0
    angr_score      = 0
    confirmed_score = 0
    fired = []

    for key, pattern, weight, direction, description in _SIGNALS:
        if re.search(pattern, notes, _RE_FLAGS):
            fired.append({"key": key, "weight": weight, "description": description, "direction": direction})
            if direction == "needs-ghidra":
                ghidra_score += weight
            elif direction == "needs-angr":
                angr_score += weight
            else:
                confirmed_score += weight

    return ghidra_score, angr_score, confirmed_score, fired


def _decide(ghidra_score, angr_score, confirmed_score):
    if angr_score >= 4:
        return "needs-angr"
    if ghidra_score >= 3:
        return "needs-ghidra"
    if confirmed_score < 0 and ghidra_score < 3:
        return "confirmed"
    return "uncertain"


# ─────────────────────────────────────────────────────────────────────────────
# Reasoning templates
# ─────────────────────────────────────────────────────────────────────────────

_REASONING = {
    "needs-angr": (
        "Vulnerability keywords detected (post-Ghidra finding). "
        "Symbolic execution via angr is required to confirm exploitability and bound the reachable paths."
    ),
    "needs-ghidra": (
        "Automated triage found obfuscation or evasion signals that prevent IOC recovery from static "
        "analysis alone. Manual Ghidra decompilation is required to understand the payload."
    ),
    "confirmed": (
        "No obfuscation or evasion signals detected. Known-clean hash or no suspicious indicators. "
        "Findings from automated triage are sufficient to validate the IOCs."
    ),
    "uncertain": (
        "No strong signals in either direction. Review the enrichment and correlation notes manually "
        "before recording a decision."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Note formatter
# ─────────────────────────────────────────────────────────────────────────────

def _format_note(case_id, decision, ghidra_score, angr_score, confirmed_score, fired):
    lines = [f"## Assessment Suggestion: Case #{case_id}", ""]

    if decision == "uncertain":
        lines += [
            "**Suggested decision: uncertain — manual review required** (no strong signals)",
            "",
            _REASONING["uncertain"],
        ]
    else:
        lines += [
            f"**Suggested decision: {decision}** "
            f"(ghidra score: {ghidra_score}, angr score: {angr_score}, confirmed score: {confirmed_score})",
            "",
        ]

        if fired:
            lines += [
                "**Signals detected:**",
                "| Signal | Weight | Description |",
                "|--------|--------|-------------|",
            ]
            for s in sorted(fired, key=lambda x: abs(x["weight"]), reverse=True):
                sign = "+" if s["weight"] > 0 else ""
                lines.append(f"| {s['key']} | {sign}{s['weight']} | {s['description']} |")
            lines.append("")

        n = len(fired)
        direction_label = decision.replace("-", " ")
        lines += [
            f"**Reasoning:** {n} signal(s) detected. {_REASONING[decision]}",
            "",
            f"_Run `assess_case` with `decision: {decision}` to record this decision._",
        ]

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Note writer
# ─────────────────────────────────────────────────────────────────────────────

def _write_note(case_id, note_text, db_session):
    try:
        from app.case import common_core as _CC
        case_orm = _CC.get_case(case_id)
        if case_orm:
            case_orm.notes = (case_orm.notes or "") + "\n\n" + note_text
            case_orm.last_modif = _dt.datetime.now()
            db_session.session.commit()
    except Exception as exc:
        logger.warning("Could not write suggestion note: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(instance, case, user, case_model=None, db_session=None, payload=None):
    case_id = case.get("id") if isinstance(case, dict) else case.id

    try:
        from app.case import common_core as _CC
        case_orm = _CC.get_case(case_id)
        notes = case_orm.notes if case_orm else ""
    except Exception as exc:
        return {"error": f"Could not read case notes: {exc}"}

    if not notes or not notes.strip():
        return {
            "case_id" : case_id,
            "decision": "uncertain",
            "message" : "No case notes found. Run reverify_binary, enrich_observable, or correlate_observables first.",
        }

    ghidra_score, angr_score, confirmed_score, fired = _score_notes(notes)
    decision = _decide(ghidra_score, angr_score, confirmed_score)

    note = _format_note(case_id, decision, ghidra_score, angr_score, confirmed_score, fired)

    if db_session:
        _write_note(case_id, note, db_session)

    return {
        "case_id" : case_id,
        "decision": decision,
        "scores"  : {
            "ghidra"   : ghidra_score,
            "angr"     : angr_score,
            "confirmed": confirmed_score,
        },
        "signals" : [
            {"key": s["key"], "weight": s["weight"], "description": s["description"]}
            for s in fired
        ],
    }


def introspection():
    return module_config
