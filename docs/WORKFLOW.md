# Incident Investigation Workflow Guide

End-to-end reference for all investigation paths in flowintel-reverify.
FlowIntel Case is the central investigation container — multiple evidence intake paths
converge into the same observable enrichment, correlation, assessment, and
intelligence-promotion model.

---

## Overview

```
         Mattermost             Binary / file        Web page       Log / network
              │                       │                 │                │
   /flowintel <title>           upload or curl      curl payload     curl payload
              │                       │                 │                │
              └───────────────────────┴─────────────────┴────────────────┘
                                      │
                               ┌──────▼──────┐
                               │  FLOWINTEL  │
                               │    CASE     │
                               └──────┬──────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           │                          │                          │
           ▼                          ▼                          ▼
    FILE / BINARY            WEB EVIDENCE               LOG / NETWORK
           │                          │                          │
    reverify_binary             preserve_page            ┌───────┴───────┐
           │                          │            enrich_bulk_ips  parse_auth_log
          YARA                        │                   │               │
           │                          │                   │               │
           └──────────────────────────┴───────────────────┴───────────────┘
                                      │
                              CASE FINDINGS
                             (Notes · Files)
                                      │
                            OBSERVABLE EXTRACTION
                                      │
                            enrich_observable
                            (domain / IP / URL / hash)
                                      │
                          correlate_observables
                          (IPs, hashes, ASNs — local only)
                                      │
                           suggest_assessment
                           (16 scored signals — machine recommendation)
                                      │
                         ╔════════════╧════════════╗
                         ║       ANALYST GATE      ║
                         ║      [assess_case]      ║
                         ╚════════════╤════════════╝
              ┌───────────┬───────────┴───────────┬──────────────┐
              ▼           ▼                       ▼              ▼
          confirmed  needs-ghidra            needs-angr   false-positive
              │           │                       │              │
           Approved   Req. Review             Req. Review    Rejected
              │      🔍 MM alert             🐛 MM alert
              │           │                       │
              │         Ghidra                  angr
              │        (external)             (external)
              │           └────────────┬──────────┘
              │                        │
              └────────────────┬───────┘
                               │
                         APPROVED IOC
                               │
                       MISP (publication)
                               │
                      THREAT INTELLIGENCE
```

**Three investigation intake paths:**

| Path | Evidence type | Intake module(s) |
|------|--------------|-----------------|
| FILE / BINARY | Suspicious files, malware samples | `reverify_binary` + YARA |
| WEB EVIDENCE | Defaced pages, script injection, XSS | `preserve_page` |
| LOG / NETWORK | DDoS source data, authentication logs | `enrich_bulk_ips`, `parse_auth_log` |

All three paths write their findings into the same FlowIntel case and continue through
the same enrichment → correlation → assessment → analyst decision model.

**Automation recommends. Analysts conclude.**

```
Observable  ≠ IOC              Signal       ≠ Detection
Detection   ≠ Verdict          Correlation  ≠ Attribution
YARA Match  ≠ Confirmed Malware
Machine Recommendation ≠ Analyst Assessment
```

No intelligence is published without a deliberate analyst decision at `assess_case`.

---

## Workflow A — Upload a new binary

Use when you receive a suspicious file and want to open a case immediately.

### 1. Open the upload form

Navigate to **Analyser → Reverify Binary** in the sidebar, or go to:

```
https://<your-flowintel>/reverify/
```

### 2. Fill in the form

| Field | Description |
|-------|-------------|
| **Case Title** | Short, descriptive name (e.g. `Suspicious dropper — 2026-09-05`) |
| **Description** | Source, campaign, or ticket reference |
| **Binary File** | Any file — PE, ELF, Mach-O, APK, script, raw binary |
| **Analysis Depth** | See [Depth options](#depth-options) |
| **Push to MISP** | Toggle on to create a MISP event automatically |

### 3. Submit

Click **Create Case & Analyze**. The pipeline runs in sequence:

1. New Flowintel case created
2. File saved to case
3. Stage 1: Reverify analysis
4. Stage 2: YARA rule generated from findings
5. Markdown note written to case Notes tab (includes YARA rule)
6. Stage 3 *(if Push to MISP)*: MISP event created → synced to MISP tab

### 4. Review results

**Notes tab** — Markdown summary with full findings and the generated YARA rule:

```
## Reverify: `sample.exe` — PE x86_64 64bit

File       : sample.exe  (142,312 bytes)
Type       : PE32+
Arch       : x86_64 64-bit
EntryPoint : 0x6d30
Sections   : .text, .rdata, .data, .rsrc, .reloc
Imports    : 42 functions
Strings    : 312 total
MD5        : d41d8cd98f00b204e9800998ecf8427e
SHA256     : e3b0c44298fc1c149afbf4c8996fb924...
Suspicious : 7 strings flagged

**Suspicious strings:**
- `http://malicious.example.com` (offset 16672)
- `CreateRemoteThread` (offset 33280)

---

### YARA Rule (auto-generated)

​```yara
import "hash"

rule sample_exe {
    meta:
        description = "Auto-generated by flowintel-reverify from sample.exe"
        date = "2026-09-05"
        hash_md5    = "d41d8cd98f00b204e9800998ecf8427e"
        hash_sha256 = "e3b0c44298fc1c149afbf4c8996fb924..."

    strings:
        $s0 = "http://malicious.example.com"  // offset 16672
        $s1 = "CreateRemoteThread"             // offset 33280

    condition:
        hash.md5(0, filesize) == "d41d8..."
        or hash.sha256(0, filesize) == "e3b0c..."
        or any of ($s*)
}
​```

_Save as `.yar` and run: `yara rule.yar /path/to/scan/`_
```

**MISP tab** — structured objects synced from the MISP event:

```
file        filename · md5 · sha1 · sha256 · size-in-bytes · mimetype
pe          type · machine-type · number-sections · entrypoint-address
pe-section  name  (one row per section)
```

---

## Workflow B — Push an existing case to MISP

Use when a case was already analyzed but not pushed to MISP at the time.

### 1. Open the push form

Navigate to **Analyser → Push Case to MISP**, or go to:

```
https://<your-flowintel>/reverify/push_misp
```

### 2. Select case and file

- **Case** — choose from the dropdown (cases with attached files, newest first)
- **File** — populates automatically once a case is chosen
- **Analysis Depth** — quick or full

### 3. Choose action

Two buttons are available:

| Button | What it runs |
|--------|-------------|
| **Analyze & Push to MISP** | `reverify_binary` only — re-analyzes and creates/updates the MISP event |
| **Run Full Pipeline** | `reverify_binary` → `enrich_observable` → `correlate_observables` → `suggest_assessment` in one click |

**Analyze & Push to MISP** is faster — use it when you only need to refresh the MISP event.

**Run Full Pipeline** is the recommended path when starting enrichment on a case that has not been
fully processed yet. Each step's result is shown as a flash message when the page redirects to the case.

---

## Workflow B2 — Run Full Pipeline (one-click enrichment)

Use when you want to run all automated modules on an existing case in a single browser action,
without running each module separately from the Analyser tab.

### Steps

1. Navigate to **Analyser → Push Case to MISP** (`/reverify/push_misp`)
2. Select the case and file
3. Choose **Analysis Depth** (full recommended for IOC extraction)
4. Click **Run Full Pipeline**

### What runs

| Step | Module | Notes |
|------|--------|-------|
| 1 | `reverify_binary` | Static analysis + MISP draft event created |
| 2 | `enrich_observable` | MD5 + SHA256 always enriched; IPs, domains, URLs extracted from findings (full mode) |
| 3 | `correlate_observables` | Auto-extracts from Notes, scans all other cases |
| 4 | `suggest_assessment` | Reads all Notes, outputs scored recommendation |

### Result

Each step appends a flash message:

```
✓ reverify_binary — MISP event: https://<misp>/events/view/2125
✓ enrich_observable — 3 enriched
✓ correlate_observables — 0 case overlap(s)
✓ suggest_assessment → needs-ghidra
```

The page redirects to the case. All Notes are written and ready for `assess_case`.

---

## Workflow C — Binary triage via API

For scripted pipelines or CI integration.

### Run the full pipeline on an existing case

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "reverify_binary",
    "payload": {
      "file_path": "/opt/flowintel/uploads/files/<uuid>",
      "depth": "full",
      "display_name": "sample.exe",
      "generate_yara": true,
      "push_to_misp": true
    }
  }'
```

### Response

```json
{
  "summary": "File: sample.exe (142312 bytes)\nType: PE32+\n...",
  "depth": "full",
  "binary": "sample.exe",
  "yara_rule": "import \"hash\"\n\nrule sample_exe { ... }",
  "findings": {
    "file_type": "PE32+",
    "architecture": "x86_64",
    "bits": "64",
    "entry_point": "0x6d30",
    "file_size": 142312,
    "sections": [".text", ".rdata", ".data", ".rsrc", ".reloc"],
    "imports": ["CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory"],
    "strings_total": 312,
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
    "suspicious_strings": [...],
    "suspicious_count": 7
  },
  "misp_event_url": "https://<misp>/events/view/2125"
}
```

### Disable YARA generation

```bash
-d '{ ..., "generate_yara": false }'
```

### Run without MISP push (YARA only)

```bash
-d '{ ..., "generate_yara": true, "push_to_misp": false }'
```

---

## Workflow D — Observable enrichment via API

Use after binary triage to enrich IOCs extracted from the findings — or for any standalone
observable. All enrichment is written to the case Notes tab automatically.

### Hash — CIRCL hashlookup + fuzzy match

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "enrich_observable",
    "payload": {
      "value": "f15a57d91734a2308b129a1ed4add2c487eadec9b8c2d46dbfd3d2f23b5c28d7"
    }
  }'
```

CIRCL hashlookup checks the hash against NSRL (known clean) and malshare (known malicious).
If `KnownMalicious` is set, the note flags it with ⚠️.
TLSH and ssdeep then compare the file against every other file in the local corpus.

### Domain

```bash
-d '{"module": "enrich_observable", "payload": {"value": "malicious.example.com"}}'
```

Returns: registrar, registered/expires dates, nameservers, CIRCL passive DNS history.

### IP

```bash
-d '{"module": "enrich_observable", "payload": {"value": "198.51.100.1"}}'
```

Returns: RDAP network name, country, CIDR, RIPE Stat ASN and holder.

### URL

```bash
-d '{"module": "enrich_observable", "payload": {"value": "https://malicious.example.com/stage2"}}'
```

Submits to Lookyloo (CIRCL public). Returns redirect chain, IPs contacted, screenshot and
capture links. If the public instance times out, the capture UUID and link are still saved
so the analyst can check later.

### Type auto-detection

The type is inferred automatically from the value:

| Priority | Pattern | Detected type |
|----------|---------|---------------|
| 1 | Starts with `http://` or `https://` | `url` |
| 2 | IPv4 format | `ip` |
| 3 | 32 / 40 / 64 hex chars | `hash` |
| 4 | Domain pattern | `domain` |

Pass `"type"` explicitly to override.

### Note written to case

```
## Enrichment: `malicious.example.com` (domain)

**RDAP registration:**
- Registrar: GoDaddy
- Registered: 2024-01-15T00:00:00Z
- Expires: 2025-01-15T00:00:00Z
- Status: clientTransferProhibited
- Nameservers: ns1.malicious.example.com

**CIRCL Passive DNS (recent resolutions):**
- `A` → `198.51.100.1` (last seen: 2026-08-20, count: 42)
- `MX` → `mail.malicious.example.com` (last seen: 2026-07-01, count: 5)
```

---

## Workflow E — Cross-case correlation

Run after observable enrichment to find other cases in this Flowintel instance
that share the same IPs, hashes, or ASNs — linking them as a campaign cluster.

### Auto mode (recommended)

Observables are extracted from the current case Notes automatically.
Run this after `enrich_observable` has written enrichment results:

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"module": "correlate_observables", "payload": {}}'
```

### Manual mode — explicit observables

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "correlate_observables",
    "payload": {
      "observables": ["198.51.100.1", "AS12345", "f15a57d9..."],
      "min_overlap": 2
    }
  }'
```

### What happens

1. Extracts IPs, hashes (MD5/SHA1/SHA256), and ASNs from the current case Notes
2. Scans Notes of every other case in the instance for matching values
3. For each case that shares at least `min_overlap` observables:
   - Creates a `Case_Link_Case` record (visible in Flowintel **Linked Cases** tab)
   - Lists which observables are shared and how many
4. Writes a correlation summary to the current case Notes

### Response

```json
{
  "searched": 5,
  "matched_cases": 2,
  "linked": [8, 9],
  "correlations": [
    {
      "case_id": 8,
      "title": "Suspicious dropper campaign",
      "matches": [
        {"value": "f15a57d9...", "type": "hash"},
        {"value": "1ada846a...", "type": "hash"}
      ]
    }
  ]
}
```

### Note written to case

```
## Correlation: Case #17

Searched 5 observable(s) across all cases.
Found overlap in 2 case(s):

### Case #8 — Suspicious dropper campaign (2 shared observables)
_Last modified: 2026-09-05_
- `f15a57d9...` (hash)
- `1ada846a...` (hash)
_case link created ✓_
```

---

## Workflow F — Assessment suggestion

Run after `correlate_observables` to get a scored, rule-based recommendation before
the analyst records a final decision. `suggest_assessment` scans all case Notes and
scores 16 signals across three decision axes.

### Run

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"module": "suggest_assessment", "payload": {}}'
```

No payload required.

### Response

```json
{
  "case_id": 17,
  "decision": "needs-ghidra",
  "scores": { "ghidra": 7, "angr": 0, "confirmed": 0 },
  "signals": [
    { "key": "process_injection", "weight": 3, "description": "Process injection APIs (VirtualAlloc, CreateRemoteThread)" },
    { "key": "no_strings",        "weight": 2, "description": "No extractable strings (obfuscated binary)" },
    { "key": "low_level_alloc",   "weight": 1, "description": "Low-level memory allocation APIs" },
    { "key": "correlation_found", "weight": 1, "description": "Correlation with other cases — possible campaign" }
  ]
}
```

### Decision logic

| Condition | Suggested decision |
|-----------|-------------------|
| `angr_score ≥ 4` | `needs-angr` |
| `ghidra_score ≥ 3` | `needs-ghidra` |
| `confirmed_score < 0` and `ghidra_score < 3` | `confirmed` |
| No strong signals | `uncertain — manual review` |

### Note written to case

```
## Assessment Suggestion: Case #17

**Suggested decision: needs-ghidra** (ghidra score: 7, angr score: 0, confirmed score: 0)

**Signals detected:**
| Signal | Weight | Description |
|--------|--------|-------------|
| process_injection | +3 | Process injection APIs (VirtualAlloc, CreateRemoteThread) |
| no_strings        | +2 | No extractable strings (obfuscated binary) |
| low_level_alloc   | +1 | Low-level memory allocation APIs |
| correlation_found | +1 | Correlation with other cases — possible campaign |

**Reasoning:** 4 signal(s) detected. Automated triage found obfuscation or evasion
signals that prevent IOC recovery from static analysis alone. Manual Ghidra
decompilation is required to understand the payload.

_Run `assess_case` with `decision: needs-ghidra` to record this decision._
```

---

## Workflow G — Record analyst assessment decision

Use after reviewing enrichment notes and the `suggest_assessment` output to record
the analyst's final decision. Applies a colour-coded custom tag, updates case status,
writes a timestamped audit note, and — for `needs-ghidra` and `needs-angr` — sends
an escalation alert to `#flowintel-alerts` in Mattermost.

### Run

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "assess_case",
    "payload": {
      "decision": "needs-ghidra",
      "rationale": "Process injection APIs and high entropy — IOCs not recoverable from static analysis."
    }
  }'
```

### Decisions

| `decision` | Custom tag | Case status | Mattermost alert | Next step |
|------------|-----------|-------------|-----------------|-----------|
| `confirmed` | confirmed (green) | Approved | — | Publishes MISP draft event → distribute IOCs |
| `needs-ghidra` | needs-ghidra (orange) | Request Review | ✓ sent to `#flowintel-alerts` | Open binary in Ghidra |
| `needs-angr` | needs-angr (red) | Request Review | ✓ sent to `#flowintel-alerts` | Run angr symbolic execution |
| `false-positive` | false-positive (grey) | Rejected | — | No further action |

Running `assess_case` again replaces the previous tag — only one assessment tag is active at a time.

### Mattermost alert (needs-ghidra / needs-angr)

When `MATTERMOST_ENABLED = True` in `conf/config_module.py`, a message is posted
to `#flowintel-alerts` automatically:

```
🔍 Case #17 escalated: Needs Ghidra

| Field      | Value                                        |
|------------|----------------------------------------------|
| Case       | [Suspicious dropper](https://<flowintel>/case/17) |
| Decision   | `needs-ghidra`                               |
| Analyst    | analyst@example.com                          |
| Rationale  | Process injection APIs and high entropy...   |

**Next step:** Open the binary in Ghidra using the hashes and suspicious strings
from the case Notes as a navigation guide.
```

For `needs-angr` the emoji is 🐛 and the next step reads:
*"Run angr symbolic execution toward the vulnerable address identified in Ghidra
to confirm exploitability."*

### Response

```json
{
  "case_id": 17,
  "decision": "needs-ghidra",
  "label": "Needs Ghidra",
  "tag": "needs-ghidra",
  "status_id": 9,
  "rationale": "Process injection APIs and high entropy...",
  "notified": true
}
```

`notified: true` means the Mattermost escalation alert was sent successfully.
`notified: false` means Mattermost is disabled or not configured.
When `decision` is `confirmed`, the response also includes a `misp` field:

```json
{
  "case_id": 17,
  "decision": "confirmed",
  "label": "Confirmed",
  "tag": "confirmed",
  "status_id": 8,
  "rationale": "All IOCs verified; no evasion signals detected.",
  "misp": {
    "published": true,
    "event_url": "https://<misp>/events/view/2125"
  }
}
```

### Note written to case

For `needs-ghidra`:

```
## Assessment: Case #17

**ESCALATED → Ghidra — insufficient evidence from automated triage.**

| Field    | Value                       |
|----------|-----------------------------|
| Decision | Needs Ghidra                |
| Analyst  | analyst@example.com         |
| Time     | 2026-09-06 00:15            |

**Rationale:**
> Process injection APIs and high entropy — IOCs not recoverable from static analysis.

_Next step: open binary in Ghidra for deep decompilation and flow analysis._
```

For `confirmed`:

```
## Assessment: Case #17

**CONFIRMED ✓ — IOCs verified. MISP event will be published.**

| Field    | Value                       |
|----------|-----------------------------|
| Decision | Confirmed                   |
| Analyst  | analyst@example.com         |
| Time     | 2026-09-06 00:15            |

**Rationale:**
> All IOCs verified; no evasion signals detected.

**MISP event published ✓** — [https://<misp>/events/view/2125](https://<misp>/events/view/2125)

_Next step: review IOCs in MISP and distribute as needed._
```

---

## Workflow H — Open a case from Mattermost

Use when an incident is reported in Mattermost and you want to open a Flowintel case
without leaving the chat.

### Command

In any Mattermost channel:

```
/flowintel <case title> [| description]
```

**Examples:**

```
/flowintel Suspicious dropper from HR email
/flowintel Ransomware on workstation PC-042 | Found at 09:00, still running, endpoint isolated
```

### What happens

1. Mattermost POSTs the command to `https://<flowintel>/mattermost/create_case`
2. Flowintel creates a new case immediately
3. A notification appears in `#flowintel-alerts`:

```
✅ Case #16 created
Title: Suspicious dropper from HR email
Link: https://<flowintel>/case/16
Opened via Mattermost by @analyst
```

4. The user who sent the command receives a private ephemeral confirmation

### Setup

Register a slash command in Mattermost (**System Console → Integrations → Slash Commands → Add**):

| Field | Value |
|-------|-------|
| Command trigger word | `flowintel` |
| Request URL | `https://<flowintel>/mattermost/create_case` |
| Request Method | POST |
| Autocomplete hint | `<case title> [| description]` |

Then set in Flowintel `conf/config_module.py`:

```python
FLOWINTEL_API_KEY      = "<flowintel-admin-api-key>"
MATTERMOST_SLASH_TOKEN = "<token-from-mattermost-slash-command>"  # optional
```

---

## Workflow I — Notify a user via Mattermost from Flowintel

Use when you want to alert a team member about a task inside Flowintel.

### Via Flowintel UI

1. Open a case → open a **task**
2. In the task's **Main** tab, find the list of assigned users
3. Click the **bell icon** 🔔 next to a user (not yourself)
4. In the modal, select **mattermost** from the module dropdown
5. Click **Send**

The user receives a notification in `#flowintel-alerts`:

```
**Analyst**, your attention is required on a case.

| Field        | Value                              |
|--------------|------------------------------------|
| Case         | [Suspicious dropper](https://...)  |
| Case ID      | 16                                 |
| Triggered by | Admin                              |
| Task         | Initial triage                     |
```

> The bell icon only appears for other users assigned to the task — you cannot notify yourself.

### Requirements

In `conf/config_module.py`:

```python
MATTERMOST_WEBHOOK_URL = "https://<mattermost>/hooks/<token>"
MATTERMOST_CHANNEL     = "flowintel-alerts"
MATTERMOST_ENABLED     = True
FLOWINTEL_URL          = "https://<flowintel>"
```

---

## Workflow J — Ghidra deep analysis (needs-ghidra path)

Use when `assess_case` has set the decision to `needs-ghidra` — automated triage found
signals (obfuscation, injection APIs, KnownMalicious hash) that require manual decompilation
to understand what the binary actually does.

### What to bring into Ghidra

All findings are already in the Flowintel case Notes from the automated pipeline:

| Input | Source note |
|-------|-------------|
| Binary file | Flowintel case → Files tab |
| MD5 / SHA256 | `reverify_binary` — Hashes section |
| Suspicious strings + offsets | `reverify_binary` — Suspicious strings table |
| IOCs (URLs, IPs, domains) | `reverify_binary` full-mode — IOC section |
| Entry-point disassembly | `reverify_binary` full-mode — Disassembly section |
| Fuzzy match candidates | `enrich_observable` hash note |
| Assessment suggestion | `suggest_assessment` — scored signals table |

### Workflow

1. Open Ghidra → **File → Import File** → select the binary from the Flowintel Files tab
2. Run auto-analysis (accept defaults)
3. In the **Symbol Tree**, navigate to the entry point address from the `reverify_binary` note
4. Cross-reference suspicious imports (e.g. `CreateRemoteThread`, `VirtualAlloc`) to find their callers
5. For each suspicious string flagged by Reverify, use **Search → For Strings** to locate it
   and confirm whether it appears in a reachable code path
6. Use the **Decompiler** window to read C pseudocode for obfuscated routines

### After analysis

Add a Ghidra findings note to the case and re-run `assess_case`:

```bash
# IOCs confirmed — close case as confirmed (publishes MISP draft)
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "assess_case",
    "payload": {
      "decision": "confirmed",
      "rationale": "Ghidra confirmed CreateRemoteThread is reachable from entry point. C2 URL recovered from decompiled string decryption routine."
    }
  }'

# Vulnerability found — escalate to angr
curl ... -d '{
  "module": "assess_case",
  "payload": {
    "decision": "needs-angr",
    "rationale": "Ghidra identified a stack buffer overflow at 0x4012A0. Exploitability not yet confirmed."
  }
}'
```

---

## Workflow K — angr symbolic execution (needs-angr path)

Use when `assess_case` has set the decision to `needs-angr` — Ghidra has confirmed
a potential vulnerability and the analyst needs to determine whether it is exploitable
and generate a proof of concept.

### Prerequisites

- angr installed: `pip install angr`
- Ghidra analysis complete — you need the address of the vulnerable code path
- Binary accessible on the analyst workstation

### Workflow

```python
import angr

proj = angr.Project("/path/to/sample.exe", auto_load_libs=False)

# Address of vulnerable function identified in Ghidra
VULN_ADDR  = 0x4012A0
# Address of a safe exit / error handler to avoid
AVOID_ADDR = 0x401500

sm = proj.factory.simulation_manager()
sm.explore(find=VULN_ADDR, avoid=AVOID_ADDR)

if sm.found:
    state = sm.found[0]
    exploit_input = state.posix.dumps(0)
    print("Exploitable")
    print("PoC input (hex):", exploit_input.hex())
else:
    print("No path found — may not be exploitable with this constraint set")
```

For ROP chain generation, use [angrop](https://github.com/angr/angrop):

```python
rop = proj.analyses.ROP()
rop.find_gadgets()
chain = rop.execve("/bin/sh")
print(chain.payload_code())
```

### After analysis

Add the exploitability verdict and PoC to the case Notes, then close with `assess_case`:

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "assess_case",
    "payload": {
      "decision": "confirmed",
      "rationale": "angr confirmed exploitability via stack overflow at 0x4012A0. PoC input attached to case Notes. CVSS estimated 9.8 (RCE, no auth)."
    }
  }'
```

---

## Workflow L — Preserve a defaced / injected / XSS page

Use **immediately** when you discover a defaced, script-injected, or XSS-exploited page —
before the admin restores or takes down the site. `preserve_page` captures forensic
evidence using a headless Chromium browser and stores it permanently in the case.

### Run

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "preserve_page",
    "payload": {
      "url": "https://situs-deface.go.id",
      "wayback": true,
      "save_files": true
    }
  }'
```

### What is captured

| Artefak | Disimpan di | Keterangan |
|---------|------------|------------|
| Screenshot PNG (full page) | Files tab | Bukti visual kondisi saat ini |
| HTML source lengkap | Files tab | Untuk analisis script injeksi |
| SHA-256 screenshot | Notes tab | Bukti integritas — tidak bisa dipalsukan |
| SHA-256 HTML | Notes tab | Bukti integritas |
| Timestamp UTC | Notes tab | Waktu capture resmi |
| External scripts/resources | Notes tab | **Kritis untuk injeksi** — domain mana yang load script |
| Semua domain dikontaki | Notes tab | Seluruh network activity saat halaman dibuka |
| Wayback Machine URL | Notes tab | Arsip publik permanen |

### Note written to case

```
## Preserve: `https://situs-deface.go.id`

| Field | Value |
|-------|-------|
| Timestamp (UTC) | `2026-09-06 09:16:33 UTC` |
| Page title | Hacked by XYZ |
| Final URL | `https://situs-deface.go.id/` |
| HTML SHA-256 | `7b6cd9a1d881c4a...` |
| Screenshot SHA-256 | `421c19fc4b60588...` |
| Screenshot file | `bce410fd-....png` (Files tab) |
| HTML source file | `ae5a0e6c-....html` (Files tab) |
| Wayback Machine | https://web.archive.org/web/2026.../https://situs-deface.go.id |

### External scripts / resources (2)

⚠️ These resources are loaded from outside the page domain — review for injected content:

- `https://cdn-slot88.xyz/js/inject.js`
- `https://track.ads-hidden.com/pixel.gif`

### All external domains contacted (3)

- `cdn-slot88.xyz` — 4 request(s)
- `track.ads-hidden.com` — 1 request(s)
- `fonts.googleapis.com` — 2 request(s)
```

### Response

```json
{
  "url": "https://situs-deface.go.id",
  "timestamp": "2026-09-06 09:16:33 UTC",
  "title": "Hacked by XYZ",
  "final_url": "https://situs-deface.go.id/",
  "html_sha256": "7b6cd9a1d881c4...",
  "screenshot_sha256": "421c19fc4b60...",
  "external_scripts": ["https://cdn-slot88.xyz/js/inject.js"],
  "total_requests": 7,
  "wayback": {"url": "https://web.archive.org/save/https://situs-deface.go.id"},
  "screenshot_uuid": "bce410fd-f862-40d7-bcc0-71183e1eb4cc",
  "html_uuid": "ae5a0e6c-1dfe-432e-b920-640fd6c4b9cb"
}
```

### Recommended flow per case type

**Defacement:**
```
preserve_page(url)          ← sebelum situs dipulihkan
enrich_observable(domain)   ← pemilik situs korban
enrich_observable(ip)       ← hosting provider → kontak untuk takedown
correlate_observables()     ← apakah attacker ini pernah deface situs lain
assess_case(confirmed)
```

**Script injection (judi/porno):**
```
preserve_page(url)                          ← tangkap halaman + daftar external scripts
enrich_observable(domain injector)          ← siapa di balik cdn-slot88.xyz
enrich_observable(ip injector)              ← hosting attacker
enrich_observable(domain korban)            ← pemilik situs yang terinjeksi
correlate_observables()                     ← satu IP bisa injeksi banyak situs
assess_case(confirmed)
```

**XSS:**
```
preserve_page(url_with_payload)             ← tangkap halaman + exfil domain
enrich_observable(domain situs rentan)      ← untuk responsible disclosure
enrich_observable(domain exfil attacker)    ← tujuan data dicuri
correlate_observables()
assess_case(confirmed)
```

---

## Depth options

| Depth | What runs | YARA strings source |
|-------|-----------|---------------------|
| `quick` | Header, sections, imports, exports, strings, hashes | Generic strings from extraction |
| `full` | Everything in quick + entry-point disassembly + IOC classification | IOC strings: URLs, IPs, domains, registry keys |

Full mode produces more targeted YARA rules because the strings section contains
confirmed IOC patterns rather than arbitrary printable strings.

---

## MISP object mapping

| Reverify finding | MISP object / attribute |
|-----------------|-------------------------|
| Filename | `file` → `filename` |
| File size | `file` → `size-in-bytes` |
| MD5 / SHA1 / SHA256 | `file` → `md5` / `sha1` / `sha256` |
| MIME type | `file` → `mimetype` |
| PE metadata | `pe` → `type`, `machine-type`, `number-sections`, `entrypoint-address` |
| PE imports | `pe` → `text` (comma-separated) |
| PE section names | `pe-section` → `name` (one object per section) |
| ELF metadata | `elf` → `arch`, `entrypoint-address`, `number-sections` |
| ELF section names | `elf-section` → `name` (one object per section) |
| URLs *(full)* | attribute `url` — Network activity |
| IP addresses *(full)* | attribute `ip-dst` — Network activity |
| Domains *(full)* | attribute `domain` — Network activity |
| Registry keys *(full)* | attribute `regkey` — Persistence mechanism |
| Other IOC strings *(full)* | attribute `pattern-in-file` — Payload delivery |
| Entry-point disasm *(full)* | attribute `text` — Artifacts dropped |

---

## Supported file formats

Detection is based on magic bytes — file extension is ignored.

| Magic bytes | Format | MISP objects |
|-------------|--------|--------------|
| `MZ` | Windows PE (.exe, .dll, .sys, …) | `file` + `pe` + `pe-section` ×N |
| `\x7fELF` | Linux / Android ELF | `file` + `elf` + `elf-section` ×N |
| `\xfe\xed\xfa` / `\xce\xfa\xed\xfe` | Mach-O | `file` |
| anything else | Raw / script / document | `file` + string attributes *(full mode)* |

---

## MISP tab sync

When `push_to_misp` is enabled, the module performs a two-way operation:

1. **Push** — creates a MISP event on the external MISP instance
2. **Sync back** — immediately re-fetches the created event and writes every object
   and attribute into Flowintel's database, so the case MISP tab shows the full
   structured data without any manual import step

---

## YARA rule deployment

After an analysis run, copy the rule from the case Notes tab to a `.yar` file and scan:

```bash
# Scan a single file
yara rule.yar /path/to/suspicious.exe

# Scan a directory
yara rule.yar /path/to/samples/

# Scan recursively
yara -r rule.yar /path/to/samples/
```

To hunt for variants across a collection, tune the condition before deploying:

```yara
condition:
    // Hash match = exact sample
    hash.md5(0, filesize) == "..."
    // String match = family variant (remove strings you consider too generic)
    or 2 of ($s*)
```

---

## Credentials

MISP credentials are read directly from the Flowintel database — no manual configuration needed.
The module uses the first available `Connector_Instance` and its associated API key.

Ensure your Flowintel instance has a MISP connector configured under **Connectors**.

---

## Workflow M — DDoS source analysis (`enrich_bulk_ips`)

**Use case:** server or network receives a volumetric attack; you have a list of source IPs
from netflow or access logs and need to quickly identify origin ASNs, flag bulletproof hosting,
and write a structured summary for the case.

### Payload

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ips` | list | auto | IP strings to enrich. If omitted, auto-extracted from case Notes (regex) |
| `max_ips` | integer | 100 | Cap on IPs enriched per run |

### Quick start

```bash
curl -s -X POST https://flowintel.iww.web.id/modules/analyze/enrich_bulk_ips \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": 42,
    "payload": {
      "ips": ["1.2.3.4", "5.6.7.8", "9.10.11.12"],
      "max_ips": 200
    }
  }'
```

Or leave `ips` out — the module automatically extracts every IP from case Notes.

### What it produces

Note appended to case:

```
## Bulk IP Enrichment

**Input:** 87 IPs | **Enriched:** 85 | **Skipped (private/invalid):** 2 | **Suspicious ASNs:** 3

### Top ASNs (12 unique)

| ASN | Holder | IPs | Country | Flag |
|-----|--------|-----|---------|------|
| AS205100 | F3 Netze e.V. | 41 | DE | ⚠️ SUSPICIOUS |
| AS20473 | Choopa LLC | 18 | US | ⚠️ SUSPICIOUS |
...

### Country distribution (9 countries)

| Country | IPs |
|---------|-----|
| DE | 41 |
| US | 23 |
...

### Suspicious IPs (7)

⚠️ These IPs belong to ASNs associated with botnets, bulletproof hosting, or Tor exits:

- `1.2.3.4` — F3 Netze e.V.
- `5.6.7.8` — Choopa LLC
```

### Response JSON

```json
{
  "total_input": 87,
  "public_ips": 85,
  "enriched": 85,
  "skipped_private": 2,
  "unique_asns": 12,
  "unique_countries": 9,
  "suspicious_count": 7,
  "top_asns": [
    {"asn": "205100", "holder": "F3 Netze e.V.", "ip_count": 41},
    {"asn": "20473",  "holder": "Choopa LLC",    "ip_count": 18}
  ]
}
```

### Recommended follow-up

- Run `correlate_observables` — links cases sharing the same attacker ASNs
- Run `suggest_assessment` — scores the case based on enrichment signals
- Export suspicious IPs to firewall blocklist or MISP feed

---

## Workflow N — Account takeover / credential stuffing (`parse_auth_log`)

**Use case:** web or SSH service reports unusual failed login volume; analyst pastes raw log
content into the payload and the module parses it, identifies attacker IPs, targeted accounts,
and enriches the top offenders via RDAP/ASN.

### Supported log formats (auto-detected)

| Format | Detection | Example line |
|--------|-----------|--------------|
| `nginx` / `apache` | Combined Log Format regex | `1.2.3.4 - - [06/Sep/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 ...` |
| `auth` | sshd `Failed password` regex | `Sep  6 10:00:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 55432 ssh2` |
| `json` | First line parses as JSON | `{"ip":"1.2.3.4","status":401,"path":"/login","user":"admin"}` |

### Payload

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_text` | string | — | Raw log content (**required**) |
| `log_format` | string | `auto` | `nginx` \| `apache` \| `auth` \| `json` \| `auto` |
| `threshold` | integer | 5 | Min failed attempts to flag IP as attacker |
| `enrich_top` | integer | 20 | Enrich top N IPs via RDAP/ASN |

### Quick start — SSH auth.log

```bash
LOG=$(sudo tail -n 5000 /var/log/auth.log | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
curl -s -X POST https://flowintel.iww.web.id/modules/analyze/parse_auth_log \
  -H "Content-Type: application/json" \
  -d "{\"case_id\": 43, \"payload\": {\"log_text\": $LOG, \"threshold\": 3}}"
```

### Quick start — nginx access.log

```bash
LOG=$(sudo tail -n 10000 /var/log/nginx/access.log | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
curl -s -X POST https://flowintel.iww.web.id/modules/analyze/parse_auth_log \
  -H "Content-Type: application/json" \
  -d "{\"case_id\": 43, \"payload\": {\"log_text\": $LOG, \"log_format\": \"nginx\"}}"
```

### What it produces

Note appended to case:

```
## Auth Log Analysis

| Field | Value |
|-------|-------|
| Parsed at (UTC) | `2026-09-06 10:30:00 UTC` |
| Log format | `auth` |
| Total lines | 5000 |
| Failed auth events | 412 |
| Unique attacker IPs | 38 |
| IPs above threshold (≥5 fails) | 14 |
| Unique targeted usernames | 23 |

### Top attacker IPs (≥5 failed attempts)

| IP | Attempts | ASN | Holder | Country | UA variants |
|----|----------|-----|--------|---------|-------------|
| `1.2.3.4` | 187 | AS20473 | Choopa LLC | US | 0 |
| `5.6.7.8` | 94  | AS205100 | F3 Netze | DE | 0 |

### Most targeted usernames / paths

| Username / Path | Attempts |
|----------------|----------|
| `root` | 201 |
| `admin` | 87 |
| `ubuntu` | 44 |

### Assessment signals

- ⚠️ Top attacker `1.2.3.4` made **187** failed attempts (AS20473 Choopa LLC)
- ⚠️ **14 IPs** above threshold — likely coordinated credential stuffing
```

### Response JSON

```json
{
  "total_lines": 5000,
  "log_format": "auth",
  "failed_events": 412,
  "unique_ips": 38,
  "attackers_above_threshold": 14,
  "unique_users": 23,
  "top_attackers": [
    {"ip": "1.2.3.4", "attempts": 187, "asn": "20473", "holder": "Choopa LLC"},
    {"ip": "5.6.7.8", "attempts": 94,  "asn": "205100", "holder": "F3 Netze"}
  ]
}
```

### Recommended follow-up

- Feed attacker IPs to `enrich_bulk_ips` for full ASN grouping
- Run `correlate_observables` — matches attacker IPs against other cases
- Blocklist top N IPs at firewall / fail2ban level
- Check targeted usernames against recent data-breach dumps (HIBP / DeHashed)
