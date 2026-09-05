# Reverify Binary Analysis — Workflow Guide

This guide covers the end-to-end workflow for analyzing a binary file using
the `reverify_binary` module integrated into Flowintel, from upload to MISP event creation
and Mattermost notifications.

---

## Overview

```
Mattermost                    Binary file / API
    │                               │
    │  /flowintel <title>           │  upload or curl
    ▼                               ▼
┌─────────────────────────────────────────────────────────┐
│  Flowintel                                              │
│                                                         │
│  Case created  ◄──────────────────────────────────────  │
│                                                         │
│  [if binary uploaded]                                   │
│  Reverify analysis:                                     │
│       • File type, architecture, bitness                │
│       • Sections, imports, exports                      │
│       • MD5 / SHA1 / SHA256 hashes                      │
│       • String extraction (quick)                       │
│       • Entry-point disasm + suspicious strings (full)  │
│  Results written to Case Notes (Markdown)               │
│                                                         │
│  [optional] Push to MISP                                │
└───────────────────────┬─────────────────────────────────┘
                        │
           ┌────────────┴────────────┐
           ▼                         ▼
┌──────────────────────┐   ┌─────────────────────────────┐
│  MISP Event          │   │  Mattermost #flowintel-alerts│
│  ├── file object     │   │                             │
│  ├── pe / elf object │   │  ✅ Case #16 dibuat          │
│  ├── pe-section ×N   │   │  Judul: ...                 │
│  └── attributes      │   │  Link: https://...          │
└──────────┬───────────┘   └─────────────────────────────┘
           │ auto-sync back
           ▼
┌─────────────────────────────────────────────────────────┐
│  Flowintel Case — MISP tab                              │
│   ├── file object with all attributes                   │
│   ├── pe / elf object                                   │
│   ├── pe-section / elf-section objects (×N)             │
│   └── standalone attributes (full mode)                 │
└─────────────────────────────────────────────────────────┘
```

---

## Workflow A — Upload a new binary

Use this when you receive a new suspicious file and want to open a case immediately.

### 1. Open the upload form

Navigate to **Analyser → Reverify Binary** in the Flowintel sidebar,
or go directly to:

```
https://<your-flowintel>/reverify/
```

### 2. Fill in the form

| Field | Description |
|-------|-------------|
| **Case Title** | A short, descriptive name (e.g. `Suspicious dropper — 2026-09-05`) |
| **Description** | Optional context: source, campaign, ticket reference |
| **Binary File** | Any file — PE, ELF, Mach-O, APK, script, raw binary |
| **Analysis Depth** | See [Depth options](#depth-options) below |
| **Push to MISP** | Toggle on to create a MISP event automatically |

### 3. Submit

Click **Create Case & Analyze**. The page will:

1. Create a new Flowintel case
2. Save the uploaded file to the case
3. Run Reverify analysis (may take a few seconds for large binaries)
4. Write findings to the **Notes** tab of the case
5. If MISP push is enabled:
   - Create a MISP event with structured objects
   - Sync all objects and attributes back into the case's **MISP tab** automatically
   - Include the MISP event URL in the case note
6. Redirect to the new case page

### 4. Review results

**Notes tab** (sticky-note icon) — Markdown summary:

```
## Reverify: `sample.exe` — PE x86_64 64bit
...
**MISP Event:** https://<your-misp>/events/view/2117
```

**MISP tab** — structured objects and attributes synced from the MISP event:

```
file        filename · md5 · sha1 · sha256 · size-in-bytes · mimetype
pe          type · machine-type · number-sections · entrypoint-address
pe-section  name  (one row per section)
```

Open the case and click the **Notes** tab (sticky-note icon). You will see:

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

**Imports (top 15):** `CreateRemoteThread`, `VirtualAlloc`, ...

**MISP Event:** https://<your-misp>/events/view/2117
```

---

## Workflow B — Push an existing case to MISP

Use this when a case was already created and analyzed, but was not pushed to MISP at the time.

### 1. Open the push form

Navigate to **Analyser → Push Case to MISP** in the sidebar, or go to:

```
https://<your-flowintel>/reverify/push_misp
```

### 2. Select case and file

- **Case** — choose from the dropdown (only cases with attached files are listed, newest first)
- **File** — the file selector populates automatically once a case is chosen
- **Analysis Depth** — choose quick or full (see below)

### 3. Submit

Click **Analyze & Push to MISP**. The module will:

1. Re-run Reverify analysis on the selected file
2. Create a MISP event with structured objects
3. Sync all objects and attributes back into the case's **MISP tab**
4. Append an updated note to the case with hashes and the MISP event URL
5. Redirect to the case page with a flash message containing the MISP event link

---

## Workflow C — API / automation

For scripted pipelines or CI integration.

### Run analysis on an existing case

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
  "findings": {
    "file_type": "PE32+",
    "architecture": "x86_64",
    "bits": "64",
    "entry_point": "0x6d30",
    "file_size": 142312,
    "sections": [".text", ".rdata", ".data", ".rsrc", ".reloc"],
    "imports": ["CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory"],
    "exports": [],
    "strings_total": 312,
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "suspicious_strings": [...],
    "suspicious_count": 7
  },
  "misp_event_url": "https://<misp>/events/view/2117"
}
```

---

## Workflow D — Open a case from Mattermost

Use this when an incident is reported in Mattermost and you want to open a Flowintel case
without leaving the chat.

### Command

In any Mattermost channel, type:

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
3. A notification appears in `#flowintel-alerts` with the case number and link:

```
✅ Case #16 dibuat
Judul: Suspicious dropper from HR email
Link: https://<flowintel>/case/16
Dibuka via Mattermost oleh @wahyu
```

4. The user who sent the command gets a private ephemeral confirmation

### Setup

Register a slash command in Mattermost (**System Console → Integrations → Slash Commands → Add**):

| Field | Value |
|-------|-------|
| Command trigger word | `flowintel` |
| Request URL | `https://<flowintel>/mattermost/create_case` |
| Request Method | POST |
| Response username | `Flowintel` *(optional)* |
| Autocomplete | Enabled |
| Autocomplete hint | `<case title> [| description]` |

Then set in Flowintel `conf/config_module.py`:

```python
FLOWINTEL_API_KEY      = "<flowintel-admin-api-key>"
MATTERMOST_SLASH_TOKEN = "<token-from-mattermost-slash-command>"  # optional, for verification
```

---

## Workflow E — Notify a user via Mattermost from Flowintel

Use this when you want to alert a team member about a task inside Flowintel,
and have the notification delivered to Mattermost.

### Via Flowintel UI

1. Open a case → open a **task**
2. In the task's **Main** tab, find the list of assigned users
3. Click the **bell icon** 🔔 next to a user (not yourself)
4. In the modal, select **mattermost** from the module dropdown
5. Click **Send**

The user receives a notification in Mattermost's `#flowintel-alerts` channel:

```
**Wahyu**, your attention is required on a case.

| Field        | Value                              |
|--------------|------------------------------------|
| Case         | [Suspicious dropper](https://...)  |
| Case ID      | 16                                 |
| Triggered by | Admin                              |
| Task         | Initial triage                     |
```

> The bell icon only appears for **other users** assigned to the task — you cannot
> notify yourself. Make sure at least one other user is assigned to the task.

### Requirements

In Flowintel `conf/config_module.py`:

```python
MATTERMOST_WEBHOOK_URL = "https://<mattermost>/hooks/<token>"
MATTERMOST_CHANNEL     = "flowintel-alerts"
MATTERMOST_ENABLED     = True
FLOWINTEL_URL          = "https://<flowintel>"
```

---

## Depth options

| Depth | What runs | Use when |
|-------|-----------|----------|
| **quick** | Header parsing, section/import/export listing, string extraction, MD5/SHA1/SHA256 | First triage — fast, low noise |
| **full** | Everything in quick + entry-point disassembly (first 20 instructions) + suspicious string classification | Deep analysis, MISP enrichment, malware confirmation |

---

## MISP object mapping

| Reverify finding | MISP object / attribute type |
|-----------------|------------------------------|
| Filename | `file` → `filename` |
| File size | `file` → `size-in-bytes` |
| MD5 / SHA1 / SHA256 | `file` → `md5` / `sha1` / `sha256` |
| MIME type | `file` → `mimetype` |
| PE metadata | `pe` → `type`, `machine-type`, `number-sections`, `entrypoint-address` |
| PE imports | `pe` → `text` (comma-separated list) |
| PE section names | `pe-section` → `name` (one object per section) |
| ELF metadata | `elf` → `arch`, `entrypoint-address`, `number-sections` |
| ELF section names | `elf-section` → `name` (one object per section) |
| URLs in strings *(full)* | attribute `url`, category `Network activity` |
| IP addresses *(full)* | attribute `ip-dst`, category `Network activity` |
| Domains *(full)* | attribute `domain`, category `Network activity` |
| Registry keys *(full)* | attribute `regkey`, category `Persistence mechanism` |
| Other suspicious strings *(full)* | attribute `pattern-in-file`, category `Payload delivery` |
| Entry-point disasm *(full)* | attribute `text`, category `Artifacts dropped` |

---

## Supported file formats

Format detection is based on **magic bytes**, not file extension — any file can be uploaded.

| Magic bytes | Format | Objects created |
|-------------|--------|-----------------|
| `MZ` | Windows PE (.exe, .dll, .sys, .drv, …) | `file` + `pe` + `pe-section` ×N |
| `\x7fELF` | Linux/Android ELF (.elf, .so, no ext) | `file` + `elf` + `elf-section` ×N |
| `\xfe\xed\xfa` / `\xce\xfa\xed\xfe` | Mach-O (macOS/iOS) | `file` only |
| anything else | Raw / script / document | `file` + string-based attributes (full mode) |

---

## MISP tab sync

When `push_to_misp` is enabled, the module performs a two-way operation:

1. **Push** — creates a MISP event on the external MISP instance
2. **Sync back** — immediately re-fetches the created event and writes every object
   and attribute into Flowintel's own database, so the **MISP tab** of the case
   shows the full structured data without any manual import step

This uses the same internal mechanism as Flowintel's built-in `receive_misp_object` module
(`misp_object_helper.create_misp_object` + `result_misp_object_module`), so the data
appears identically to objects imported from MISP manually.

---

## Credentials

The module reads MISP credentials directly from the Flowintel database — no manual configuration needed.
It uses the first available `Connector_Instance` and its associated API key.

Ensure your Flowintel instance already has a MISP connector configured under **Connectors**.
