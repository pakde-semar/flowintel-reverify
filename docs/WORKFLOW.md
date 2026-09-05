# Reverify Binary Analysis — Workflow Guide

This guide covers the end-to-end workflow for analyzing a binary file using
the `reverify_binary` module integrated into Flowintel, from upload to MISP event creation.

---

## Overview

```
Binary file
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Flowintel /reverify/                                   │
│                                                         │
│  1. Upload binary  ──►  New Case created                │
│  2. Reverify analysis:                                  │
│       • File type, architecture, bitness                │
│       • Sections, imports, exports                      │
│       • MD5 / SHA1 / SHA256 hashes                      │
│       • String extraction (quick)                       │
│       • Entry-point disasm + suspicious strings (full)  │
│  3. Results written to Case Notes (Markdown)            │
│  4. [Optional] Push structured objects to MISP          │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  MISP Event                                             │
│   ├── Object: file  (filename, md5, sha1, sha256, size) │
│   ├── Object: pe / elf  (arch, entrypoint, sections)    │
│   ├── Objects: pe-section / elf-section  (×N)           │
│   └── Attributes (full mode):                           │
│        url · ip-dst · domain · regkey · pattern-in-file │
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
5. If MISP push is enabled — create a MISP event and include the event URL in the note
6. Redirect to the new case page

### 4. Review results

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
3. Append an updated note to the case with hashes and the MISP event URL
4. Redirect to the case page with a flash message containing the MISP event link

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

## Credentials

The module reads MISP credentials directly from the Flowintel database — no manual configuration needed.
It uses the first available `Connector_Instance` and its associated API key.

Ensure your Flowintel instance already has a MISP connector configured under **Connectors**.
