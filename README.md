# flowintel-reverify

Flowintel module that brings [Reverify](https://github.com/2akouwu/reverify) binary analysis
into case workflows — with automatic triage, structured findings, and
[MISP](https://github.com/MISP/MISP) threat intelligence enrichment in a single step.

**The AI proposes. The bytes decide.** — every claim about a binary is checked against the real bytes.

---

## Documentation

- **[WORKFLOW.md](docs/WORKFLOW.md)** — end-to-end usage guide: upload, push to MISP, API automation, MISP object mapping
- **[COMPARISON.md](docs/COMPARISON.md)** — Ghidra vs Reverify vs angr: feature comparison tables, when to use each, tiered workflow

---

## What it does

Upload a binary file → get a Flowintel case + MISP event, fully populated, in one click.

When called on a Flowintel case, the `reverify_binary` module:

1. Resolves the target binary (from payload or case object attributes)
2. Analyzes it with Reverify's deterministic RE toolkit — no LLM, no guessing
3. Writes structured findings to the case **Notes** tab (Markdown)
4. Optionally pushes findings to [MISP](https://github.com/MISP/MISP) as typed objects:
   - Creates a MISP event with `file` / `pe` / `elf` / section objects
   - Syncs all objects and attributes back into the case's **MISP tab** automatically

### Findings extracted

| Category | Details |
|----------|---------|
| Identity | File type, architecture, bitness |
| Hashes | MD5, SHA1, SHA256 |
| Structure | Sections, imports, exports |
| Strings | All printable strings with offsets |
| Disassembly | Entry-point disasm — first 20 instructions *(full mode)* |
| Suspicious strings | URLs, IPs, domains, registry keys, patterns *(full mode)* |

---

## Triage workflow

```
Incoming binary
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  Reverify  (automated, seconds)                     │
│                                                     │
│  • File type + architecture + hashes                │
│  • Sections, imports, exports                       │
│  • String extraction + suspicious string scan       │
│  • Entry-point disassembly (full mode)              │
│                                                     │
│  → Case Notes: Markdown summary                     │
│  → MISP: structured objects + attributes            │
│  → Flowintel MISP tab: synced automatically         │
└─────────────────────────────────────────────────────┘
      │
      │  suspicious? escalate to analyst
      ▼
┌─────────────────────────────────────────────────────┐
│  Ghidra  (manual, hours)                            │
│                                                     │
│  • Full disassembly + decompile to C pseudocode     │
│  • Execution flow tracing                           │
│  • Confirm and refine IOCs from Reverify            │
└─────────────────────────────────────────────────────┘
      │
      │  need to prove exploitability?
      ▼
┌─────────────────────────────────────────────────────┐
│  angr  (research-grade, hours to days)              │
│                                                     │
│  • Symbolic execution across all code paths         │
│  • Constraint solving via Z3 SMT solver             │
│  • Automatic exploit / PoC generation               │
└─────────────────────────────────────────────────────┘
```

---

## Mattermost integration

Two-way integration with [Mattermost](https://mattermost.com/):

### Flowintel → Mattermost (notify_user)

When a case event occurs, notify a user via Mattermost incoming webhook.
Notification is posted to a dedicated channel (e.g. `#flowintel-alerts`).

Configure in `conf/config_module.py`:

```python
MATTERMOST_WEBHOOK_URL = "https://<mattermost>/hooks/<token>"
MATTERMOST_CHANNEL    = "flowintel-alerts"
MATTERMOST_ENABLED    = True
FLOWINTEL_URL         = "https://<flowintel>"  # used for case links in notifications
```

### Mattermost → Flowintel (slash command)

Open a new case directly from any Mattermost channel:

```
/flowintel Suspicious dropper dari email HR
/flowintel Ransomware on workstation PC-042 | Found at 09:00, still running
```

On submit:
- A new Flowintel case is created immediately
- A notification with the case number and link appears in `#flowintel-alerts`
- The user who typed the command gets a private ephemeral confirmation

**Setup** — register the slash command in Mattermost:

| Field | Value |
|-------|-------|
| Command | `/flowintel` |
| Request URL | `https://<flowintel>/mattermost/create_case` |
| Method | POST |

Then set in `conf/config_module.py`:

```python
FLOWINTEL_API_KEY     = "<flowintel-admin-api-key>"
MATTERMOST_SLASH_TOKEN = "<token-from-mattermost-slash-command-config>"  # optional
```

---

## MISP integration

When **Push to MISP** is enabled, the module:

1. Creates a [MISP](https://github.com/MISP/MISP) event (`distribution: org only`, `threat level: medium`)
2. Populates it with typed objects based on the binary format detected:

| Binary type | MISP objects created |
|-------------|---------------------|
| Windows PE | `file` + `pe` + `pe-section` ×N |
| Linux ELF | `file` + `elf` + `elf-section` ×N |
| Mach-O | `file` |
| Raw / script | `file` |

3. Maps suspicious strings to MISP attribute types *(full mode)*:

| String pattern | MISP attribute |
|----------------|----------------|
| `http://` / `https://` | `url` — Network activity |
| IPv4 address | `ip-dst` — Network activity |
| Domain name | `domain` — Network activity |
| `HKEY_*` | `regkey` — Persistence mechanism |
| Other | `pattern-in-file` — Payload delivery |

4. Syncs all created objects and attributes back into the Flowintel case **MISP tab**
   — no manual import step required

MISP credentials are read automatically from the Flowintel database
(`Connector_Instance` + `User_Connector_Instance`).

---

## Requirements

- [Flowintel](https://github.com/flowintel/flowintel) (running instance)
- [Reverify](https://github.com/2akouwu/reverify) installed in the Flowintel venv
- [MISP](https://github.com/MISP/MISP) instance connected to Flowintel *(for MISP push)*
- Python 3.10+

---

## Installation

```bash
git clone https://github.com/pakde-semar/flowintel-reverify.git
cd flowintel-reverify

# Install module into Flowintel
FLOWINTEL_DIR=/opt/flowintel bash install.sh

# Restart Flowintel
systemctl restart flowintel
```

If Reverify is installed in a non-default path, set the env var before starting Flowintel:

```bash
export REVERIFY_VENV=/path/to/reverify/venv/lib/python3.12/site-packages
```

---

## Quick start

### Upload a new binary (web UI)

Navigate to **Analyser → Reverify Binary** in the Flowintel sidebar.
Fill in a case title, upload the binary, choose analysis depth, and optionally toggle **Push to MISP**.

Any file type is accepted — format is detected from magic bytes, not the file extension.

### Push an existing case to MISP

Navigate to **Analyser → Push Case to MISP**, select the case and file, and submit.

### Via API

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
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

> The `run_analyze_module` route requires a patch to Flowintel's `case_api.py`.
> The patch is included in this repo at `patch/case_api_analyze_route.patch`.

---

## Payload options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file_path` | string | — | Absolute path to binary on the server |
| `depth` | `"quick"` \| `"full"` | `"quick"` | Analysis depth |
| `display_name` | string | basename of file_path | Original filename shown in notes and MISP |
| `push_to_misp` | boolean | `false` | Create a MISP event and sync back to case MISP tab |

---

## Module response

```json
{
  "summary": "File: sample.exe (142312 bytes)\nType: PE32+\nArch: x86_64 64-bit\n...",
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

## Test without Flowintel

```bash
cd flowintel-reverify
python tests/test_module.py /bin/ls full
```

---

## License

MIT
