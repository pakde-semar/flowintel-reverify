# flowintel-reverify

Flowintel module that brings [Reverify](https://github.com/2akouwu/reverify) binary analysis into case workflows.

**The AI proposes. The bytes decide.** — every claim about a binary is checked against the real bytes.

## Documentation

- **[WORKFLOW.md](docs/WORKFLOW.md)** — end-to-end usage guide: upload, push to MISP, API automation, MISP object mapping

## What it does

When called on a Flowintel case, the `reverify_binary` module:

1. Resolves the target binary (from payload or case object attributes)
2. Analyzes it with Reverify's deterministic RE toolkit
3. Returns structured findings back to the case:
   - File type, architecture, bitness
   - Sections, imports, exports
   - MD5 / SHA1 / SHA256 hashes
   - String extraction with offsets
   - Entry-point disassembly (full mode)
   - Suspicious string detection (full mode)
4. Optionally pushes structured objects to a connected MISP instance

## Use case

```
Flowintel Case (malware incident)
  ├── Artifact: suspicious binary
  └── [Module: reverify_binary (depth=full)]
       ├── Type: Windows PE x86_64
       ├── Imports: CreateRemoteThread, VirtualAlloc, WriteProcessMemory ...
       ├── Suspicious strings: http://c2.evil.com, cmd.exe, base64
       ├── Entry disasm: endbr64 / push rbp / ...
       └── → Push findings to MISP as file/pe/pe-section objects
```

## Requirements

- [Flowintel](https://github.com/flowintel/flowintel) (running instance)
- [Reverify](https://github.com/2akouwu/reverify) installed in the Flowintel venv
- Python 3.10+

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

## Quick start

### Upload a new binary (web UI)

Navigate to **Analyser → Reverify Binary** in the Flowintel sidebar.
Fill in a case title, upload the binary, choose analysis depth, and optionally toggle **Push to MISP**.

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

## Payload options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file_path` | string | — | Absolute path to binary on the server |
| `depth` | `"quick"` \| `"full"` | `"quick"` | Analysis depth |
| `display_name` | string | basename of file_path | Original filename shown in notes and MISP |
| `push_to_misp` | boolean | `false` | Create a MISP event from findings |

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

## Test without Flowintel

```bash
cd flowintel-reverify
python tests/test_module.py /bin/ls full
```

## License

MIT
