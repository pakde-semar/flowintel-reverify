# flowintel-reverify

Flowintel module that brings [Reverify](https://github.com/2akouwu/reverify) binary analysis into case workflows.

**The AI proposes. The bytes decide.** — every claim about a binary is checked against the real bytes.

## What it does

When called on a Flowintel case, the `reverify_binary` module:

1. Resolves the target binary (from payload or case object attributes)
2. Analyzes it with Reverify's deterministic RE toolkit
3. Returns structured findings back to the case:
   - File type, architecture, bitness
   - Sections, imports, exports
   - String extraction with offsets
   - Entry-point disassembly (full mode)
   - Suspicious string detection (full mode)

## Use case

```
Flowintel Case (malware incident)
  ├── Artifact: suspicious binary
  └── [Module: reverify_binary (depth=full)]
       ├── Type: Windows PE x86_64
       ├── Imports: CreateRemoteThread, VirtualAlloc, WriteProcessMemory ...
       ├── Suspicious strings: http://c2.evil.com, cmd.exe, base64
       ├── Entry disasm: endbr64 / push rbp / ...
       └── → Push findings to MISP via existing connector
```

## Requirements

- [Flowintel](https://github.com/flowintel/flowintel) (running instance)
- [Reverify](https://github.com/2akouwu/reverify) installed at `/opt/reverfy/`
- Python 3.10+

## Installation

```bash
git clone https://github.com/<your-org>/flowintel-reverify.git
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

## Usage in Flowintel

### Via API

Gunakan endpoint `run_analyze_module` (tidak butuh MISP connector instance):

```bash
# Quick analysis (parse + strings)
curl -X POST https://flowintel.iww.web.id/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "reverify_binary",
    "payload": {
      "file_path": "/path/to/sample.exe",
      "depth": "quick"
    }
  }'

# Full analysis (+ disasm + suspicious string detection)
curl -X POST https://flowintel.iww.web.id/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "reverify_binary",
    "payload": {
      "file_path": "/path/to/sample.exe",
      "depth": "full"
    }
  }'
```

> **Catatan implementasi**: Flowintel membutuhkan patch `case_api.py` untuk menambahkan route
> `/<cid>/run_analyze_module` — route ini ada di repo ini sebagai `patch/case_api_analyze_route.patch`.

### Via case object attribute

Add an object to the case with attribute `object_relation` = `filename` or `malware-sample`
and set the `value` to the absolute path of the binary. The module will pick it up automatically.

## Payload options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file_path` | string | — | Absolute path to binary on the server |
| `depth` | `"quick"` \| `"full"` | `"quick"` | Analysis depth |

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
    "imports": ["CreateRemoteThread", "VirtualAlloc", ...],
    "exports": [],
    "strings": [{"offset": "0x318", "encoding": "ASCII", "value": "cmd.exe"}],
    "strings_total": 312,
    "disasm_entry": [
      {"address": "0x1000", "mnemonic": "endbr64", "op_str": ""},
      ...
    ],
    "suspicious_strings": [...],
    "suspicious_count": 7
  }
}
```

## Test without Flowintel

```bash
cd flowintel-reverify
python tests/test_module.py /bin/ls full
```

## License

MIT
