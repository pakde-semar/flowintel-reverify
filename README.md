# flowintel-reverify

A multi-stage malware triage and observable enrichment framework built on
[Flowintel](https://github.com/flowintel/flowintel),
using [Reverify](https://github.com/2akouwu/reverify) as its static analysis core.

Every finding is grounded in raw bytes. Every step produces evidence an analyst can verify.

---

## Documentation

- **[WORKFLOW.md](docs/WORKFLOW.md)** — end-to-end usage: upload, MISP push, Mattermost integration, observable enrichment, API automation
- **[COMPARISON.md](docs/COMPARISON.md)** — Reverify · Ghidra · angr · YARA: when to use each, how they fit together
- **[ROADMAP.md](docs/ROADMAP.md)** — what is done and what is being considered next

---

## What it does

Eight modules share the same Flowintel case as their container:

```
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│  preserve_page       │  │  reverify_binary     │  │  enrich_observable    │
│                      │  │                      │  │                      │
│  Playwright snapshot │  │  Stage 1 — Static    │  │  Domain → RDAP+PDNS  │
│  Screenshot (PNG)    │  │    analysis          │  │  IP     → RDAP+RIPE  │
│  HTML source         │  │  Stage 2 — YARA rule │  │  URL    → Lookyloo   │
│  External resources  │  │    generation        │  │  Hash   → CIRCL      │
│  SHA-256 hashes      │  │  Stage 3 — MISP push │  │          lookup +    │
│  Wayback Machine     │  │    + Mattermost      │  │          TLSH/ssdeep │
│  submission          │  │                      │  │                      │
│                      │  │                      │  │  Signals appended to │
│  Run FIRST before    │  │                      │  │  each enrichment note│
│  page is restored    │  │                      │  │                      │
└──────────────────────┘  └──────────────────────┘  └──────────────────────┘
          │                          │                          │
          └──────────────────────────┴──────────────────────────┘
                                     ▼
                            FLOWINTEL CASE
                     (Notes · MISP tab · Tasks · Links · Files)
                                     │
          ┌──────────────────────────┴──────────────────────────┐
          ▼                                                      ▼
┌──────────────────────┐                            ┌──────────────────────┐
│  correlate_observables│                            │                      │
│                      │  │                      │  │                      │
│  Stage 1 — Static    │  │  Domain → RDAP+PDNS  │  │  Auto-extract IPs,   │
│    analysis          │  │  IP     → RDAP+RIPE  │  │  hashes, ASNs from   │
│  Stage 2 — YARA rule │  │  URL    → Lookyloo   │  │  current case Notes  │
│    generation        │  │  Hash   → CIRCL      │  │                      │
│  Stage 3 — MISP push │  │          lookup +    │  │  Scan all other case │
│    + Mattermost      │  │          TLSH/ssdeep │  │  Notes for matches   │
│                      │  │                      │  │                      │
│                      │  │  Signals appended to │  │  Create case links   │
│                      │  │  each enrichment note│  │  Write corr. note    │
└──────────────────────┘  └──────────────────────┘  └──────────────────────┘
          │                          │                          │
          └──────────────────────────┴──────────────────────────┘
                                     ▼
                            FLOWINTEL CASE
                     (Notes · MISP tab · Tasks · Links)
                                     │
          ┌──────────────────────────┴──────────────────────────┐
          ▼                                                      ▼
┌──────────────────────┐                            ┌──────────────────────┐
│  suggest_assessment  │ ──── recommendation ─────► │  assess_case         │
│                      │                            │                      │
│  Scan all Notes for  │                            │  Record analyst      │
│  16 scored signals   │                            │  decision, apply     │
│  (entropy, injection │                            │  custom tag, update  │
│  APIs, KNOWN MAL,    │                            │  case status, write  │
│  vuln keywords, ...)  │                            │  audit note          │
│                      │                            │                      │
│  Output: scored      │                            │  confirmed →         │
│  suggestion + table  │                            │    Approved; MISP    │
│  of triggered rules  │                            │    draft published   │
│                      │                            │  needs-ghidra →      │
│                      │                            │    Request Review +  │
│                      │                            │    🔍 MM alert       │
│                      │                            │  needs-angr →        │
│                      │                            │    Request Review +  │
│                      │                            │    🐛 MM alert       │
│                      │                            │  false-positive →    │
│                      │                            │    Rejected          │
│                      │                            │                      │
└──────────────────────┘                            └──────────────────────┘
```

---

## Post-assessment paths

After `assess_case` records the analyst's decision, two downstream paths are available
for cases that need deeper investigation:

### needs-ghidra → Ghidra (manual decompilation)

`assess_case` applies the `needs-ghidra` tag, sets status to **Request Review**,
and posts a 🔍 alert to `#flowintel-alerts` in Mattermost.
The analyst then opens the binary in [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
with the Flowintel case Notes as a guide:

| What to bring | Where it comes from |
|---------------|---------------------|
| Binary file | Flowintel case → Files tab |
| Hashes (MD5, SHA256) | `reverify_binary` Notes |
| Suspicious strings + offsets | `reverify_binary` Notes |
| IOCs (URLs, IPs, domains) | `reverify_binary` full-mode Notes |
| Fuzzy match results | `enrich_observable` hash Notes |

Ghidra confirms whether suspicious strings appear in reachable code paths,
recovers the full call graph, and decompiles obfuscated logic into C pseudocode.
When analysis is complete, the analyst adds findings to the case Notes and re-runs
`assess_case` with `confirmed` or `false-positive`.

### needs-angr → angr (symbolic execution)

`assess_case` applies the `needs-angr` tag, sets status to **Request Review**,
and posts a 🐛 alert to `#flowintel-alerts` in Mattermost.

The decision is triggered when `suggest_assessment` signals `angr_score ≥ 4` — typically after Ghidra has already confirmed a potential vulnerability
and the analyst needs proof of exploitability.

[angr](https://github.com/angr/angr) runs symbolic execution with Z3 constraint solving
to determine whether a specific code path can be reached with a crafted input:

```python
import angr

proj = angr.Project("sample.exe", auto_load_libs=False)
# Explore paths toward the vulnerable address identified in Ghidra
sm = proj.factory.simulation_manager()
sm.explore(find=0xDEADBEEF, avoid=0xBADC0DE)

if sm.found:
    print("Exploitable — input:", sm.found[0].posix.dumps(0))
```

angr runs externally — the `needs-angr` decision in Flowintel is the handoff point.
Findings (exploitability verdict, PoC input) are added to the case Notes and `assess_case`
is re-run with `confirmed` to close the loop.

---

## Binary triage pipeline

A binary enters and exits as a structured case — with hashes, IOCs, a YARA detection rule,
and optionally a MISP event — without requiring any manual triage step.

```
Incoming binary
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  Stage 1 — Static analysis  (seconds)               │
│                                                     │
│  • File type, architecture, bitness                 │
│  • MD5 / SHA1 / SHA256                              │
│  • Sections, imports, exports                       │
│  • String extraction                                │
│  • Entry-point disassembly          (full mode)     │
│  • Suspicious string classification (full mode)     │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  Stage 2 — IOC extraction & YARA rule generation    │
│                                                     │
│  • URLs, IPs, domains, registry keys extracted      │
│  • YARA rule built from hashes + IOC strings        │
│  • Rule validates against yara-python before save   │
│  • Saved to case Notes — analyst can edit and ship  │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  Stage 3 — Evidence distribution   (optional)       │
│                                                     │
│  • MISP event created with typed objects:           │
│    file · pe · elf · pe-section · attributes        │
│  • Objects synced back to Flowintel MISP tab        │
│  • Mattermost alert posted to #flowintel-alerts     │
└─────────────────────────────────────────────────────┘
```

### Stage 1 — Static analysis

| Category | Details |
|----------|---------|
| Identity | File type, architecture, bitness |
| Hashes | MD5, SHA1, SHA256 |
| Structure | Sections, imports, exports |
| Strings | All printable strings with offsets |
| Disassembly | Entry-point — first 20 instructions *(full mode)* |
| IOCs | URLs, IPs, domains, registry keys, patterns *(full mode)* |

### Stage 2 — YARA rule generation

After extraction, a YARA rule is built automatically from the findings:

```yara
import "hash"

rule sample_dropper_exe {
    meta:
        description = "Auto-generated by flowintel-reverify from sample_dropper.exe"
        generated_by = "flowintel-reverify"
        date = "2026-09-05"
        hash_md5    = "1ada846a5458a0a1e732e35e91176fd4"
        hash_sha256 = "f15a57d91734a2308b129a1ed4add2c487eadec9b8c2d46dbfd3d2f23b5c28d7"

    strings:
        $s0 = "http://malicious.example.com"  // offset 0x4120
        $s1 = "CreateRemoteThread"             // offset 0x8200
        $s2 = "HKEY_LOCAL_MACHINE\\Software"   // offset 0x9400

    condition:
        hash.md5(0, filesize) == "1ada846a5458a0a1e732e35e91176fd4"
        or hash.sha256(0, filesize) == "f15a57d91734a2308b129a1ed4add2c487eadec9b8c2d46dbfd3d2f23b5c28d7"
        or any of ($s*)
}
```

The rule matches on hash (exact sample) **or** any IOC string (family variants).
It is saved to the case Notes tab — the analyst edits, tunes, and deploys it from there.

### Stage 3 — Evidence distribution

| Destination | What is sent |
|-------------|-------------|
| Flowintel Notes | Markdown summary + YARA rule |
| MISP event | `file` + `pe`/`elf` + section objects + IOC attributes |
| Flowintel MISP tab | Full sync from MISP — no manual import |
| Mattermost | Case link posted to `#flowintel-alerts` |

---

## Observable enrichment pipeline

The `enrich_observable` module runs on any observable extracted from the triage —
or supplied directly. No API key required for any source.

| Observable | Sources | What you get |
|------------|---------|-------------|
| Domain | RDAP + CIRCL Passive DNS | Registrar, nameservers, passive DNS history (up to 20 records) |
| IP | RDAP + RIPE Stat | Network name, country, CIDR, ASN, prefix |
| URL | Lookyloo (CIRCL public) | Redirect chain, IPs contacted, screenshot and capture links |
| Hash | CIRCL hashlookup + local corpus fuzzy match | KnownMalicious flag, TLSH + ssdeep similarity vs all corpus files |

Results are written to the case Notes tab automatically.

### Hash enrichment detail

[CIRCL hashlookup](https://hashlookup.circl.lu) checks the hash against known-good (NSRL)
and known-bad (malshare, etc.) databases. If `KnownMalicious` is set, the note flags it prominently:

```
CIRCL hashlookup: KNOWN MALICIOUS ⚠️ (source: malshare.com)
- File name: eicar.com
- MIME type: text/plain
- SHA256: 275a021b...
```

If the hash is not found in public databases (novel or private malware), TLSH and ssdeep
fuzzy-match the file against every other file in the local Flowintel uploads corpus to detect
structural variants — even across recompiled samples.

### Per-enrichment signals

Every `enrich_observable` run appends an **Assessment signals** footer to the enrichment note,
giving the analyst an immediate signal without waiting for a separate assessment step:

```
---
**Assessment signals from this enrichment:**
- ⚠️ `needs-ghidra` — KNOWN MALICIOUS in CIRCL hashlookup (source: malshare)
  — automated triage cannot determine behavior; Ghidra required
```

| Observable | Signal conditions |
|------------|------------------|
| Hash | `KnownMalicious` set → needs-ghidra; trust ≥ 95 (NSRL) → confirmed; trust < 70 → needs-ghidra; fuzzy match found but not in public DB → needs-ghidra |
| Domain | Registered < 30 days → needs-ghidra; registered < 90 days → needs-ghidra; no PDNS history → needs-ghidra |
| IP | No ASN data → needs-ghidra |
| URL | Redirect chain > 3 hops → needs-ghidra; capture error → manual review |

### Local correlation

After enrichment, `correlate_observables` finds other cases in this Flowintel instance
that share the same observables — connecting cases that belong to the same campaign or
attacker infrastructure:

```
## Correlation: Case #17

Searched 5 observable(s) across all cases.
Found overlap in 2 case(s):

### Case #8 — Uji coba kirim 1 (2 shared observables)
- `f15a57d9...` (hash)
- `1ada846a...` (hash)
case link created ✓

### Case #9 — check file 2 (2 shared observables)
- `f15a57d9...` (hash)
- `1ada846a...` (hash)
case link created ✓
```

Flowintel's **Linked Cases** tab shows the connections. Observables are auto-extracted
from the current case Notes — no manual input needed after the enrichment step.

### URL enrichment detail

URLs are submitted to [Lookyloo](https://lookyloo.circl.lu) (CIRCL public instance).
The capture returns a redirect chain, all IPs contacted, and a screenshot link.
If the CIRCL public instance times out, the capture UUID and direct link are still included
in the note so the analyst can check the result later.

---

## Mattermost integration

Two-way integration with [Mattermost](https://mattermost.com/):

### Flowintel → Mattermost

When a task notification is sent, the assigned user receives a message in `#flowintel-alerts`:

```
**Analyst**, your attention is required on a case.

| Field        | Value                              |
|--------------|------------------------------------|
| Case         | [Suspicious dropper](https://...)  |
| Case ID      | 16                                 |
| Triggered by | Admin                              |
| Task         | Initial triage                     |
```

Configure in `conf/config_module.py`:

```python
MATTERMOST_WEBHOOK_URL = "https://<mattermost>/hooks/<token>"
MATTERMOST_CHANNEL    = "flowintel-alerts"
MATTERMOST_ENABLED    = True
FLOWINTEL_URL         = "https://<flowintel>"
```

### Mattermost → Flowintel

Open a case directly from any Mattermost channel:

```
/flowintel Suspicious dropper from HR email
/flowintel Ransomware on workstation PC-042 | Found at 09:00, still running
```

A new case is created immediately and the case link appears in `#flowintel-alerts`.

**Setup** — register the slash command in Mattermost:

| Field | Value |
|-------|-------|
| Command | `/flowintel` |
| Request URL | `https://<flowintel>/mattermost/create_case` |
| Method | POST |

Then set in `conf/config_module.py`:

```python
FLOWINTEL_API_KEY      = "<flowintel-admin-api-key>"
MATTERMOST_SLASH_TOKEN = "<token-from-mattermost-slash-command>"  # optional
```

---

## MISP integration

When **Push to MISP** is enabled, the module creates a MISP event and syncs it back into the
case's MISP tab — no manual import required.

| Binary type | MISP objects created |
|-------------|---------------------|
| Windows PE | `file` + `pe` + `pe-section` ×N |
| Linux ELF | `file` + `elf` + `elf-section` ×N |
| Mach-O | `file` |
| Raw / script | `file` |

IOC strings are mapped to typed MISP attributes:

| Pattern | MISP attribute type | Category |
|---------|---------------------|----------|
| `http://` / `https://` | `url` | Network activity |
| IPv4 address | `ip-dst` | Network activity |
| Domain name | `domain` | Network activity |
| `HKEY_*` | `regkey` | Persistence mechanism |
| Other | `pattern-in-file` | Payload delivery |

MISP credentials are read from the Flowintel database — no separate configuration needed.

---

## Requirements

- [Flowintel](https://github.com/flowintel/flowintel)
- [MISP](https://github.com/MISP/MISP) instance connected to Flowintel *(for MISP push)*
- Python 3.10+
- System library: `libfuzzy-dev` (for ssdeep — installed automatically by `install.sh`)
- Chromium (for `preserve_page` — installed automatically by `install.sh` via `playwright install chromium`)

Python dependencies are listed in [`requirements.txt`](requirements.txt) and installed
automatically by `install.sh`:

| Package | Purpose |
|---------|---------|
| `reverify` | Static analysis core |
| `yara-python` | YARA rule validation |
| `python-tlsh` | TLSH fuzzy hashing |
| `ssdeep` | ssdeep fuzzy hashing |
| `pymisp` | MISP event creation and publishing |
| `requests` | HTTP calls to RDAP, RIPE Stat, Lookyloo, Wayback Machine |
| `playwright` | Headless Chromium — screenshot + HTML capture for `preserve_page` |

---

## Installation

```bash
git clone https://github.com/pakde-semar/flowintel-reverify.git
cd flowintel-reverify

FLOWINTEL_DIR=/opt/flowintel bash install.sh

systemctl restart flowintel
```

`install.sh` handles everything: installs `libfuzzy-dev` via apt, installs all Python
dependencies from `requirements.txt` into the Flowintel venv, copies all modules, patches
the sidebar and API, and adds Mattermost config stubs.

To install dependencies only (skip module deployment):

```bash
SKIP_PATCH=1 FLOWINTEL_DIR=/opt/flowintel bash install.sh
```

To skip dependency installation (modules only):

```bash
SKIP_DEPS=1 FLOWINTEL_DIR=/opt/flowintel bash install.sh
```

If Reverify is installed outside the default path:

```bash
export REVERIFY_VENV=/path/to/venv/lib/python3.12/site-packages
```

---

## Quick start

### Preserve a defaced / injected page (web evidence)

Run `preserve_page` **before** the page is restored or taken down:

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" -H "Content-Type: application/json" \
  -d '{"module": "preserve_page", "payload": {"url": "https://situs-deface.go.id"}}'
```

What is captured and stored in the case:

| Artefak | Disimpan di |
|---------|------------|
| Screenshot PNG (full page) | Files tab |
| HTML source lengkap | Files tab |
| SHA-256 screenshot + HTML | Notes tab |
| Timestamp UTC | Notes tab |
| Semua external scripts/resource | Notes tab |
| Semua domain yang dikontaki browser | Notes tab |
| Wayback Machine archive URL | Notes tab |

Recommended flow for defacement, script injection, and XSS cases:

```
preserve_page(url)          ← run first, before page is restored
enrich_observable(domain)   ← owner info
enrich_observable(ip)       ← hosting provider
correlate_observables()     ← link to other cases with same IP/domain
assess_case(confirmed)      ← record decision
```

---

### Run full pipeline via web UI (one click)

Navigate to **Analyser → Push Case to MISP** (`/reverify/push_misp`),
select a case and file, choose depth, then click **Run Full Pipeline**.

This runs all four automated modules in sequence without leaving the browser:

| Step | Module | What it does |
|------|--------|-------------|
| 1 | `reverify_binary` | Static analysis + MISP draft event |
| 2 | `enrich_observable` | Enrich every hash, IP, domain, URL found in findings |
| 3 | `correlate_observables` | Cross-case scan for shared observables |
| 4 | `suggest_assessment` | Score 16 rules → recommendation |

Each step's result appears as a flash message. The page redirects to the case
when done — all Notes are written and ready for `assess_case`.

### Upload a binary (web UI)

Navigate to **Analyser → Reverify Binary** in the sidebar.
Fill in a case title, upload the binary, choose depth, and optionally toggle **Push to MISP**.

Format is detected from magic bytes — any file type is accepted.

### Run binary triage via API

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
      "generate_yara": true,
      "push_to_misp": true
    }
  }'
```

### Analyse DDoS source IPs via API

```bash
# Pass IPs explicitly or omit — module auto-extracts from case Notes
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "enrich_bulk_ips",
    "payload": {
      "ips": ["1.2.3.4", "5.6.7.8"],
      "max_ips": 200
    }
  }'
```

### Analyse auth log for ATO / credential stuffing via API

```bash
# Pipe raw log content as JSON string
LOG=$(sudo tail -n 5000 /var/log/auth.log | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d "{\"module\": \"parse_auth_log\", \"payload\": {\"log_text\": $LOG, \"threshold\": 3}}"
```

### Run observable enrichment via API

```bash
# Hash — CIRCL hashlookup + fuzzy match
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "enrich_observable",
    "payload": {
      "value": "f15a57d91734a2308b129a1ed4add2c487eadec9b8c2d46dbfd3d2f23b5c28d7"
    }
  }'

# Domain
curl ... -d '{"module": "enrich_observable", "payload": {"value": "malicious.example.com"}}'

# IP
curl ... -d '{"module": "enrich_observable", "payload": {"value": "198.51.100.1"}}'

# URL
curl ... -d '{"module": "enrich_observable", "payload": {"value": "https://malicious.example.com/stage2"}}'
```

Type is auto-detected from the value. Pass `"type"` explicitly if needed.

### Run local correlation via API

```bash
# Auto-extract observables from case Notes (run after enrich_observable)
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"module": "correlate_observables", "payload": {}}'

# Or pass explicit observables
curl ... -d '{
  "module": "correlate_observables",
  "payload": {"observables": ["198.51.100.1", "AS12345", "f15a57d9..."]}
}'
```

### Run assessment suggestion via API

```bash
# Scans all case Notes, scores 16 signals, outputs recommendation
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"module": "suggest_assessment", "payload": {}}'
```

### Record analyst decision via API

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "assess_case",
    "payload": {
      "decision": "needs-ghidra",
      "rationale": "Hash matched KnownMalicious; process injection APIs found. IOCs not recoverable from static analysis."
    }
  }'
```

---

## Payload options

### preserve_page

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | string | — | URL to preserve (required) |
| `wayback` | boolean | `true` | Submit to Wayback Machine |
| `save_files` | boolean | `true` | Attach screenshot + HTML to case Files tab |

Output written to case Notes: timestamp UTC, SHA-256 of screenshot + HTML, list of external
scripts/resources loaded, all external domains contacted, Wayback Machine archive URL.
Screenshot (PNG) and HTML source are attached to the case Files tab.

---

### reverify_binary

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file_path` | string | — | Absolute path to binary on the server |
| `depth` | `"quick"` \| `"full"` | `"quick"` | Analysis depth |
| `display_name` | string | basename of `file_path` | Filename shown in notes and MISP |
| `generate_yara` | boolean | `true` | Auto-generate YARA rule from hashes + IOC strings |
| `push_to_misp` | boolean | `false` | Create MISP event and sync to case MISP tab |

### enrich_observable

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `value` | string | — | The observable to enrich |
| `type` | `"domain"` \| `"ip"` \| `"url"` \| `"hash"` | auto-detected | Observable type |
| `corpus_path` | string | `/opt/flowintel/uploads/files/` | Path for TLSH/ssdeep corpus scan |
| `lookyloo_url` | string | `https://lookyloo.circl.lu` | Lookyloo instance for URL capture |

### correlate_observables

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `observables` | list of strings | — | Values to search for; auto-extracted from Notes if omitted |
| `types` | list | `["ip","hash","asn"]` | Types to auto-extract when `observables` not given |
| `create_links` | boolean | `true` | Create Flowintel case links for matching cases |
| `min_overlap` | integer | `1` | Minimum shared observables to include a case in results |

### suggest_assessment

No payload required. Reads the current case Notes and scores against 16 built-in rules.

### enrich_bulk_ips

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ips` | list of strings | auto | IP addresses to enrich; auto-extracted from case Notes if omitted |
| `max_ips` | integer | `100` | Cap on IPs enriched per run |

### parse_auth_log

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `log_text` | string | — | Raw log content (**required**) |
| `log_format` | `"nginx"` \| `"apache"` \| `"auth"` \| `"json"` \| `"auto"` | `"auto"` | Log format; auto-detected if `"auto"` |
| `threshold` | integer | `5` | Minimum failed attempts to flag an IP as attacker |
| `enrich_top` | integer | `20` | Enrich top N attacker IPs via RDAP/ASN |

### assess_case

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `decision` | `"confirmed"` \| `"needs-ghidra"` \| `"needs-angr"` \| `"false-positive"` | — | Analyst decision; `confirmed` publishes the MISP draft event; `needs-ghidra` and `needs-angr` send a Mattermost escalation alert |
| `rationale` | string | — | Optional explanation written to the audit note |

### Depth options (reverify_binary)

| Depth | What runs | YARA strings source |
|-------|-----------|---------------------|
| `quick` | Header, sections, imports, exports, strings, hashes | Generic strings |
| `full` | Everything in quick + entry-point disassembly + IOC classification | IOC strings: URLs, IPs, domains, registry keys |

---

## Module response

### reverify_binary

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
    "exports": [],
    "strings_total": 312,
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
    "suspicious_strings": [...],
    "suspicious_count": 7
  },
  "misp_event_url": "https://<misp>/events/view/2125"
}
```

### enrich_observable

```json
{
  "type": "hash",
  "value": "f15a57d9...",
  "result": {
    "hash": "f15a57d9...",
    "hashlookup": {
      "found": false,
      "data": null,
      "error": null
    },
    "tlsh": {
      "hash": "T1A7B533...",
      "matches": [{"file": "58f8670e-...", "score": 0}],
      "error": null
    },
    "ssdeep": {
      "hash": "49152:S2SCBk...",
      "matches": [{"file": "58f8670e-...", "score": 100}],
      "error": null
    }
  }
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
