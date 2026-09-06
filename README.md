# flowintel-reverify

FlowIntel-Reverify is a case-centric incident investigation framework that preserves and
analyzes technical evidence, extracts and enriches observables, correlates findings across
cases, supports analyst-controlled assessment, and promotes approved intelligence into MISP.

[FlowIntel](https://github.com/flowintel/flowintel) is the architectural center —
the case is the investigation record. Every module writes its output into the case:
Notes, Files, Links, MISP tab. Evidence comes in through three intake paths; all three
converge into the same observable enrichment, correlation, and assessment model.

---

## Documentation

- **[WORKFLOW.md](docs/WORKFLOW.md)** — per-workflow reference: binary triage, web evidence, log analysis, enrichment, correlation, assessment, API automation
- **[COMPARISON.md](docs/COMPARISON.md)** — Reverify · YARA · Ghidra · angr: what each tool does, where it fits, when to use it
- **[ROADMAP.md](docs/ROADMAP.md)** — what is done and what is being considered next

---

## Architecture

```
                              INCIDENT
                                 │
                                 ▼
                          FLOWINTEL CASE
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
           ▼                     ▼                     ▼
    FILE / BINARY          WEB EVIDENCE         LOG / NETWORK
           │                     │                     │
    reverify_binary         preserve_page        ┌─────┴──────┐
           │                     │         enrich_bulk_ips  parse_auth_log
          YARA                   │               │              │
           │                     │               │              │
           └─────────────────────┴───────────────┴──────────────┘
                                 │
                          CASE FINDINGS
                                 │
                           OBSERVABLES
                                 │
                        enrich_observable
                                 │
                      correlate_observables
                                 │
                        suggest_assessment
                                 │
                  ╔══════════════╧══════════════╗
                  ║        ANALYST GATE         ║
                  ║    (assess_case module)     ║
                  ╚══════════════╤══════════════╝
         ┌──────────────┬────────┴────────┬────────────┐
         ▼              ▼                 ▼            ▼
     confirmed     needs-ghidra       needs-angr  false-positive
         │              │                 │            │
      Approved      Req. Review       Req. Review   Rejected
         │         🔍 MM alert        🐛 MM alert
         │              │                 │
         │           Ghidra             angr
         │          (external)        (external)
         │              └────────┬────────┘
         │                       │
         └───────────────┬───────┘
                         │
                   APPROVED IOC
                         │
                        MISP
                         │
               THREAT INTELLIGENCE
```

**Automation recommends. Analysts conclude.**
Evidence is gathered, observables enriched, signals scored — but no intelligence is
published without a deliberate analyst decision at `assess_case`.

---

## Module categories

### Investigation / evidence modules

These modules intake evidence from a specific incident type and write structured findings
into the case.

| Module | Incident type | What it produces |
|--------|--------------|-----------------|
| `preserve_page` | Web defacement, script injection, XSS | Screenshot (PNG), HTML source, SHA-256 hashes, external resource inventory, Wayback Machine archive — attached to case Files tab and Notes |
| `reverify_binary` | Suspicious files and binaries | Static analysis (file type, hashes, sections, imports, strings, IOCs), YARA rule, MISP draft event, Mattermost alert |
| `enrich_bulk_ips` | DDoS, volumetric network incidents | ASN/country grouping of source IPs, suspicious infrastructure indicators, structured summary note |
| `parse_auth_log` | Account takeover, credential stuffing, brute force | Source IPs by fail count, targeted usernames, user-agent patterns, top-IP enrichment, investigation signals |

### Cross-cutting investigation modules

These modules operate on the findings already in the case — regardless of which intake
path produced them.

| Module | What it does |
|--------|-------------|
| `enrich_observable` | Enriches a single domain, IP, URL, or hash using RDAP, CIRCL Passive DNS, RIPE Stat, Lookyloo, CIRCL hashlookup, and local fuzzy matching |
| `correlate_observables` | Scans all case Notes in this FlowIntel instance for IPs, hashes, and ASNs that appear in multiple cases; creates case links |
| `suggest_assessment` | Scores 16 rule-based signals across all case Notes; outputs a machine recommendation (not a verdict) |
| `assess_case` | Records the analyst's decision, applies a colour-coded tag, updates case status, writes an audit note; `confirmed` publishes the MISP draft; `needs-ghidra` / `needs-angr` send Mattermost escalation alerts |

### External / supporting systems

These run outside FlowIntel. `reverify_binary` creates the MISP draft event; `assess_case`
publishes it when the analyst decides `confirmed`.

| System | Role |
|--------|------|
| YARA | Pattern-match detection against file collections using rules auto-generated by `reverify_binary` |
| Ghidra | Deep manual reverse engineering — triggered by `needs-ghidra` analyst decision |
| angr | Symbolic execution and reachability analysis — triggered by `needs-angr` analyst decision |
| MISP | Threat-intelligence sharing layer; investigation data is published only after analyst approval |
| Mattermost | Collaboration and escalation layer — task notifications, `/flowintel` case creation, escalation alerts |

---

## Key distinctions

These distinctions are enforced throughout the framework:

```
Observable        ≠ IOC
Signal            ≠ Detection
Detection         ≠ Verdict
YARA Match        ≠ Confirmed Malware
Similarity        ≠ Identity
Correlation       ≠ Attribution
Machine Recommendation ≠ Analyst Assessment
```

An observable is a normalized technical entity (IP, domain, hash, URL) extracted from
evidence. It may be enriched, correlated, and eventually promoted to an IOC — but only
after an analyst decision.

---

## Evidence model

A FlowIntel case can contain any combination of:

| Evidence type | Intake module |
|---------------|--------------|
| File or binary | `reverify_binary` |
| Web page state (live) | `preserve_page` |
| Screenshot (PNG) | `preserve_page` |
| HTML source | `preserve_page` |
| Authentication log | `parse_auth_log` |
| Web access log | `parse_auth_log` |
| Network / source-IP dataset | `enrich_bulk_ips` |

Evidence provenance, SHA-256 integrity hashes, and UTC timestamps are recorded where
applicable. **Preserve volatile evidence before remediation.**

---

## Investigation paths

### Binary / malware investigation

```
File upload
    ↓
reverify_binary        ← static analysis, YARA rule, MISP draft event
    ↓
enrich_observable      ← each IP, domain, URL, hash from findings
    ↓
correlate_observables  ← cross-case scan (IPs, hashes, ASNs)
    ↓
suggest_assessment     ← machine recommendation
    ↓
assess_case            ← analyst decision gate
```

### Web incident investigation (defacement, injection, XSS)

```
Compromised page identified
    ↓
preserve_page          ← run FIRST, before the page is restored
    ↓
enrich_observable      ← domain, IP, injected script sources
    ↓
correlate_observables
    ↓
assess_case
```

### DDoS source analysis

```
Source IPs from logs or netflow
    ↓
enrich_bulk_ips        ← ASN/country grouping, suspicious infrastructure signals
    ↓
correlate_observables
    ↓
suggest_assessment
    ↓
assess_case
```

### Account takeover / credential stuffing

```
Authentication or access log
    ↓
parse_auth_log         ← source IPs, fail counts, targeted usernames, UA patterns
    ↓
enrich_bulk_ips        ← (optional) deeper bulk enrichment of attacker IPs
    ↓
correlate_observables
    ↓
assess_case
```

---

## Run Full Pipeline (web UI)

Navigate to **Analyser → Push Case to MISP** (`/reverify/push_misp`), select a case
and file, choose depth, then click **Run Full Pipeline**.

This runs the automated binary investigation sequence in order:

| Step | Module | What it does |
|------|--------|-------------|
| 1 | `reverify_binary` | Static analysis + MISP draft event |
| 2 | `enrich_observable` | Enrich each observable extracted from findings |
| 3 | `correlate_observables` | Cross-case scan for shared observables |
| 4 | `suggest_assessment` | Score 16 signals → machine recommendation |

Each step's result appears as a flash message. The page redirects to the case when done.

**Run Full Pipeline automates investigation preparation, not the analyst's final decision.**
It stops before `assess_case` — the analyst reviews Notes and decides.

---

## Requirements

- [FlowIntel](https://github.com/flowintel/flowintel)
- [MISP](https://github.com/MISP/MISP) instance connected to FlowIntel *(for MISP integration)*
- Python 3.10+
- System library: `libfuzzy-dev` (ssdeep — installed automatically by `install.sh`)
- Chromium (preserve_page — installed automatically by `install.sh` via `playwright install chromium`)

Python dependencies (installed by `install.sh` into the FlowIntel venv):

| Package | Purpose |
|---------|---------|
| `reverify` | Static analysis core for `reverify_binary` |
| `yara-python` | YARA rule validation |
| `python-tlsh` | TLSH fuzzy hashing |
| `ssdeep` | ssdeep fuzzy hashing |
| `pymisp` | MISP event creation and publishing |
| `requests` | HTTP calls to RDAP, RIPE Stat, Lookyloo, Wayback Machine |
| `playwright` | Headless Chromium for `preserve_page` |

---

## Installation

```bash
git clone https://github.com/pakde-semar/flowintel-reverify.git
cd flowintel-reverify

FLOWINTEL_DIR=/opt/flowintel bash install.sh

systemctl restart flowintel
```

`install.sh` installs `libfuzzy-dev` via apt, installs all Python dependencies into the
FlowIntel venv, copies all modules, patches the sidebar and API, and adds Mattermost
config stubs.

```bash
SKIP_PATCH=1 FLOWINTEL_DIR=/opt/flowintel bash install.sh   # skip sidebar patch
SKIP_DEPS=1  FLOWINTEL_DIR=/opt/flowintel bash install.sh   # skip dependency install
```

---

## API quick reference

All module calls follow the same pattern:

```bash
curl -X POST https://<flowintel>/api/case/<case_id>/run_analyze_module \
  -H "X-API-KEY: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"module": "<name>", "payload": {...}}'
```

### preserve_page — web forensic capture

```bash
curl ... -d '{
  "module": "preserve_page",
  "payload": {"url": "https://situs-deface.example.id"}
}'
```

Run before the page is restored. Screenshot and HTML are attached to the case Files tab.

### reverify_binary — binary static analysis

```bash
curl ... -d '{
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

### enrich_bulk_ips — DDoS source IP analysis

```bash
curl ... -d '{
  "module": "enrich_bulk_ips",
  "payload": {
    "ips": ["1.2.3.4", "5.6.7.8"],
    "max_ips": 200
  }
}'
```

Omit `ips` to auto-extract from case Notes.

### parse_auth_log — authentication log investigation

```bash
LOG=$(sudo tail -n 5000 /var/log/auth.log | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
curl ... -d "{\"module\": \"parse_auth_log\", \"payload\": {\"log_text\": $LOG, \"threshold\": 3}}"
```

### enrich_observable — single observable enrichment

```bash
# Hash
curl ... -d '{"module": "enrich_observable", "payload": {"value": "f15a57d9..."}}'
# Domain
curl ... -d '{"module": "enrich_observable", "payload": {"value": "example.com"}}'
# IP
curl ... -d '{"module": "enrich_observable", "payload": {"value": "198.51.100.1"}}'
# URL
curl ... -d '{"module": "enrich_observable", "payload": {"value": "https://example.com/path"}}'
```

### correlate_observables — cross-case correlation

```bash
curl ... -d '{"module": "correlate_observables", "payload": {}}'
```

### suggest_assessment — machine recommendation

```bash
curl ... -d '{"module": "suggest_assessment", "payload": {}}'
```

### assess_case — analyst decision

```bash
curl ... -d '{
  "module": "assess_case",
  "payload": {
    "decision": "confirmed",
    "rationale": "IOCs verified. External script from known malicious domain."
  }
}'
```

---

## Payload reference

### preserve_page

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | string | — | URL to preserve (**required**) |
| `wayback` | boolean | `true` | Submit to Wayback Machine |
| `save_files` | boolean | `true` | Attach screenshot + HTML to case Files tab |

### reverify_binary

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file_path` | string | — | Absolute path to binary on server (**required**) |
| `depth` | `"quick"` \| `"full"` | `"quick"` | Analysis depth |
| `display_name` | string | basename of `file_path` | Filename shown in Notes and MISP |
| `generate_yara` | boolean | `true` | Auto-generate YARA rule |
| `push_to_misp` | boolean | `false` | Create MISP draft event |

**Depth options:**

| Depth | What runs |
|-------|-----------|
| `quick` | Header, sections, imports, exports, strings, hashes |
| `full` | Everything in quick + entry-point disassembly + IOC classification (URLs, IPs, domains, registry keys) |

### enrich_bulk_ips

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ips` | list of strings | auto | IPs to enrich; auto-extracted from case Notes if omitted |
| `max_ips` | integer | `100` | Maximum IPs enriched per run |

Suspicious ASN classifications (Tor-related, bulletproof hosting, known botnet providers)
are **investigation signals**, not definitive attribution.

### parse_auth_log

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `log_text` | string | — | Raw log content (**required**) |
| `log_format` | `"nginx"` \| `"apache"` \| `"auth"` \| `"json"` \| `"auto"` | `"auto"` | Format; auto-detected if `"auto"` |
| `threshold` | integer | `5` | Minimum failed attempts to flag an IP |
| `enrich_top` | integer | `20` | Enrich top N IPs via RDAP/ASN |

Supported log formats:

| Format | Detection basis |
|--------|----------------|
| `nginx` / `apache` | Combined Log Format (IP - - [timestamp] "METHOD path" status ...) |
| `auth` | Linux sshd auth.log — `Failed password for ... from IP` |
| `json` | JSON object per line with `ip`, `status`, `user` / `path` fields |

Failed-attempt counts and Tor/bulletproof ASN signals are **investigation signals**,
not confirmed attack verdicts.

### enrich_observable

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `value` | string | — | Observable to enrich (**required**) |
| `type` | `"domain"` \| `"ip"` \| `"url"` \| `"hash"` | auto-detected | Observable type |
| `corpus_path` | string | `/opt/flowintel/uploads/files/` | Path for TLSH/ssdeep corpus scan |
| `lookyloo_url` | string | `https://lookyloo.circl.lu` | Lookyloo instance for URL capture |

### correlate_observables

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `observables` | list of strings | auto | Values to search for; auto-extracted from Notes if omitted |
| `types` | list | `["ip","hash","asn"]` | Types to auto-extract (domain/URL not currently supported) |
| `create_links` | boolean | `true` | Create FlowIntel case links for matches |
| `min_overlap` | integer | `1` | Minimum shared observables to include a case in results |

### suggest_assessment

No payload required. Reads all current case Notes.

### assess_case

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `decision` | `"confirmed"` \| `"needs-ghidra"` \| `"needs-angr"` \| `"false-positive"` | — | Analyst decision (**required**) |
| `rationale` | string | — | Optional reasoning written to the audit note |

`confirmed` publishes the MISP draft event. `needs-ghidra` and `needs-angr` send a
Mattermost escalation alert to `#flowintel-alerts`.

---

## Intelligence promotion model

```
Raw Evidence
    ↓
Preserved Artifact
    ↓
Deterministic Fact   (hash, file type, string at offset)
    ↓
Observable           (IP, domain, URL, hash — normalized)
    ↓
Enrichment           (reputation, ASN, passive DNS, redirect chain)
    ↓
Signal               (assessment indicator — not a verdict)
    ↓
Correlation          (cross-case match — not attribution)
    ↓
Finding              (all signals in context)
    ↓
Analyst Assessment   (assess_case decision)
    ↓
Approved IOC
    ↓
MISP Publication     (controlled, analyst-approved)
    ↓
Threat Intelligence
```

FlowIntel is the investigation workspace. MISP is the controlled sharing layer.
Investigation data remains private until the analyst explicitly approves publication.

---

## Mattermost integration

### FlowIntel → Mattermost

Configure in `conf/config_module.py`:

```python
MATTERMOST_WEBHOOK_URL = "https://<mattermost>/hooks/<token>"
MATTERMOST_CHANNEL    = "flowintel-alerts"
MATTERMOST_ENABLED    = True
FLOWINTEL_URL         = "https://<flowintel>"
```

Notifications sent:
- Task assignment alerts (notify_user module)
- `needs-ghidra` escalation: 🔍 alert to `#flowintel-alerts`
- `needs-angr` escalation: 🐛 alert to `#flowintel-alerts`

### Mattermost → FlowIntel (slash command)

```
/flowintel Suspicious dropper from HR email
```

Register the slash command in Mattermost:

| Field | Value |
|-------|-------|
| Command | `/flowintel` |
| Request URL | `https://<flowintel>/mattermost/create_case` |
| Method | POST |

```python
FLOWINTEL_API_KEY      = "<flowintel-admin-api-key>"
MATTERMOST_SLASH_TOKEN = "<token-from-mattermost-slash-command>"
```

---

## MISP integration

`reverify_binary` creates a MISP draft event (not published). `assess_case` with
`confirmed` publishes the draft — no intermediate step required.

| Binary type | MISP objects created |
|-------------|---------------------|
| Windows PE | `file` + `pe` + `pe-section` ×N |
| Linux ELF | `file` + `elf` + `elf-section` ×N |
| Mach-O | `file` |
| Raw / script | `file` |

IOC strings are mapped to typed MISP attributes:

| Pattern | MISP attribute type |
|---------|---------------------|
| `http://` / `https://` | `url` |
| IPv4 address | `ip-dst` |
| Domain name | `domain` |
| `HKEY_*` | `regkey` |
| Other | `pattern-in-file` |

MISP credentials are read from the FlowIntel database — no separate configuration.

---

## Post-assessment tools (external)

### Ghidra — triggered by `needs-ghidra`

`assess_case` sets status to **Request Review** and posts a 🔍 alert to
`#flowintel-alerts`. The analyst opens the binary in
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) using the case Notes
as a navigation guide (hashes, suspicious strings + offsets, disassembly).

Ghidra runs externally. When analysis is complete, the analyst adds findings to case
Notes and re-runs `assess_case` with `confirmed` or `false-positive`.

### angr — triggered by `needs-angr`

`assess_case` sets status to **Request Review** and posts a 🐛 alert to
`#flowintel-alerts`. The analyst uses
[angr](https://github.com/angr/angr) for symbolic execution and reachability analysis.

angr runs externally. When done, findings are added to case Notes and `assess_case` is
re-run to close the loop. A native angr FlowIntel module is not currently implemented.

---

## Test without FlowIntel

```bash
cd flowintel-reverify
python tests/test_module.py /bin/ls full
```

---

## License

MIT
