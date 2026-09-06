# Roadmap

## Target architecture

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
                      OBSERVABLE EXTRACTION
                       normalize + validate
                                 │
                        enrich_observable
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
           domain/IP            URL               hash
              │                  │                  │
           RDAP/DNS           Lookyloo         CIRCL lookup
           ASN/PDNS           redirects        TLSH/ssdeep
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                    ⚠️  per-observable signals
                                 │
                      correlate_observables
                                 │
                  cross-case scan: IPs, hashes, ASNs
                  case links for overlapping cases
                                 │
                       suggest_assessment
                                 │
                  score 16 signals across Notes
                  → scored recommendation + reasoning
                                 │
                  ╔══════════════╧══════════════╗
                  ║        ANALYST GATE         ║
                  ║       [assess_case]         ║
                  ╚══════════════╤══════════════╝
         ┌──────────────┬────────┴────────┬────────────┐
         ▼              ▼                 ▼            ▼
     confirmed     needs-ghidra       needs-angr  false-positive
         │              │                 │            │
      Approved      Req. Review       Req. Review   Rejected
      tag: ✓        tag: 🔍           tag: 🐛       tag: ✗
         │              │                 │
         │           Ghidra             angr
         │         (external)         (external)
         │         decompile          symbolic exec
         │         flow analysis      constraint solve
         │              │                 │
         │              └────────┬────────┘
         │                       │
         └───────────────┬───────┘
                         │
                   APPROVED IOC
                         │
                        MISP
                    (draft → publish)
                         │
                 THREAT INTELLIGENCE
```

**Automation recommends. Analysts conclude.**
Investigation data remains private in FlowIntel until the analyst explicitly publishes
to MISP at the `confirmed` decision.

---

## Done

### Investigation / evidence modules

#### FlowIntel case as investigation container
- FlowIntel case is the investigation record — Notes, Files, Links, Tasks, MISP tab
- File upload with automatic hash computation (MD5, SHA1, SHA256)

#### Web evidence — forensic page preservation (`preserve_page`)
- Playwright headless Chromium — screenshot (PNG, full page) + HTML source capture
- SHA-256 integrity hashes for screenshot and HTML (tamper-evident evidence)
- External resource inventory — all scripts, iframes, and images loaded from outside the page domain
- Full network request log grouped by domain
- Wayback Machine submission (optional, default on)
- Screenshot and HTML attached to case Files tab; full report written to Notes
- **Preserve before remediation** — capture must happen before the page is restored
- Primary incident types: web defacement, script injection, XSS, compromised pages

#### Binary evidence — static analysis (`reverify_binary` + YARA)
- Static analysis: file type, architecture, sections, imports, strings, entry-point disassembly
- Deterministic hashes (MD5, SHA1, SHA256), IOC extraction (URLs, IPs, domains, registry keys)
- YARA rule auto-generation from hashes + IOC strings, saved to case Notes
- Analyst reviews and tunes the rule before deployment (YARA match ≠ confirmed malware)
- MISP draft event creation with typed objects (`file`, `pe`, `elf`, section objects, IOC attributes)

#### Network / DDoS evidence — bulk IP analysis (`enrich_bulk_ips`)
- Accepts an explicit IP list or auto-extracts from case Notes via regex
- Enriches each IP via RDAP (network/country) + RIPE Stat (ASN/holder)
- Groups by ASN and country; flags suspicious infrastructure indicators
  (Tor-related, bulletproof hosting, known botnet providers) — **signals, not attribution**
- Writes structured summary note: top ASNs table, country distribution, suspicious IP list
- Capped at `max_ips` (default 100) to keep per-run latency predictable

#### Log / ATO evidence — authentication log analysis (`parse_auth_log`)
- Parses nginx/apache combined log format, Linux sshd `auth.log`, and JSON-per-line logs
- Auto-detects format; explicit override via `log_format` payload field
- Extracts source IPs by fail count, targeted usernames, user-agent variants
- Flags IPs above `threshold` (default: 5 failed attempts) — **investigation signal, not verdict**
- Enriches top N attacker IPs via RDAP/ASN (`enrich_top` default: 20)
- Assessment signals: many IPs above threshold, large targeted-username set, Tor/bulletproof origins
- All signals are **investigation indicators** — a high fail count does not confirm compromise

### Cross-cutting investigation modules

#### Observable enrichment (`enrich_observable`)

| Observable | Sources |
|------------|---------|
| Domain / IP | RDAP, CIRCL Passive DNS, RIPE Stat ASN |
| URL | Lookyloo (CIRCL public instance) — redirect chain, IPs contacted, screenshot |
| Hash | CIRCL hashlookup (KnownMalicious) + TLSH/ssdeep local corpus fuzzy match |

Per-observable assessment signals appended to each enrichment note.
Signals include: KnownMalicious, domain age, no PDNS history, long redirect chain, fuzzy-only match.

#### Local correlation (`correlate_observables`)
- Auto-extracts IPs, hashes, ASNs from current case Notes
- Scans Notes of all other cases for matching values (domain/URL not currently supported)
- Creates `Case_Link_Case` records for overlapping cases
- Writes correlation summary to case Notes
- Shared observable = correlation signal — **not the same as campaign attribution**

#### Assessment gate (`suggest_assessment` + `assess_case`)
- `suggest_assessment`: scans all case Notes, scores 16 signals (entropy, injection APIs,
  KNOWN MALICIOUS, vuln keywords, correlation hits), outputs scored recommendation table
  — **machine recommendation only, never a final verdict**
- `assess_case`: records analyst decision (confirmed / needs-ghidra / needs-angr /
  false-positive), applies colour-coded tag, updates case status, writes timestamped audit note
- Tags auto-created on first use; previous assessment tag replaced on decision change
- `confirmed` publishes the MISP draft event (via PyMISP.publish); event ID resolved from
  `Case_Connector_Instance` or extracted from case Notes

### Evidence distribution and collaboration
- MISP event creation (draft) from `reverify_binary`; MISP tab auto-sync back to FlowIntel case
- MISP publication from `assess_case` when decision is `confirmed`
- Mattermost notify_user module — task bell notification to `#flowintel-alerts`
- Mattermost slash command `/flowintel <title>` → create FlowIntel case
- Mattermost escalation alerts: 🔍 `needs-ghidra`, 🐛 `needs-angr`
- **Run Full Pipeline** button at `/reverify/push_misp` — runs reverify_binary →
  enrich_observable → correlate_observables → suggest_assessment in sequence;
  **automates investigation preparation, not the analyst's final decision** (stops before assess_case)

---

## In progress / next

### MISP correlation → mitigation

MISP correlates approved IOCs across cases and campaigns.
Output: targeted mitigation or advisory per case / campaign.

---

## Post-assessment tools (external, no Flowintel module required)

These tools are triggered by `assess_case` decisions. They run outside FlowIntel —
findings are added to case Notes manually and `assess_case` is re-run to close the loop.

### Ghidra — triggered by `needs-ghidra`

Full reverse engineering suite. The analyst opens the binary in Ghidra using the
`reverify_binary` output (hashes, suspicious strings + offsets, entry-point disassembly)
as a navigation guide. When analysis is complete, re-run `assess_case` with
`confirmed` or `needs-angr`.

### angr — triggered by `needs-angr`

Symbolic execution framework. Used after Ghidra has confirmed a potential vulnerability.
angr explores reachable code paths with Z3 constraint solving to determine
exploitability. When done, re-run `assess_case` with `confirmed`.

A native angr FlowIntel module is not currently implemented.

---

## Considering

- Domain and URL in local correlation (currently IP, hash, ASN only — free-text domains produce too many false positives)
- Lookyloo private instance on a dedicated VM (currently using CIRCL public — slow, no privacy)
- angr FlowIntel module — automated symbolic execution triggered from `needs-angr`
  (high complexity; resource-intensive and binary-specific)
- Relationship graph visualization inside FlowIntel case (linked cases + shared observables)
