# Roadmap

## Target architecture

```
                         FLOWINTEL CASE
                               │
                               ▼
                         EVIDENCE INTAKE
                               │
                     preserve + hash
                               │
                               ▼
                            ARTIFACT
                               │
                     fingerprint / metadata
                               │
                ┌──────────────┴───────────────┐
                ▼                              ▼
            REVERIFY                         YARA
         deterministic facts             detections
                │                              │
                └──────────────┬───────────────┘
                               ▼
                        TRIAGE FINDINGS
                               │
                               ▼
                     OBSERVABLE EXTRACTION
                               │
                    normalize + validate
                               │
                               ▼
                    ENRICHMENT  [enrich_observable]
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
          domain/IP           URL               hash
             │                 │                 │
          RDAP/DNS          Lookyloo        CIRCL lookup
          ASN/PDNS          redirects       TLSH/ssdeep
             │                 │                 │
             └─────────────────┼─────────────────┘
                               │
                  ⚠️  per-observable signals
                      appended to each note
                               │
                               ▼
                    RELATIONSHIPS  [correlate_observables]
                               │
                    cross-case scan + case links
                    shared IPs, ASNs, hashes
                               │
                               ▼
                ASSESSMENT SUGGESTION  [suggest_assessment]
                               │
                    score 16 rules across Notes:
                    entropy · injection APIs ·
                    KNOWN MALICIOUS · vuln keywords
                    → scored table + reasoning
                               │
                               ▼
                  ANALYST DECISION  [assess_case]
                               │
          ┌────────────┬────────┴────────┬────────────┐
          ▼            ▼                 ▼            ▼
      confirmed   needs-ghidra      needs-angr  false-positive
          │            │                 │            │
       Approved    Req. Review       Req. Review   Rejected
       tag: ✓      tag: 🔍           tag: 🐛       tag: ✗
          │            │                 │
          │          GHIDRA            angr
          │       deep manual      symbolic exec
          │       decompile +      constraint solve
          │       flow analysis    exploit / PoC
          │            │                 │
          │            └────────┬────────┘
          │                     │
          └─────────────┬───────┘
                        ▼
                   APPROVED IOC
                        │
                        ▼
                       MISP
                        │
                    correlation
                        │
               ┌────────┴────────┐
               ▼                 ▼
             case            campaign
               │                 │
               └────────┬────────┘
                        ▼
                  mitigation /
                    advisory
```

---

## Done

### Evidence intake
- Flowintel case as the container for all evidence and findings
- File upload with automatic hash computation (MD5, SHA1, SHA256)

### Binary analysis (Reverify + YARA)
- Static analysis — file type, architecture, sections, imports, strings, entry-point disassembly
- YARA rule auto-generation from hashes + IOC strings, saved to case Notes
- Analyst reviews and tunes the rule before deployment

### Evidence distribution
- MISP event creation with typed objects (`file`, `pe`, `elf`, section objects, IOC attributes)
- MISP → Flowintel case MISP tab auto-sync
- Mattermost notify_user module — task bell notification to `#flowintel-alerts`
- Mattermost slash command `/flowintel <title>` → create Flowintel case

### Observable enrichment (`enrich_observable`)

| Observable | Sources | Tools |
|------------|---------|-------|
| Domain / IP | RDAP, CIRCL passive DNS, RIPE Stat ASN | — |
| URL | Redirect chain, screenshot | Lookyloo (CIRCL public) |
| Hash | CIRCL hashlookup (KnownMalicious) + local corpus fuzzy match | TLSH, ssdeep |

Per-observable **assessment signals** appended to each enrichment note (KnownMalicious, domain age,
no PDNS, long redirect chain, fuzzy-only match, etc.).

### Local correlation (`correlate_observables`)
- Auto-extracts IPs, hashes, ASNs from current case Notes
- Scans Notes of all other cases for matching values
- Creates `Case_Link_Case` records for matching cases
- Writes correlation summary to case Notes

### Assessment gate (`suggest_assessment` + `assess_case`)
- `suggest_assessment`: scans all case Notes, scores 16 rules (entropy, injection APIs, KNOWN MALICIOUS,
  vuln keywords, correlation hits), outputs scored recommendation table with reasoning
- `assess_case`: records analyst decision (confirmed / needs-ghidra / needs-angr / false-positive),
  applies custom tag (colour-coded), updates case status, writes timestamped audit note
- Custom tags auto-created on first use; previous assessment tag replaced on decision change
- `confirmed` decision publishes the MISP draft event automatically (via `PyMISP.publish`);
  event ID resolved from `Case_Connector_Instance` or extracted from case Notes

---

## In progress / next

### MISP correlation → mitigation

MISP correlates approved IOCs across cases and campaigns.
Output: targeted mitigation or advisory per case / campaign.

---

## Post-assessment tools (external, no module required)

These tools are triggered by `assess_case` decisions. They run outside Flowintel —
findings are added to case Notes manually and `assess_case` is re-run to close the loop.

### Ghidra — triggered by `needs-ghidra`

Full reverse engineering suite. The analyst opens the binary in Ghidra using the
`reverify_binary` output (hashes, suspicious strings + offsets, entry-point disassembly)
as a navigation guide. When analysis is complete, re-run `assess_case` with
`confirmed` or `needs-angr`.

### angr — triggered by `needs-angr`

Symbolic execution framework. Used after Ghidra has confirmed a potential vulnerability.
angr explores all reachable code paths with Z3 constraint solving to determine
exploitability and generate a PoC input. When done, re-run `assess_case` with `confirmed`.

---

## Considering

- Domain/URL in local correlation (currently IP, hash, ASN only — domains produce too many false positives from free text)
- Lookyloo private instance on dedicated VM (currently using CIRCL public — slow, no privacy)
- angr Flowintel module — automated angr analysis triggered from the `needs-angr` decision
  (high complexity; angr symbolic execution is resource-intensive and binary-specific)
- Relationship graph visualization inside Flowintel case (linked cases + shared observables)
