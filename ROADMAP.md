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
                         ENRICHMENT
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
          domain/IP           URL               hash
             │                 │                 │
          RDAP/DNS          Lookyloo        CIRCL lookup
          ASN/PDNS          redirects       TLSH/ssdeep
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                         RELATIONSHIPS
                               │
                    shared IPs, ASNs, hashes
                               │
                               ▼
                       LOCAL CORRELATION
                               │
                    cross-case scan + case links
                               │
                               ▼
                       ANALYST ASSESSMENT
                               │
                   ┌───────────┴───────────┐
                   ▼                       ▼
              insufficient              confirmed/
                   │                   high-confidence
                   ▼                       │
                GHIDRA                     │
                   │                       │
              need proof?                  │
                   │                       │
                   ▼                       │
                  angr                     │
                   │                       │
                   └──────────┬────────────┘
                              ▼
                       APPROVED IOC
                              │
                              ▼
                             MISP
                              │
                         correlation
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
                  case               campaign
                    │                   │
                    └──────────┬────────┘
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

### Local correlation (`correlate_observables`)
- Auto-extracts IPs, hashes, ASNs from current case Notes
- Scans Notes of all other cases for matching values
- Creates `Case_Link_Case` records for matching cases
- Writes correlation summary to case Notes

---

## In progress / next

### Analyst assessment gate

Two paths after findings are reviewed:

- **Confirmed / high-confidence** → approved IOC → MISP
- **Insufficient** → escalate to Ghidra (deep manual analysis) → angr (proof of exploitability) → approved IOC → MISP

### MISP correlation → mitigation

MISP correlates approved IOCs across cases and campaigns.
Output: targeted mitigation or advisory per case / campaign.

---

## Considering

- Domain/URL in local correlation (currently IP, hash, ASN only — domains produce too many false positives from free text)
- Lookyloo private instance on dedicated VM (currently using CIRCL public — slow, no privacy)
- angr integration for proof-of-exploitability after Ghidra triage
- Relationship graph visualization inside Flowintel case (linked cases + shared observables)
