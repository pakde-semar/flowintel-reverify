# Roadmap

## Done

### Binary triage pipeline
- Static analysis via Reverify — file type, architecture, hashes, sections, imports, strings, entry-point disassembly
- YARA rule auto-generation from hashes + IOC strings, saved to case Notes
- MISP event creation with typed objects (`file`, `pe`, `elf`, section objects, IOC attributes)
- MISP → Flowintel case MISP tab auto-sync
- Mattermost notify_user module — task bell notification to `#flowintel-alerts`
- Mattermost slash command `/flowintel <title>` → create Flowintel case

---

## Considering

### Domain / IP / URL / hash enrichment pipeline

A second pipeline running alongside the binary pipeline — for observable indicators
that are not binary files.

| Observable | Potential enrichment sources |
|------------|------------------------------|
| Domain | WHOIS, passive DNS, reputation |
| IP | Geolocation, ASN, blacklist |
| URL | Redirect chain, resolve, screenshot |
| Hash | VirusTotal, MalwareBazaar, cross-reference to binary pipeline |

**Goal:** make flowintel-reverify an **Incident Response enrichment framework** —
a single entry point for all indicator types, not only binaries.

Tools and integration mechanism inside Flowintel are still being evaluated.
