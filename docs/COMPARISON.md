# Tool Comparisons

This page situates flowintel-reverify within a broader malware analysis ecosystem.
Each tool occupies a distinct role — understanding where one ends and another begins
determines how to build an effective pipeline, not which tool to pick over another.

---

## 1. Ghidra vs Reverify

[Ghidra](https://github.com/NationalSecurityAgency/ghidra) is a full reverse engineering
suite developed by the NSA. It provides a GUI environment for deep, manual analysis of
a single binary.

### Feature comparison

| Aspect | Ghidra | Reverify |
|--------|--------|----------|
| **Type** | Full RE suite | Static analysis toolkit |
| **Interface** | Desktop GUI (Java) | CLI / Python library / API |
| **Disassembly** | Full binary — all functions, call graph, cross-references | Entry point (configurable depth) |
| **Decompiler** | Yes — C pseudocode output | No |
| **String extraction** | Yes | Yes |
| **Header parsing** | Yes — PE, ELF, Mach-O, and more | Yes — PE, ELF, Mach-O |
| **Import / export listing** | Yes | Yes |
| **Hash computation** | No (external tool required) | Yes — MD5, SHA1, SHA256 |
| **Scripting** | Java / Python via Ghidra API | Native Python library |
| **Pipeline automation** | Possible via headless mode — complex setup | Designed for it |
| **Resource usage** | Heavy — 4 GB+ RAM, JDK required | Lightweight — pure Python |
| **Flowintel / MISP integration** | None built-in | Native |
| **Best for** | Deep manual analysis of one binary | Automated triage across many files |

### When to use Ghidra

- A human analyst needs to deeply understand what a binary does
- You need to decompile obfuscated or packed code into readable C pseudocode
- You are tracing execution flow or recovering a custom protocol
- Reverify flagged suspicious indicators that warrant hours of manual investigation

### When to use Reverify

- You need fast, automated triage as the first stage of the pipeline
- You are populating a Flowintel case or MISP event with structured findings
- You need deterministic, reproducible output with no interpretation layer
- Your server has limited resources (no JDK, limited RAM)

---

## 2. angr vs Reverify

[angr](https://github.com/angr/angr) is a binary analysis framework from UC Santa Barbara.
Its core capability is symbolic execution — running a binary with symbolic variables, then
using a Z3 SMT solver to reason about all possible execution paths simultaneously.

### Feature comparison

| Aspect | angr | Reverify |
|--------|------|----------|
| **Type** | Binary analysis framework | Static analysis toolkit |
| **Core technique** | Symbolic / concolic execution | Static parsing |
| **Disassembly** | Full — all reachable code paths | Entry point (configurable depth) |
| **Symbolic execution** | Yes | No |
| **Constraint solving** | Yes — Z3 SMT solver | No |
| **Control flow graph** | Yes — full CFG recovery | No |
| **Vulnerability discovery** | Yes | No |
| **Exploit generation** | Yes (via angrop, rex) | No |
| **Hash computation** | No | Yes — MD5, SHA1, SHA256 |
| **String extraction** | No | Yes |
| **IOC classification** | No | Yes |
| **Pipeline automation** | Python library | Python library / CLI |
| **Resource usage** | Heavy — symbolic execution is CPU/RAM intensive | Lightweight |
| **Speed on a typical binary** | Minutes to hours | Seconds |
| **Flowintel / MISP integration** | None built-in | Native |
| **Best for** | Vulnerability research, CTF, exploit development | Automated triage and enrichment |

### When to use angr

- You need to prove whether a binary contains an exploitable vulnerability
- You are solving a CTF challenge that requires symbolic reasoning
- You need to find what exact input drives execution to a specific code path
- You are doing advanced security research on a specific binary

### When to use Reverify

- You need fast, automated triage as the first stage of the pipeline
- You are feeding structured findings into Flowintel, TheHive, or a SOAR platform
- You need deterministic output without SMT solver overhead
- Your pipeline must complete in seconds, not hours

---

## 3. YARA vs Reverify

[YARA](https://github.com/VirusTotal/yara) is a pattern-matching engine from VirusTotal.
It scans files against user-written rules to detect known malware families or behaviors.

### Feature comparison

| Aspect | YARA | Reverify |
|--------|------|----------|
| **Type** | Pattern-matching / signature engine | Static analysis toolkit |
| **Core technique** | Rule-based scanning — byte patterns, strings, conditions | Binary parsing — headers, sections, imports, disassembly |
| **Requires prior knowledge?** | Yes — useless without rules | No — analyzes any unknown file |
| **Output** | Match / No match | Structured findings — type, hashes, IOCs, strings |
| **Hash computation** | No | Yes — MD5, SHA1, SHA256 |
| **String extraction** | No (strings are rule inputs, not outputs) | Yes |
| **IOC classification** | No | Yes — URLs, IPs, domains, registry keys |
| **Header parsing** | No | Yes |
| **Speed** | Very fast (sub-second per file) | Fast (seconds per file) |
| **Flowintel / MISP integration** | None built-in | Native |
| **Best for** | Detecting known patterns across a file collection | Extracting unknown structure from a single sample |

### How they work together in this pipeline

YARA and Reverify are **complementary** — Reverify extracts, YARA detects.
In this pipeline, Reverify generates the YARA rule automatically from its own findings:

```
Incoming unknown binary
        │
        ▼
┌──────────────────────────────────────────────┐
│  Reverify  (Stage 1 + Stage 2)               │
│                                              │
│  • Extract hashes, strings, IOCs             │
│  • Classify: URLs, IPs, domains, regkeys     │
│  • Build YARA rule from hashes + IOC strings │
│  • Save rule to case Notes                   │
└──────────────────┬───────────────────────────┘
                   │  analyst reviews and tunes the rule
                   ▼
┌──────────────────────────────────────────────┐
│  YARA scan  (sub-second per file)            │
│                                              │
│  • Scan file collection for the new rule     │
│  • Detect other variants of the same family  │
└──────────────────────────────────────────────┘
```

The analyst receives a ready-to-deploy rule. They tune the condition
(e.g. `2 of ($s*)` instead of `any of ($s*)`) before scanning at scale.

---

## 4. Observable enrichment sources

The `enrich_observable` module extends the pipeline beyond binary analysis to cover
any IOC extracted from triage findings.

### CIRCL hashlookup vs local corpus fuzzy matching

| Aspect | CIRCL hashlookup | TLSH + ssdeep (local corpus) |
|--------|-----------------|------------------------------|
| **Source** | Public database (NSRL + malshare + others) | Your own Flowintel uploads |
| **What it tells you** | Is this hash known? Known malicious? | Are there structurally similar files in your corpus? |
| **Requires file on disk?** | No — hash lookup only | Yes — file must be in corpus |
| **API key required?** | No | No |
| **Coverage** | Broad (millions of known files) | Narrow (only files you have uploaded) |
| **Best for** | First-pass reputation check on any hash | Detecting recompiled variants across your own sample set |

Both run automatically when the `hash` type is enriched. If the hash is not in CIRCL hashlookup
(novel or private malware), fuzzy matching still runs against the local corpus.

### URL enrichment — Lookyloo

[Lookyloo](https://lookyloo.circl.lu) captures a full browser session for a URL — recording
the redirect chain, all IPs contacted, and a screenshot. This is used for URLs extracted from
binary analysis or supplied directly.

The pipeline uses the CIRCL public instance (no authentication, no installation required).
If a capture times out, the UUID and capture link are saved to the note so the analyst can
check later.

---

## 5. All tools together

Each tool occupies a distinct stage in the investigation lifecycle:

```
Incoming binary
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  Reverify  (automated, seconds)                         │
│                                                         │
│  Stage 1: file type, architecture, hashes,              │
│           sections, imports, strings, IOCs              │
│  Stage 2: YARA rule from hashes + IOC strings           │
│  Stage 3: MISP event + Flowintel MISP tab               │
└──────────────────────┬──────────────────────────────────┘
                       │  IOCs extracted (domains, IPs, URLs, hashes)
                       ▼
┌─────────────────────────────────────────────────────────┐
│  enrich_observable  (automated, seconds)                │
│                                                         │
│  Domain → RDAP + CIRCL Passive DNS                      │
│  IP     → RDAP + RIPE Stat ASN                          │
│  URL    → Lookyloo redirect chain + screenshot          │
│  Hash   → CIRCL hashlookup + TLSH/ssdeep corpus        │
└──────────────────────┬──────────────────────────────────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
┌────────────────────┐   ┌────────────────────────────────┐
│  YARA  (seconds)   │   │  Ghidra  (hours)               │
│                    │   │                                │
│  Hunt for variants │   │  Deep manual analysis          │
│  across file sets  │   │  Decompile, trace flow,        │
│  using the         │   │  confirm IOCs from Reverify    │
│  generated rule    │   │                                │
└────────────────────┘   └──────────────────┬─────────────┘
                                            │
                                            │  exploitability needed?
                                            ▼
                         ┌────────────────────────────────┐
                         │  angr  (hours to days)         │
                         │                                │
                         │  Symbolic execution            │
                         │  Constraint solving via Z3     │
                         │  Exploit / PoC generation      │
                         └────────────────────────────────┘
```

| Tool | Question it answers | Time | Entry point |
|------|---------------------|------|-------------|
| **Reverify** | *What is this file, and what does it contain?* | Seconds | Unknown file, no prior knowledge |
| **enrich_observable** | *Are these IOCs known? What do they resolve to?* | Seconds | IOCs from triage or supplied directly |
| **YARA** | *How many other files match this pattern?* | Sub-second | Known IOCs or generated rule |
| **Ghidra** | *What does this binary do?* | Hours | Reverify flagged it as suspicious |
| **angr** | *Can this binary be exploited, and how?* | Hours – days | Ghidra confirmed a vulnerability |

---

## Summary

> Use **Reverify** to triage an unknown file and generate structured evidence — hashes, IOCs, a YARA rule — in seconds.
>
> Use **enrich_observable** to look up every IOC from triage against open sources — reputation, passive DNS, redirect chains, fuzzy matches — without leaving Flowintel.
>
> Use **YARA** to hunt for variants across a file collection using the rule Reverify produced.
>
> Use **Ghidra** to understand what a confirmed suspicious binary actually does.
>
> Use **angr** to prove whether a binary can be exploited and to generate a proof of concept.
