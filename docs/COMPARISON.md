# Reverify — Tool Comparisons

Reverify is a lightweight static analysis toolkit designed for automated triage.
This page compares it against two widely-used tools — **Ghidra** and **angr** —
to clarify where each one belongs in a binary analysis workflow.

---

## 1. Ghidra vs Reverify

[Ghidra](https://github.com/NationalSecurityAgency/ghidra) is a full reverse engineering
suite developed by the NSA. It provides a GUI-based environment for deep, manual analysis.

### Feature comparison

| Aspect | Ghidra | Reverify |
|--------|--------|----------|
| **Type** | Full reverse engineering suite | Lightweight analysis toolkit |
| **Developed by** | NSA (open source) | Independent (open source) |
| **Interface** | Desktop GUI (Java) | CLI / Python library / API |
| **Disassembly** | Full binary — all functions, call graph, cross-references | Entry point (configurable depth) |
| **Decompiler** | Yes — C pseudocode output | No |
| **String extraction** | Yes | Yes |
| **Header parsing** | Yes — PE, ELF, Mach-O, and more | Yes — PE, ELF, Mach-O |
| **Import / export listing** | Yes | Yes |
| **Hash computation** | No (requires external tool) | Yes — MD5, SHA1, SHA256 |
| **Scripting** | Java / Python via Ghidra API | Native Python library |
| **Automation / pipeline** | Possible via headless mode — complex setup | Designed for it — `import reverify` |
| **Resource usage** | Heavy — 4 GB+ RAM, JDK required | Lightweight — pure Python + optional lief |
| **Flowintel / MISP integration** | None built-in | Native — push findings as MISP objects |
| **Anti-hallucination design** | Not applicable | Core principle — every claim verified against raw bytes |
| **Learning curve** | High | Low |
| **Best for** | Deep manual analysis | Automated triage and enrichment |

### When to use Ghidra

- A human analyst needs to deeply understand what a binary does
- You need to decompile obfuscated or packed code into readable C pseudocode
- You are tracing execution flow, patching a binary, or recovering a custom protocol
- The binary warrants hours of manual investigation

### When to use Reverify

- You need fast, automated triage across many files
- You are enriching a case management or SOAR platform (Flowintel, TheHive, etc.)
- You are building a pipeline that pushes structured findings to MISP automatically
- You need deterministic, reproducible output with no interpretation layer
- Your server has limited resources (no JDK, limited RAM)

---

## 2. angr vs Reverify

[angr](https://github.com/angr/angr) is a binary analysis framework developed at
UC Santa Barbara (UCSB). Its core capability is **symbolic execution** — running a binary
with mathematical (symbolic) variables, then using a Z3 SMT solver to reason about
all possible execution paths simultaneously.

### Feature comparison

| Aspect | angr | Reverify |
|--------|------|----------|
| **Type** | Binary analysis framework | Lightweight analysis toolkit |
| **Developed by** | UC Santa Barbara (UCSB) | Independent (open source) |
| **Core technique** | Symbolic / concolic execution | Static parsing |
| **Disassembly** | Full — all reachable code paths | Entry point (configurable depth) |
| **Decompiler** | No | No |
| **Symbolic execution** | Yes — variables carry symbolic constraints | No |
| **Constraint solving** | Yes — Z3 SMT solver built in | No |
| **Control flow graph** | Yes — full CFG recovery | No |
| **Data flow analysis** | Yes | No |
| **Vulnerability discovery** | Yes — find exploitable paths automatically | No |
| **Exploit generation** | Yes (via angrop, rex) | No |
| **Header parsing** | Yes (via CLE loader) | Yes — PE, ELF, Mach-O |
| **Hash computation** | No | Yes — MD5, SHA1, SHA256 |
| **String extraction** | No | Yes |
| **Suspicious string detection** | No | Yes |
| **Supported architectures** | x86, x86\_64, ARM, AArch64, MIPS, PPC, and more | x86, x86\_64, ARM, AArch64 |
| **Interface** | Python library | Python library / CLI |
| **Resource usage** | Heavy — symbolic execution is CPU/RAM intensive | Lightweight — runs on minimal hardware |
| **Speed on a typical binary** | Minutes to hours | Seconds |
| **Learning curve** | Very high | Low |
| **Flowintel / MISP integration** | None built-in | Native |
| **Best for** | Vulnerability research, CTF, exploit development | Automated triage and enrichment |

### When to use angr

- You need to prove whether a binary contains an exploitable vulnerability
- You are solving a CTF challenge that requires symbolic reasoning
- You need to find what exact input drives execution to a specific code path
- You are doing academic or advanced security research on a specific binary
- You have hours or days to spend on a single sample

### When to use Reverify

- You need fast, automated triage across many files
- You are feeding structured findings into Flowintel, TheHive, or a SOAR platform
- You need deterministic, reproducible output without an SMT solver overhead
- You are enriching [MISP](https://github.com/MISP/MISP) events automatically
- Your pipeline must complete in seconds, not hours

---

## 3. All three together (Reverify · Ghidra · angr)

Each tool occupies a distinct tier in a binary analysis pipeline:

```
Incoming binary
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  Reverify  (automated, seconds)                         │
│                                                         │
│  • File type, architecture, hashes                      │
│  • Sections, imports, exports                           │
│  • String extraction + suspicious string scan           │
│  • Entry-point disassembly (full mode)                  │
│                                                         │
│  → Flowintel case Notes (Markdown)                      │
│  → MISP event: file / pe / elf + section objects        │
│  → Flowintel MISP tab: synced automatically             │
└─────────────────────────────────────────────────────────┘
      │
      │  suspicious imports / strings? escalate to analyst
      ▼
┌─────────────────────────────────────────────────────────┐
│  Ghidra  (manual, hours)                                │
│                                                         │
│  • Full disassembly of all functions                    │
│  • Decompile to C pseudocode                            │
│  • Trace execution flow, recover custom protocols       │
│  • Confirm and refine IOCs found by Reverify            │
└─────────────────────────────────────────────────────────┘
      │
      │  need to prove exploitability?
      ▼
┌─────────────────────────────────────────────────────────┐
│  angr  (research-grade, hours to days)                  │
│                                                         │
│  • Symbolic execution across all code paths             │
│  • Constraint solving via Z3 SMT solver                 │
│  • Find exact input that triggers a vulnerability       │
│  • Automatic exploit / PoC generation (angrop, rex)     │
└─────────────────────────────────────────────────────────┘
```

| Tool | Question it answers | Time | Skill required |
|------|---------------------|------|----------------|
| **Reverify** | *What is this file?* | Seconds | Low |
| **Ghidra** | *What does this binary do?* | Hours | High |
| **angr** | *Can this binary be exploited, and how?* | Hours – days | Very high |

See [Section 5](#5-all-four-together) for the full four-tool comparison including YARA.

---

## 4. YARA vs Reverify

[YARA](https://github.com/VirusTotal/yara) is a pattern-matching engine developed at VirusTotal.
It scans files against user-written rules (signatures) to detect known malware families or behaviors.

### Feature comparison

| Aspect | YARA | Reverify |
|--------|------|----------|
| **Type** | Pattern-matching / signature engine | Static analysis toolkit |
| **Developed by** | VirusTotal (open source) | Independent (open source) |
| **Core technique** | Rule-based scanning — byte patterns, strings, conditions | Binary parsing — headers, sections, imports, disassembly |
| **Requires rules?** | Yes — useless without rules | No — analyzes any file immediately |
| **Output** | Match / No match — "file matches rule Mirai.v2" | Structured findings — type, architecture, hashes, strings, IOCs |
| **False positives** | Depends on rule quality | None — reports only facts from bytes |
| **Hash computation** | No | Yes — MD5, SHA1, SHA256 |
| **String extraction** | No (strings are inputs to rules, not outputs) | Yes |
| **Disassembly** | No | Yes — entry-point disasm (full mode) |
| **Header parsing** | No | Yes — PE, ELF, Mach-O |
| **Automation / pipeline** | Yes — CLI and library | Yes — designed for it |
| **Speed** | Very fast (sub-second) | Fast (seconds) |
| **Flowintel / MISP integration** | None built-in | Native |
| **Best for** | Detecting known malware across a file collection | Extracting unknown structure from a single sample |

### When to use YARA

- You have an existing rule set and want to scan a collection of files for known malware
- You want to detect variants of a known family across thousands of samples
- You need to write signatures from IOCs found during manual analysis
- You are running automated scanning on incoming files at scale

### When to use Reverify

- You have an unknown file and need to understand what it is
- You are extracting IOCs (hashes, strings, suspicious patterns) to then write YARA rules from
- You are feeding structured findings into Flowintel, TheHive, or MISP automatically
- You need deterministic output without any prior knowledge of the file

### How they work together

YARA and Reverify are **complementary, not competing**:

```
Incoming unknown binary
        │
        ▼
┌──────────────────────────────────────────────┐
│  Reverify  (seconds)                         │
│                                              │
│  • Extract hashes, strings, structure        │
│  • Identify suspicious patterns and IOCs     │
│  • Push to MISP / Flowintel automatically    │
└──────────────────┬───────────────────────────┘
                   │
                   │  use findings to
                   ▼
┌──────────────────────────────────────────────┐
│  Write YARA rule from Reverify findings      │
│                                              │
│  rule SuspiciousDropper {                    │
│    strings:                                  │
│      $s1 = "CreateRemoteThread"              │
│      $s2 = "http://malicious.example.com"    │
│    condition: all of them                    │
│  }                                           │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  YARA scan  (sub-second per file)            │
│                                              │
│  • Scan file collection for the new rule     │
│  • Detect other variants of the same family  │
└──────────────────────────────────────────────┘
```

---

## 5. All four together

| Tool | Question it answers | Time | Skill required |
|------|---------------------|------|----------------|
| **Reverify** | *What is this file?* | Seconds | Low |
| **YARA** | *How many other files match this pattern?* | Sub-second | Medium (rule writing) |
| **Ghidra** | *What does this binary do?* | Hours | High |
| **angr** | *Can this binary be exploited, and how?* | Hours – days | Very high |

---

## Summary

> Use **Reverify** to triage at scale and feed your platforms automatically.
> Use **YARA** to detect known patterns and hunt for variants across a file collection.
> Use **Ghidra** to understand *what* a binary does.
> Use **angr** to prove *whether* a binary can be exploited and *how*.
