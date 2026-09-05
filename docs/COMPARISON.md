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

## 3. All three together

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

---

## Summary

> Use **Reverify** to triage at scale and feed your platforms automatically.
> Use **Ghidra** to understand *what* a binary does.
> Use **angr** to prove *whether* a binary can be exploited and *how*.
