# angr vs Reverify — Tool Comparison

[angr](https://github.com/angr/angr) and Reverify occupy very different positions
in the binary analysis landscape. Understanding the distinction helps you pick the
right tool for each stage of an investigation.

---

## What is angr?

angr is a binary analysis framework developed at UC Santa Barbara (UCSB).
Its core capability is **symbolic execution** — running a binary with symbolic
(mathematical) values instead of concrete inputs, then using an SMT solver (Z3)
to reason about all possible execution paths simultaneously.

This allows angr to answer questions like:

- *"Is there any input that makes this binary reach `system()`?"*
- *"What exact byte sequence triggers this buffer overflow?"*
- *"Does this path lead to an exploitable condition?"*

---

## Feature comparison

| Aspect | angr | Reverify |
|--------|------|----------|
| **Type** | Binary analysis framework | Lightweight analysis toolkit |
| **Developed by** | UC Santa Barbara (UCSB) | Independent (open source) |
| **Core technique** | Symbolic / concolic execution | Static parsing |
| **Disassembly** | Full — all reachable code paths | Entry point (configurable depth) |
| **Decompiler** | No (use with Ghidra for that) | No |
| **Symbolic execution** | Yes — variables carry symbolic constraints | No |
| **Constraint solving** | Yes — Z3 SMT solver built in | No |
| **Control flow graph** | Yes — full CFG recovery | No |
| **Data flow analysis** | Yes | No |
| **Vulnerability discovery** | Yes — automatically find exploitable paths | No |
| **Exploit generation** | Yes (via angrop, rex) | No |
| **Header parsing** | Yes (via CLE loader) | Yes — PE, ELF, Mach-O |
| **Hash computation** | No | Yes — MD5, SHA1, SHA256 |
| **String extraction** | No | Yes |
| **Suspicious string detection** | No | Yes |
| **Supported architectures** | x86, x86\_64, ARM, AArch64, MIPS, PPC, and more | x86, x86\_64, ARM, AArch64 |
| **Interface** | Python library | Python library / CLI |
| **Resource usage** | Heavy — symbolic execution is CPU/RAM intensive | Lightweight — runs on minimal hardware |
| **Speed on a typical binary** | Minutes to hours (or longer) | Seconds |
| **Learning curve** | Very high | Low |
| **Flowintel / MISP integration** | None built-in | Native |
| **Pipeline / automation** | Possible but complex | Designed for it |
| **Primary use case** | Vulnerability research, CTF, exploit development | Automated triage and threat intelligence enrichment |

---

## Where each tool wins

### angr is the right choice when:

- You need to prove whether a binary contains an exploitable vulnerability
- You are solving a CTF challenge that requires symbolic reasoning
- You need to find what input drives execution to a specific code path
- You are doing academic or advanced security research on a specific binary
- You have hours or days to spend on a single sample

### Reverify is the right choice when:

- You need fast, automated triage across many files
- You are feeding structured findings into a case management or SOAR platform
- You need deterministic, reproducible output without an SMT solver overhead
- You are enriching [MISP](https://github.com/MISP/MISP) events automatically
- Your pipeline must complete in seconds, not hours

---

## Complementary workflow

The two tools address different stages of a binary investigation.
Used together with Ghidra, they form a complete tiered pipeline:

```
Incoming binary
      │
      ▼
  Reverify  (automated, seconds)
      │
      ├── Creates Flowintel case
      ├── Extracts: type · hashes · imports · strings
      ├── Flags suspicious strings (URLs, IPs, regkeys)
      └── Pushes file / pe / elf objects to MISP
      │
      │  suspicious? escalate to analyst
      ▼
   Ghidra  (manual, hours)
      │
      ├── Full disassembly and decompilation
      ├── Execution flow analysis
      └── Confirm and refine IOCs from Reverify
      │
      │  need to prove exploitability or find exact trigger?
      ▼
    angr  (research-grade, hours to days)
      │
      ├── Symbolic execution across all code paths
      ├── Constraint solving: find exact input to reach target
      └── Automatic exploit / PoC generation (via rex / angrop)
```

---

## Practical notes on angr

angr is powerful but demanding:

- **State explosion** — the number of symbolic states grows exponentially with the number
  of branches; large or obfuscated binaries can run for hours without finishing
- **Requires expertise** — writing effective angr scripts requires understanding of
  binary internals, VEX IR, and SMT solving concepts
- **Not a batch tool** — angr is applied to one specific binary with a targeted question,
  not run automatically across all incoming files

Reverify does not attempt symbolic execution and does not claim to find vulnerabilities.
What it does instead is give you reliable, fast facts about a binary — exactly the
information an analyst needs to decide whether a deeper investigation with angr is warranted.

---

## Summary

> Use **Reverify** to triage at scale and feed your platforms automatically.
> Use **Ghidra** to understand *what* a binary does.
> Use **angr** to prove *whether* a binary can be exploited and *how*.
