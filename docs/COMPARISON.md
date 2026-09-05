# Ghidra vs Reverify — Tool Comparison

Ghidra and Reverify serve different purposes in a binary analysis workflow.
They are not direct competitors — understanding where each fits helps you use both effectively.

---

## Feature comparison

| Aspect | Ghidra | Reverify |
|--------|--------|----------|
| **Type** | Full reverse engineering suite | Lightweight analysis toolkit |
| **Developed by** | NSA (open source) | Independent (open source) |
| **Interface** | Desktop GUI (Java) | CLI / Python library / API |
| **Disassembly** | Full binary — all functions, call graph, cross-references | Entry point only (configurable depth) |
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

---

## Where each tool wins

### Ghidra is the right choice when:

- A human analyst needs to deeply understand what a binary does
- You need to decompile obfuscated or packed code into readable C pseudocode
- You are tracing execution flow, patching a binary, or recovering a custom protocol
- The binary warrants hours of manual investigation

### Reverify is the right choice when:

- You need fast, automated triage across many files
- You are enriching a case management or SOAR platform (Flowintel, TheHive, etc.)
- You are building a pipeline that pushes structured findings to MISP automatically
- You need deterministic, reproducible output with no interpretation layer
- Your server has limited resources (no JDK, limited RAM)

---

## They work best together

Reverify and Ghidra complement each other in a tiered workflow:

```
Incoming file
      │
      ▼
  Reverify  (automated, seconds)
      │
      ├── Creates Flowintel case
      ├── Writes findings to case Notes
      └── Pushes file / pe / elf objects to MISP
      │
      │  suspicious? escalate to analyst
      ▼
   Ghidra  (manual, hours)
      │
      ├── Full disassembly of all functions
      ├── Decompile to C pseudocode
      ├── Trace execution flow
      └── Confirm / refine IOCs found by Reverify
```

Reverify acts as the **automated first filter** — it runs on every file without human
intervention and populates your case management and threat intelligence platforms
with structured data immediately.

Ghidra is the **analyst's deep-dive tool** — it is opened only when Reverify's
output flags a file as worth investigating further.

---

## Summary

> Use **Reverify** to triage at scale and feed your platforms automatically.
> Use **Ghidra** to understand *why* a binary does what it does.
