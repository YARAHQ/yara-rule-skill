---
name: yara-skill
description: Expert YARA rule authoring, review, and optimization. Use when writing new YARA rules, reviewing existing rules for quality issues, optimizing rule performance, or converting detection logic to YARA syntax. Covers rule naming conventions, string selection, condition optimization, performance tuning, and automated quality checks based on yaraQA.
---

# YARA Rule Authoring & Review

Expert guidance for writing high-quality, performant YARA rules based on industry best practices and automated QA checks.

## Quick Start

### Rule Template
```yara
rule MAL_Family_Platform_Type_Date {
    meta:
        description = "Detects ..."
        author = "Your Name"
        date = "2026-02-03"
        reference = "https://..."
        score = 75
    strings:
        $x1 = "unique malware string"
        $s1 = "grouped string 1"
        $s2 = "grouped string 2"
        $a1 = "Go build"
        $fp1 = "Copyright Microsoft"
    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and $a1
        and (
            1 of ($x*)
            or all of ($s*)
        )
        and not 1 of ($fp*)
}
```

## Core Principles

1. **String selection is everything** — YARA searches for 4-byte atoms first. Poor strings = slow scans.
2. **Conditions short-circuit** — Order from cheapest to most expensive (but regex doesn't short-circuit).
3. **Naming matters** — Use standardized prefixes for categorization and filtering.

## String Categories ($x, $s, $a, $fp)

| Prefix | Meaning | Condition Usage |
|--------|---------|-----------------|
|`$x*`|Highly specific|`1 of ($x*)` — triggers on unique signature|
|`$s*`|Grouped strings|`all of ($s*)` or `3 of ($s*)` — need multiple|
|`$a*`|Pre-selection|`$a1` — narrows file type first|
|`$fp*`|False positive filters|`not 1 of ($fp*)` — exclude benign matches|

## Rule Naming

Format: `CATEGORY_SUBCATEGORY_DESCRIPTOR_DATE`

**Main categories:** `MAL`, `HKTL`, `WEBSHELL`, `EXPL`, `VULN`, `SUSP`, `PUA`

**Examples:**
- `MAL_APT_CozyBear_ELF_Loader_Apr18`
- `SUSP_Anomaly_LNK_Huge_May23`
- `WEBSHELL_APT_ASP_China_2023`

See [references/style.md](references/style.md) for full naming conventions.

## Performance Critical Rules

### String Length
- Minimum effective atom: **4 bytes**
- Avoid: `"MZ"`, `{ 4D 5A }`, repeating chars (`AAAAAA`)
- Use `uint16(0) == 0x5A4D` for short header checks

### Regex
- Always include **4+ byte anchor**
- Avoid: `.*`, `.+`, unbounded quantifiers `{x,}`
- Prefer: `.{1,30}` with upper bound

### Condition Order
```yara
// GOOD: Cheap first, expensive last
uint16(0) == 0x5A4D
and filesize < 100KB
and all of them
and math.entropy(500, filesize-500) > 7

// BAD: Expensive first
math.entropy(...) > 7 and uint16(0) == 0x5A4D
```

### Module Alternatives
```yara
// AVOID: Parses entire file
import "pe"
condition: pe.is_pe

// USE: Header check only
condition: uint16(0) == 0x5A4D
```

See [references/performance.md](references/performance.md) for detailed optimization guidance.

## Common Issues (yaraQA)

### Logic Errors
| Issue | Problem | Fix |
|-------|---------|-----|
|`CE1`|Condition `2 of them` with only 1 string|Adjust count to match strings|
|`SM2`|PDB path with `fullword` modifier|PDBs start with `\\`, remove `fullword`|
|`SM3`|Path segment with `fullword`|`\\Section\\` won't match with `fullword`|
|`CS1`|String is substring of another|Remove redundant shorter string|

### Performance Warnings
| Issue | Problem | Fix |
|-------|---------|-----|
|`PA1`|Short string at position (`$mz at 0`)|Use `uint16(0) == 0x5A4D`|
|`PA2`|Short atom (< 4 bytes)|Extend with context bytes|
|`RE1`|Regex without anchor|Add 4+ byte fixed prefix|
|`CF1`|Expensive calc over full file|Move to end of condition|

See [references/yaraqa-checks.md](references/yaraqa-checks.md) for complete check reference.

## Review Workflow

When asked to review YARA rules:

1. **Check structure** — Naming, metadata, indentation (see style guide)
2. **Check strings** — Length, atoms, modifiers (avoid `nocase` on short strings)
3. **Check conditions** — Short-circuit order, logic errors, impossible matches
4. **Check performance** — Module usage, regex anchors, loop efficiency
5. **Suggest improvements** — Reference yaraQA issue IDs when applicable

## Modifiers Reference

| Modifier | Impact | Best Practice |
|----------|--------|---------------|
|`ascii`|1 atom|Default if no modifier specified|
|`wide`|1 atom|UTF-16, use when needed|
|`ascii wide`|2 atoms|Both encodings|
|`nocase`|Up to 16 atoms|Avoid on short strings; use regex `[Pp]attern` for specific cases|
|`fullword`|Word boundary|Avoid with paths starting `\\` or ending `\`|
|`xor`|256 variations|Use sparingly; consider single byte xor instead|

## Resources

- [references/style.md](references/style.md) — Naming, structure, formatting
- [references/performance.md](references/performance.md) — Optimization, atoms, conditions
- [references/yaraqa-checks.md](references/yaraqa-checks.md) — All automated checks
