# yaraQA Check Reference

*All automated checks from yaraQA tool. Use these to validate rules before deployment.*

## Issue ID Reference

### Logic Issues (Critical)

| ID | Severity | Description | Fix |
|----|----------|-------------|-----|
|`CE1`|🔴 Error|`N of them` with N > number of strings|Fix condition count|
|`SM6`|🔴 Error|PDB string with only `wide` (no `ascii`)|PDBs are always ASCII — use `ascii`|
|`SM1`|🟡 Info|PDB string with `wide` modifier|Remove unnecessary `wide`|
|`SM2`|🟡 Warning|PDB path with `fullword`|Remove `fullword` — `\\path\file.pdb` won't match|
|`SM3`|🟡 Warning|Path segment `\\Section\\` with `fullword`|Remove `fullword` modifier|
|`SM4`|🟡 Warning|Path segment with `fullword` (starts with `\\`)|Remove `fullword` |
|`SM5`|🟡 Warning|String starts/ends with chars problematic for `fullword`|Remove `fullword` or adjust string|
|`DS1`|🟡 Warning|Duplicate string values in same rule|Remove duplicates|
|`CS1`|🟡 Warning|String is substring of another string|Consolidate or adjust condition|

### Performance Issues

| ID | Severity | Description | Fix |
|----|----------|-------------|-----|
|`PA1`|🟡 Warning|Short string at position (e.g., `$mz at 0`)|Use `uint16/32(x)` instead|
|`PA2`|🟡 Warning|Short atom (< 4 bytes)|Add context bytes to string|
|`RE1`|🟡 Warning|Regex without 4+ byte anchor|Add anchor or use string|
|`CF1`|🟡 Warning|Hash/math calculation over large file range|Move to end of condition (short-circuit)|
|`CF2`|🟡 Warning|>3 math calculations|Reduce math operations|
|`NC1`|🟡 Info|`nocase` on letters-only string|Add digit/special char for better atom|
|`NO1`|🟡 Info|`ascii` + `wide` + `nocase` combo|Limit modifiers to what's needed|
|`PI1`|🟡 Warning|Regex with measurable performance impact|Replace with anchored string|
|`MO1`|🔵 Info|Rare module usage (<1% of rules or <3 rules)|Avoid module if possible|

### Style Issues

| ID | Severity | Description | Fix |
|----|----------|-------------|-----|
|`SV1`|🟡 Warning|Repeating character string (`AAAA`, `\x00\x00`)|Anchor with different char|
|`SV2`|🔵 Info|Hex string that could be text|Write as readable text string|

### Resource Issues

| ID | Severity | Description | Fix |
|----|----------|-------------|-----|
|`HS1`|🔵 Info|High string count (21-40)|Consider reducing strings|
|`HS2`|🟡 Warning|Very high string count (>40)|Reduce redundant strings|
|`HS3`|🔵 Info|High regex count (3-4)|Replace regex with strings|
|`HS4`|🟡 Warning|Very high regex count (>4)|Eliminate unnecessary regex|

### Duplicate Detection

| ID | Severity | Description | Fix |
|----|----------|-------------|-----|
|`DU1`|🟡 Warning|Logically duplicate rule|Remove duplicate rules|

## Condition Patterns That Trigger Issues

### CE1: Never-Matching Condition
```yara
// WRONG: 2 of them with only 1 string
strings:
    $a = "test"
condition:
    2 of them  // Will never match!

// CORRECT:
condition:
    1 of them  // or all of them
```

### PA1: Short String at Position
```yara
// WRONG: Short atom searched everywhere
strings:
    $mz = "MZ"
condition:
    $mz at 0

// CORRECT: Use uint check
condition:
    uint16(0) == 0x5A4D
```

### SM2/SM3: Fullword with Paths
```yara
// WRONG: fullword prevents matching
$s1 = "\\i386\\mimidrv.pdb" ascii fullword
$s2 = "\\ZombieBoy\\" ascii fullword

// CORRECT: Remove fullword
$s1 = "\\i386\\mimidrv.pdb" ascii
$s2 = "\\ZombieBoy\\" ascii
```

### CF1: Expensive Calculations First
```yara
// WRONG: Expensive first
condition:
    math.entropy(500, filesize-500) >= 5.7
    and all of them

// CORRECT: Cheap checks first (short-circuit)
condition:
    all of them
    and math.entropy(500, filesize-500) >= 5.7
```

### RE1: Unanchored Regex
```yara
// WRONG: No fixed anchor
$re = /[0-9]+\n/

// CORRECT: 4+ byte anchor
$re = /error: [0-9]+\n/
```

## Fullword Allowed Exceptions

These patterns work with `fullword` despite starting with `\\`:

- `\\.` — UNC paths
- `\\device`, `\\global`, `\\dosdevices`
- `\\basenamedobjects`
- `\\?`, `\\*`, `\\%`
- `\\registry`, `\\systemroot`
- `/tmp/`, `/etc/`, `/home/`, `/var/`
- `*/`, `---`, `c$`, `admin$`, `ipc$`
