# yaraQA Check Reference

*Complete reference for all yaraQA automated checks. Use these to validate rules before deployment.*

> yaraQA detects issues that are syntactically correct but dysfunctional — rules that never match, perform poorly, or use problematic patterns.

---

## Check Categories

| Category | Focus | IDs |
|----------|-------|-----|
|**Logic**|Rules that won't work as intended|CE1, SM1-6, DS1, CS1, DU1|
|**Performance**|Slow scans, memory issues|PA1-2, RE1, CF1-2, NC1, NO1, PI1, MO1|
|**Style**|Readability improvements|SV1-2|
|**Resources**|String/regex count issues|HS1-4|

---

## Severity Levels

| Level | Description |
|-------|-------------|
|🔴 **3 (Error)**|Rule will never match or has critical flaw|
|🟡 **2 (Warning)**|Significant issue, should be fixed|
|🔵 **1 (Info)**|Minor improvement suggested|

---

## Logic Issues

### CE1 — Condition Never Matches 🔴

**Problem**: `N of them` where N > number of strings

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

---

### SM1 — PDB with `wide` Modifier 🔵

**Problem**: PDB strings use `wide` modifier (unneeded — PDBs are always ASCII)

```yara
// WRONG:
$s1 = "\\i386\\mimidrv.pdb" ascii wide

// CORRECT:
$s1 = "\\i386\\mimidrv.pdb" ascii
```

---

### SM2 — PDB Path with `fullword` 🟡

**Problem**: PDB path starts with `\\` but uses `fullword`, preventing matches

```yara
// WRONG:
$s1 = "\\i386\\mimidrv.pdb" ascii fullword

// CORRECT:
$s1 = "\\i386\\mimidrv.pdb" ascii
```

---

### SM3 — File Path Section with `fullword` 🟡

**Problem**: Path segment `\\Section\\` with `fullword` won't match

```yara
// WRONG:
$s1 = "\\ZombieBoy\\" ascii fullword

// CORRECT:
$s1 = "\\ZombieBoy\\" ascii
```

---

### SM4 — Path Segment with `fullword` 🟡

**Problem**: String looks for path segment with `fullword` but starts with `\\`

```yara
// WRONG:
$s1 = "\\Temp\\evil.dll" ascii fullword

// CORRECT:
$s1 = "\\Temp\\evil.dll" ascii
```

**Allowed exceptions** (these work with `fullword`):
- `\\.` — UNC paths
- `\\device`, `\\global`, `\\dosdevices`
- `\\basenamedobjects`
- `\\?`, `\\*`, `\\%`
- `\\registry`, `\\systemroot`
- `/tmp/`, `/etc/`, `/home/`, `/var/`
- `*/`, `---`, `c$`, `admin$`, `ipc$`

---

### SM5 — `fullword` with Problematic Characters 🟡

**Problem**: String starts/ends with characters that break `fullword` matching

**Problematic start chars**: `.` `)` `_`
**Problematic end chars**: `(` `/` `\` `_` `-`

```yara
// WRONG:
$s1 = ")evil(" ascii fullword
$s2 = "path/" ascii fullword

// CORRECT:
$s1 = ")evil(" ascii
$s2 = "path/" ascii
```

---

### SM6 — PDB with Only `wide` (No `ascii`) 🔴

**Problem**: PDB string has only `wide` modifier — PDBs are always ASCII

```yara
// WRONG:
$s1 = "\\i386\\mimidrv.pdb" wide

// CORRECT:
$s1 = "\\i386\\mimidrv.pdb" ascii
```

---

### DS1 — Duplicate Strings 🟡

**Problem**: Same string value defined multiple times in one rule

```yara
// WRONG:
$a = "evil.exe"
$b = "evil.exe"

// CORRECT:
$a = "evil.exe"
$b = "malware.dll"
```

---

### CS1 — Substring String 🟡

**Problem**: One string is a substring of another (only reported with certain conditions like `X of them`)

```yara
// Problem: $b is substring of $a
$a = "evil_malware.dll"
$b = "malware"
condition:
    any of them

// CORRECT: Remove redundant substring or adjust condition
$a = "evil_malware.dll"
condition:
    $a
```

---

### DU1 — Logically Duplicate Rule 🟡

**Problem**: Two or more rules have identical logic (same strings + condition)

**Fix**: Remove duplicate rules

---

## Performance Issues

### PA1 — Short String at Position 🟡

**Problem**: Short string at specific position creates short atom

```yara
// WRONG: Searches entire file for short atom
strings:
    $mz = "MZ"
condition:
    $mz at 0

// CORRECT: Use uint check
condition:
    uint16(0) == 0x5A4D

// Also correct for longer strings:
strings:
    $sig = "MZ\x90\x00\x03"  // 4+ bytes
condition:
    $sig at 0
```

---

### PA2 — Short Atom 🟡

**Problem**: String < 4 bytes causes performance issues and memory bloat

```yara
// WRONG: Very short atoms
$a = "ab"
$b = { 01 02 03 }

// CORRECT: Add context bytes
$a = "ab\x00\x00"           // 4+ bytes
$b = { 01 02 03 04 05 }     // 5+ bytes
```

**Less avoidable short atoms** (level 1 instead of 2):
- `<?`, `<%`, `<% `, `<?=`, `GET`, `%>`

---

### RE1 — Regex Without Anchor 🟡

**Problem**: Regex lacks 4+ byte fixed anchor

```yara
// WRONG: No fixed anchor
$re = /[0-9]+\n/
$re = /\w.*\d/

// CORRECT: 4+ byte anchor
$re = /error: [0-9]+\n/
$re = /function\s+\w.*\d/
```

---

### CF1 — Expensive Calculation Over Full File 🟡

**Problem**: Hash/math calculation over large file range

```yara
// WRONG: Expensive calculation first
condition:
    math.entropy(500, filesize-500) >= 5.7
    and all of them

// CORRECT: Short-circuit — cheap checks first
condition:
    all of them
    and math.entropy(500, filesize-500) >= 5.7
```

---

### CF2 — Multiple Math Calculations 🟡/🔴

**Problem**: Too many math operations in condition

| Count | Level |
|-------|-------|
|1 math function|Level 2 (warning)|
|>3 math functions|Level 3 (error)|

```yara
// AVOID: Multiple math calculations
math.mean(0, filesize) > 50 and
math.entropy(0, filesize) > 7 and
math.deviation(0, filesize, 0) > 10

// CORRECT: Minimize or eliminate math operations
```

---

### NC1 — `nocase` on Letters-Only String 🔵

**Problem**: `nocase` on string with only letters — creates many atoms

```yara
// SUBOPTIMAL: Many atoms generated
$a = "password" nocase

// BETTER: Add special character
$a = "password:" nocase

// BEST: Use regex for specific variations
$re = /[Pp]assword/
```

---

### NO1 — `ascii` + `wide` + `nocase` Combo 🔵

**Problem**: All three modifiers together — are you sure?

```yara
// QUESTIONABLE:
$a = "evil" ascii wide nocase

// CORRECT: Use only what you need
$a = "evil" ascii wide    // if case is known
$re = /[Ee][Vv][Ii][Ll]/  // if specific variations needed
```

---

### PI1 — Regex Performance Impact 🟡

**Problem**: Regex has measurable performance impact in live testing

**Fix**: Replace with anchored string or hex pattern

```yara
// SLOW (during live testing):
$re = /complex.*pattern.*with.*backtracking/

// FAST:
$s1 = "complex"
$s2 = "pattern"
condition:
    $s1 and $s2
```

---

### MO1 — Rare Module Usage 🔵

**Problem**: Module used by <1% of rules or <3 rules in set

**Impact**: Slows down entire scanning process (module initialization)

**Affected modules** (excluded: `math`, `hash`):
- `pe`, `elf`, `dotnet`, `cuckoo`, `magic`, etc.

**Fix**: Refactor to avoid module if possible

```yara
// SLOW (if rare in rule set):
import "pe"
condition: pe.is_pe

// FAST:
condition: uint16(0) == 0x5A4D
```

---

## Style Issues

### SV1 — Repeating Character String 🟡

**Problem**: String with repeating characters causes "too many matches"

```yara
// WRONG:
$s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
$s2 = "\x00\x20\x00\x20\x00\x20"  // wide spaces

// CORRECT: Anchor with different characters
$s1 = "AAAAA\x00AAAAA"
```

---

### SV2 — Hex String That Could Be Text 🔵

**Problem**: Hex-encoded string contains only readable ASCII

```yara
// WRONG: Unreadable hex
$s1 = { 46 72 6F 6D 42 61 73 65 36 34 }

// CORRECT: Readable text
$s1 = "FromBase64"
```

**Exception**: Control characters (`\t`, `\n`) are acceptable in hex

---

## Resource Issues

### HS1/HS2 — High String Count

| ID | Count | Level |
|----|-------|-------|
|HS1|21-40 strings|Info 🔵|
|HS2|>40 strings|Warning 🟡|

**Recommendation**: Remove redundant strings (similar error messages, paths, registry keys)

**Note**: Filter strings (`$filter`, `$fp`, `$false`, `$exclu`) are not counted

---

### HS3/HS4 — High Regex Count

| ID | Count | Level |
|----|-------|-------|
|HS3|3-4 regex|Info 🔵|
|HS4|>4 regex|Warning 🟡|

**Recommendation**: In >90% of cases, rules can be written without regex

---

## yaraQA Usage

### Basic Scan
```bash
python3 yaraQA.py -d ./rules/
```

### Ignore Performance Issues
```bash
python3 yaraQA.py -d ./rules/ --ignore-performance
```

### Minimum Level (suppress info)
```bash
python3 yaraQA.py -d ./rules/ -l 2  # Show warnings+ only
```

### Use Baseline (hide reviewed issues)
```bash
python3 yaraQA.py -d ./rules/ -b yaraQA-reviewed-issues.json
```

---

## Quick Fix Reference

| Issue | Quick Fix |
|-------|-----------|
|CE1|Adjust `N of them` to match string count|
|SM1/SM6|Remove `wide` from PDB strings|
|SM2-5|Remove `fullword` from path strings|
|PA1|Replace `$x at 0` with `uint16/32(x)`|
|PA2|Extend string to 4+ bytes|
|RE1|Add 4+ byte anchor to regex|
|CF1|Move expensive calculation to end of condition|
|CF2|Reduce or eliminate math operations|
|NC1|Add special character to `nocase` string|
|NO1|Remove unnecessary modifiers|
|MO1|Replace module with `uint16/32` checks|
|SV1|Anchor repeating strings with different chars|
|SV2|Convert readable hex to text strings|
|HS1-4|Consolidate similar strings/regex|
|DS1|Remove duplicate string definitions|
|CS1|Remove substring strings|
|DU1|Remove duplicate rules|
