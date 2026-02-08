# YARA Performance Guidelines

*Complete reference for writing efficient YARA rules. Based on YARA Performance Guidelines v1.6 (Feb 2025).*

> "Think of YARA as a two-step process: first, searching for all patterns listed in the strings, and second, evaluating the conditions. You can't use well-formed conditions to make up for poorly chosen strings." — Wesley Shields

## How YARA Scans (The 4 Steps)

### 1. Compiling the Rules
YARA extracts **atoms** (4-byte substrings) from defined strings to feed the Aho-Corasick automaton. YARA picks atoms cleverly to avoid too many matches.

Example: For strings `<?php`, `GET`, `POST`, `/assert[\t ]{0,100}\(/`, YARA might pick:
- `<?ph`
- `GET`
- `POST`
- `sser` (from "assert")

### 2. Aho-Corasick Search
Scans files for those atoms using a prefix tree. Matches are handed to the bytecode engine.

### 3. Bytecode Engine
Verifies full string matches. If `sser` matches, YARA checks for `a` prefix and `t` continuation, then validates the regex `[\t ]{0,100}\(`. This avoids running slow regex over entire files.

### 4. Condition Evaluation
Checks additional rule logic. Expensive operations (like `math.entropy`) only run if prior conditions pass (short-circuit evaluation).

---

## Atoms (The Most Important Factor)

YARA extracts up to 4-byte substrings called "atoms" from strings. These atoms drive the fast Aho-Corasick search.

### Good Atoms

YARA picks the best available atoms:

```
/abc.*cde/           → atoms: "abc" or "cde" (prefers "abc")
/(one|two)three/     → atoms: "thre" preferred (longer, more unique)
{ 00 00 00 00 [1-4] 01 02 03 04 }  → uses "01 02 03 04" (avoids common zeros)
{ 01 02 [1-4] 01 02 03 04 }        → prefers "01 02 03 04" over "01 02"
```

### Bad Atoms (Avoid These)

```yara
// Too short (< 4 bytes of unique content)
$a = "MZ"
$b = { 4D 5A }

// Repeating/uniform content
$c = "AAAAAAAAAAAAAAAA"
$d = "\x00\x20\x00\x20\x00\x20"  // wide spaces
$e = { 00 00 00 00 [1-2] FF FF [1-2] 00 00 00 00 }

// No fixed anchor (worst - forces naïve matching)
$f = /\w.*\d/
$g = /[0-9]+\n/
```

### Better Alternatives

```yara
// For short header checks, use uint functions
uint16(0) == 0x5A4D  // instead of "MZ" at 0

// Add context to extend atoms
$better = "MZ\x90\x00\x03"  // 4+ bytes

// Regex MUST have 4+ byte anchor
$anchored = /mshta\.exe http:\/\/[a-z0-9\.\/]{3,70}\.hta/
```

---

## String Selection Best Practices

### Too Short Strings
Any string < 4 bytes will probably appear in many files OR as uniform content in XORed files.

### Uniform Content
These cause "too many matches" errors:

```yara
$s1 = "22222222222222222222222222222222222222222222222222222222222222"
$s2 = "\x00\x20\x00\x20\x00\x20\x00\x20"  // wide formatted spaces
```

Error message:
```
error scanning yara-killer.dat: string "$mz" in rule "shitty_mz" caused too many matches
```

### String Modifiers & Atom Count

**LOW atom count (1 atom):**
```yara
$s1 = "cmd.exe"               // ascii only (default)
$s2 = "cmd.exe" ascii         // same as $s1
$s3 = "cmd.exe" wide          // UTF-16 only
$s4 = "cmd.exe" ascii wide    // 2 atoms
$s5 = { 63 6d 64 2e 65 78 65 }  // hex equivalent
```

**HIGH atom count (up to 16 atoms for 4-byte strings):**
```yara
$s5 = "cmd.exe" nocase        // all case combinations: "Cmd.", "cMd.", "cmD." ...
```

⚠️ **Use `nocase` carefully.** If you need specific variations, use regex: `$re = /[Pp]assword/`

### Alternation Issues

Alternations generate short atoms:

```yara
// Generates short atoms - SLOW
$re = /(a|b)cde/
$hex = { C7 C3 00 (31 | 33) }

// Better: Split into separate strings
$re1 = /acde/
$re2 = /bcde/
$hex1 = { C7 C3 00 31 }
$hex2 = { C7 C3 00 33 }
```

---

## Regular Expressions

Use regex only when necessary. Regex evaluation is slower and consumes significant memory.

### Regex Quantifiers

| Pattern | Problem | Solution |
|---------|---------|----------|
| `.*` `.+` | Greedy, unbounded | Use `.{1,30}` with upper bound |
| `{x,}` | No upper bound | Use `{x,y}` with maximum |
| `/a.*b/` | Slow | Use offsets: `@a < @b` |

### Quantifier Behavior

**Anchored suffix (one possible beginning):**
YARA matches the longest possible. `.*` and `.+` can lead to huge matches.

```
$re1 = /Tom.{0,2}/      // finds "Tomxx" in "Tomxx"
$re2 = /.{0,2}Tom/      // finds "Tom", "xTom", "xxTom" in "xxTom"
```

Multiple shorter matches can cross the limit and cause "too many matches" errors.

### Email Regex Example

**AVOID (match multiple times):**
```
/[-a-z0-9._%+]*@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
/[-a-z0-9._%+]+@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
```

**USE (match subset):**
```
/[-a-z0-9._%+]@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
OR
/@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
```

### Use Offsets Instead of Regex

```yara
// SLOW: Greedy regex
$ = /exec.*\/bin\/sh/

// FAST: String + offset check
strings:
  $exec = "exec"
  $sh   = "/bin/sh"
condition:
  $exec and $sh and @exec < @sh
```

### Regex Anchors

Longer anchors = better performance:

```yara
// BAD: No anchor, greedy
$s1 = /http:\/\/[.]*\.hta/

// BETTER: Upper bound
$s1 = /http:\/\/[a-z0-9\.\/]{3,70}\.hta/

// BEST: Long fixed prefix
$s1 = /mshta\.exe http:\/\/[a-z0-9\.\/]{3,70}\.hta/
```

---

## Conditions & Short-Circuit Evaluation

YARA evaluates left-to-right and stops at first FALSE. Order matters significantly.

### Reordering Impact

```yara
// No improvement (similar cost)
$string1 and $string2 and uint16(0) == 0x5A4D

// SLOW: Expensive first
math.entropy(0, filesize) > 7.0 and uint16(0) == 0x5A4D

// FAST: Cheap check first
uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.0
```

### Loop Optimization

```yara
// SLOW: Loops over entire file
for all i in (1..filesize) : ($a at i)

// BETTER: Short-circuit with cheap check
$mz at 0 and for all i in (1..filesize) : ( whatever )

// BEST: Limit iterations
$mz at 0 and filesize < 100KB and for all i in (1..filesize) : ( whatever )
```

### Loop Iterations Warning

```yara
// PROBLEM: $a is too common, #a can be huge
strings:
    $a = {00 00}
condition:
    for all i in (1..#a) : (@a[i] < 10000)
```

**YARA 3.10+ optimized loops:**
```yara
for all i in (0..100): (false)   // stops after first iteration
for any i in (0..100): (true)    // stops after first iteration
```

### ⚠️ Regex Does NOT Short-Circuit

Regex strings are always evaluated regardless of condition order:

```yara
// This is SLOW for ALL files, not just small ones
strings:
  $expensive_regex = /\$[a-z0-9_]+\(/ nocase
conditions:
  filesize < 200 and $expensive_regex
```

---

## Module Alternatives

Modules parse entire files before evaluation, increasing scan time.

### Magic Module (Avoid)

Not available on Windows. Slows down scanning.

```yara
// SLOW: Uses magic module
import "magic"
rule gif_2 {
  condition:
    magic.mime_type() == "image/gif"
}

// FAST: Header check
rule gif_1 {
  condition:
    (uint32be(0) == 0x47494638 and uint16be(4) == 0x3961) or
    (uint32be(0) == 0x47494638 and uint16be(4) == 0x3761)
}
```

### PE Module Alternative

```yara
// SLOW: Parses full PE
import "pe"
condition: pe.is_pe

// FAST: Header check only
condition: uint16(0) == 0x5A4D
```

---

## Fixing "Too Many Matches" & Slow Scanning

### Diagnostic Steps

1. **Check regex quantifiers**: `.*`, `.+`, `.*?`
2. **Add upper bounds**: `{x,y}` not `{x,}`
3. **Check large ranges**: `{1,300000}` → reduce
4. **Reduce hex wildcards**: minimize jump ranges
5. **Split alternations**: `/(a|b)/` → two strings
6. **Add word boundaries**: `fullword`, `\b`

### Note on Condition Changes

While condition ordering helps performance, it will NOT fix "too many matches" errors. Those are caused by string patterns, not condition logic.

---

## Metadata Memory Usage

All metadata is loaded into RAM. You can test this by inserting 100,000 hashes and checking YARA's RAM usage.

If memory-constrained, remove unneeded metadata before scanning.

---

## Quick Reference Table

| Problem | Check | Solution |
|---------|-------|----------|
| Slow scanning | Short/no atoms | Extend strings to 4+ unique bytes |
| Too many matches | Repeating content | Anchor with different characters |
| Memory usage | `nocase` on long strings | Use regex for specific variations |
| Module overhead | `pe`, `magic` usage | Use `uint16(0)`, `uint32be(0)` |
| Regex performance | Unbounded quantifiers | Add upper bounds `{1,30}` |
| Loop efficiency | `for all i in (1..filesize)` | Add `filesize < X` limit |
| Condition order | Expensive checks first | Move cheap checks (`uint16`) first |

## Video Tutorial

@herrcore has created a video covering these topics:
[Introduction Into YARA - Writing Efficient YARA Rules](https://www.youtube.com/watch?v=xKeF_cPKXt0)
