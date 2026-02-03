# YARA Performance Guidelines Reference

*Quick reference for writing efficient YARA rules. Derived from Neo23x0/YARA-Performance-Guidelines.*

## The Four Scanning Steps

1. **Compiling**: Extract 4-byte atoms from strings
2. **Aho-Corasick**: Fast atom search across files
3. **Bytecode engine**: Verify full string matches
4. **Condition evaluation**: Check rule logic

## String Selection (Most Critical)

### Good Atoms
- Minimum 4 bytes unique content
- Avoid common patterns: `\x00\x00\x00\x00`, `AAAAAA`, repeated chars
- Prefer: `cmd.exe`, `CreateRemoteThread`, unique error messages

### Avoid These Patterns
```yara
// Too short (< 4 bytes)
$a = "MZ"
$b = { 4D 5A }

// Repeating/uniform content
$c = "AAAAAAAAAAAAAAAA"
$d = "\x00\x20\x00\x20\x00\x20"  // wide spaces

// No fixed anchor (bad regex)
$e = /\w.*\d/
$f = /[0-9]+\n/
```

### Better Alternatives
```yara
// Use uint16/32 for short header checks
uint16(0) == 0x5A4D  // instead of "MZ" at 0

// Add context to short strings
$better = "MZ\x90\x00\x03"  // longer atom

// Regex with 4+ byte anchor
$anchored = /mshta\.exe http:\/\/[a-z0-9\.\/]{3,70}\.hta/
```

## Regex Best Practices

| Pattern | Issue | Better |
|---------|-------|--------|
|`.*` `.+`|Greedy, unbounded|`.{1,30}` with upper bound|
|`{x,}`|No upper bound|`{x,y}` with max|
|`/a.*b/`|Slow|Use offsets: `@a < @b`|

```yara
// SLOW: Greedy match
$bad = /exec.*\/bin\/sh/

// FAST: Use offsets
strings:
  $exec = "exec"
  $sh = "/bin/sh"
condition:
  $exec and $sh and @exec < @sh
```

## Condition Short-Circuiting

YARA evaluates left-to-right and stops at first FALSE. Order matters:

```yara
// SLOW: Expensive first
math.entropy(0, filesize) > 7.0 and uint16(0) == 0x5A4D

// FAST: Cheap check first
uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.0

// Good: Limit filesize before loops
$mz at 0 and filesize < 100KB and for all i in (1..filesize) : (...)
```

⚠️ **Regex does NOT short-circuit** — all regex strings are evaluated regardless of condition order.

## Module Alternatives

Modules parse entire files — use simple checks when possible:

```yara
// SLOW: Parses full PE
import "pe"
condition: pe.is_pe

// FAST: Header check only
condition: uint16(0) == 0x5A4D
```

| Instead Of | Use |
|------------|-----|
|`magic.mime_type()`|`uint32be(0) == 0x47494638` (GIF)|
|`pe.is_pe`|`uint16(0) == 0x5A4D`|

## Loop Performance

Avoid loops over large ranges:

```yara
// BAD: Iterates entire filesize
for all i in (1..filesize) : ($a at i)

// BAD: Too many iterations
for all i in (1..#a) : (@a[i] < 10000)  // #a could be huge
```

## Too Many Matches Fix

If you get "too many matches" errors:

1. Check regex quantifiers: `.*`, `.+`, `.*?`
2. Add upper bounds: `{x,y}` not `{x,}`
3. Reduce hex wildcards: `[1-300000]` → `[1-100]`
4. Split alternations: `/(a|b)cde/` → `/acde/` + `/bcde/`
5. Use `fullword` or `\b` for word boundaries

## NOCASE Impact

`nocase` generates exponentially more atom variations:

```yara
// 1 atom: "cmd.exe"
$a = "cmd.exe"

// 16 atoms: all case combinations
$b = "cmd.exe" nocase  // "Cmd.", "cMd.", "cmD.", ...

// Alternative: Regex for specific variations
$c = /[Pp]assword/
```

## Metadata Memory

All metadata is loaded into RAM. For memory-constrained scans, remove unnecessary metadata before deployment.
