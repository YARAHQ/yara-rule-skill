# yaraQA Check Reference

Source: [Neo23x0/yaraQA](https://github.com/Neo23x0/yaraQA). Thresholds and levels below are taken from the yaraQA source code (`main/string_checks.py`, `main/condition_checks.py`, `main/combination_checks.py`, `main/core.py`). YARA-Forge runs the per-rule checks on every rule it collects; the rule set checks `MO1` and `DU1` don't run there (see [yara-forge.md](yara-forge.md)).

yaraQA finds rules that compile but are dysfunctional: they never match, misuse modifiers, or slow down the whole rule set.

## Contents

- [Running yaraQA](#running-yaraqa)
- [Levels and types](#levels-and-types)
- [All checks](#all-checks)
- [Logic checks](#logic-checks)
- [Performance checks](#performance-checks)
- [Resource checks](#resource-checks)
- [Style checks](#style-checks)
- [Rule set checks](#rule-set-checks)
- [Limits of the checks](#limits-of-the-checks)

## Running yaraQA

```bash
pip install -r requirements.txt
python3 yaraQA.py -f rule1.yar rule2.yar      # files
python3 yaraQA.py -d ./rules/                 # directories
python3 yaraQA.py -d ./rules/ --ignore-performance   # logic issues only
python3 yaraQA.py -d ./rules/ -l 2            # warnings and errors only
python3 yaraQA.py -d ./rules/ -b yaraQA-reviewed-issues.json  # hide issues already reviewed
```

Output goes to `yaraQA-issues.json` (change with `-o`). Each issue has `rule`, `id`, `issue`, `element`, `level`, `type`, and `recommendation`. A baseline file is an earlier output: issues with the same rule and ID are suppressed.

## Levels and types

| Level | Label | Meaning |
|-------|-------|---------|
| 1 | info | Minor improvement |
| 2 | warning | Real problem: misfire risk or measurable cost |
| 3 | error | Rule can't work as intended, or major cost |

Types: `logic`, `performance`, `resources`, `style`. `--ignore-performance` suppresses the `performance` type.

YARA-Forge subtracts quality points per issue level: 1 → -2, 2 → -25, 3 → -70.

## All checks

| ID | Level | Type | Triggers when | Fix |
|----|-------|------|---------------|-----|
| `CE1` | 3 | logic | `N of ...` with N greater than the number of strings | Lower N or add strings |
| `SM1` | 1 | logic | String ending in `.pdb` has `wide` (together with `ascii`) | Remove `wide` |
| `SM2` | 2 | logic | `.pdb` string starting with `\` has `fullword` | Remove `fullword` |
| `SM3` | 2 | logic | String starting and ending with `\` has `fullword` | Remove `fullword` |
| `SM4` | 2 | logic | String starting with `\` has `fullword` (path segment), and isn't an allowed form | Remove `fullword` |
| `SM5` | 1 / 2 | logic | `fullword` string starts with `.` `)` `_` (level 1, length > 8) or ends with `(` `/` `\` `_` `-` (level 2, length > 6) | Remove `fullword` |
| `SM6` | 3 | logic | `.pdb` string has `wide` without `ascii` | Use `ascii` |
| `DS1` | 2 | logic | Same string value defined twice | Remove the duplicate |
| `CS1` | 2 | logic | One string is a substring of another, and the condition is `N of them` / `any of them` / `all of them` | Remove the redundant string or rethink the condition |
| `SV1` | 2 | logic | String consists of a single repeated character | Anchor with different bytes |
| `PA1` | 2 | performance | 1-2 byte string tested at a fixed position (`$mz at 0`) | `uint8`/`uint16` comparison |
| `PA2` | 2 (1) | performance | Text string under 4 characters or hex string under 4 bytes | Add bytes before or after |
| `RE1` | 2 | performance | Regex without a run of 4+ literal characters | Add a longer literal anchor |
| `NC1` | 1 | performance | `nocase` on a string longer than 3 characters made only of letters | Add a non-letter (space, digit, symbol) or use a narrow regex |
| `NO1` | 1 | performance | `ascii`, `wide`, and `nocase` on the same string | Keep only the modifiers samples require |
| `CF1` | 2 | performance | Calculation over (almost) the whole file, e.g. `math.entropy(0, filesize)` | Move it to the end of the condition |
| `CF2` | 2 / 3 | performance | Any `math.` call (level 2); more than three (level 3) | Avoid or reduce `math` calls |
| `PI1` | 2 | performance | Regex is measurably slow in a live test | Simplify it or replace it with a (hex) string |
| `MO1` | 1 | performance | Module used by few rules of the set (see [rule set checks](#rule-set-checks)) | Refactor to avoid the module |
| `HS1` | 1 | resources | 21-40 strings (filter strings not counted) | Remove similar or redundant strings |
| `HS2` | 2 | resources | More than 40 strings (filter strings not counted) | Remove similar or redundant strings |
| `HS3` | 1 | resources | 3-4 regex strings | Replace regex with strings |
| `HS4` | 2 | resources | More than 4 regex strings | Replace regex with strings |
| `SV2` | 1 | style | Hex string that decodes entirely to printable ASCII | Write it as a text string |
| `DU1` | 2 | logic | Rule has the same strings and condition as another rule in the set | Remove one of them |

## Logic checks

### CE1: condition never matches

```yara
// never matches: 2 of them with one string
strings:
   $a = "test1234"
condition:
   2 of them
```

Both YARA 4.x (`expression always false - requesting 2 of 1`) and YARA-X (`invariant_expr`) warn about this at compile time.

### SM1, SM6: `wide` on PDB strings

PDB paths are always stored as ASCII.

```yara
$s1 = "\\i386\\mimidrv.pdb" ascii wide   // SM1 (info): wide unneeded
$s2 = "\\i386\\mimidrv.pdb" wide         // SM6 (error): never matches
$s3 = "\\i386\\mimidrv.pdb"              // correct
```

### SM2-SM5: `fullword` on path-like strings

`fullword` requires a non-alphanumeric character (or the file boundary) on both sides. Strings that start or end with a separator usually sit between alphanumeric characters, so the match fails.

```yara
$s1 = "\\i386\\mimidrv.pdb" fullword   // SM2: preceded by a folder name
$s2 = "\\ZombieBoy\\" fullword          // SM3 (and SM5): path segment
$s3 = ".malware_loader" fullword        // SM5: starts with .
$s4 = "malware_loader_" fullword        // SM5: ends with _
```

SM4 targets the remaining strings that start with a backslash. It exempts prefixes and suffixes where `fullword` does work: device and UNC namespaces (`\\.\`, `\\?\`, `\Device`, `\Global`, `\DosDevices`, `\BaseNamedObjects`, `\Registry`, `\SystemRoot`), Unix directories (`/tmp/`, `/etc/`, `/home/`, `/root/`, `/var/`), comment markers (`*/`, `---`, ` //`), and admin shares (`c$`, `admin$`, `ipc$`). In the current yaraQA version, one exemption pattern also matches any backslash followed by letters, so SM4 rarely fires on paths like `"\\Temp\\evil.dll" fullword`. Check such strings by hand: they still fail to match when preceded by a folder name.

### DS1: duplicate strings

```yara
$a = "evil.exe"
$b = "evil.exe"   // DS1
```

YARA-X also warns (`duplicate_pattern_value`).

### CS1: substring of another string

Reported only when the condition counts strings generically (`any of them`, `all of them`, `N of them` at the start or end of the condition), because then the shorter string can satisfy the count on its own or double-count.

```yara
strings:
   $a = "evil_malware.dll"
   $b = "malware"          // CS1: substring of $a
condition:
   2 of them               // one occurrence of "evil_malware.dll" satisfies both
```

### SV1: repeating character

A string made of one character repeated (`"AAAAAAAAAAAA"`) causes "too many matches" on large files. Anchor it with different bytes: `"\x00AAAAAAAAAAAA\x00"`. SV1 only catches single-character repetition; other uniform content (`\x00\x20\x00\x20...`) needs manual review (see [performance.md](performance.md#uniform-content)).

## Performance checks

### PA1: short string at a fixed position

```yara
// PA1 + PA2
strings:
   $mz = "MZ"
condition:
   $mz at 0

// fix
condition:
   uint16(0) == 0x5a4d
```

yaraQA's recommendation text includes the computed replacement (`uint16(0) == 0x5a4d`).

### PA2: short atom

Text under 4 characters or hex under 4 bytes:

```yara
$a = "ab"            // PA2
$b = { 01 02 03 }    // PA2
$c = "ab\x00\x00"    // fixed: 4 bytes
```

Short strings that are hard to avoid in web shell and script rules get level 1 instead of 2: `<?`, `<%`, `<% `, `<?=`, `GET`, `%>`.

### RE1: regex without anchor

yaraQA looks for a run of at least 4 characters from `[a-zA-Z0-9_\s.="']` in the regex source. This is a heuristic: an escaped sequence like `\x41\x42\x43\x44` doesn't count, and a run spanning a character class might.

```yara
$r1 = /[0-9a-fA-F]{20}/          // RE1
$r2 = /\w.*\d/                   // RE1
$r3 = /hash=[0-9a-fA-F]{20}/     // ok: "hash=" is the anchor
```

### NC1, NO1: costly `nocase`

```yara
$a = "password" nocase              // NC1: letters only
$b = "password:" nocase             // ok: the colon limits the variants
$c = /[Pp]assword/                  // ok: only the variants that occur
$d = "evil.exe" ascii wide nocase   // NO1: are all three really needed?
```

### CF1: calculation over the full file

Triggered by a range of the form `(N, filesize)` or `(N, filesize-N)` with small N, as in `math.entropy(500, filesize-500)` or `hash.md5(0, filesize)`.

```yara
// CF1
condition:
   math.entropy(500, filesize-500) >= 5.7 and all of them

// fix: let the strings decide first
condition:
   all of them and math.entropy(500, filesize-500) >= 5.7
```

### CF2: `math` calls

Any `math.` call in the condition is level 2; more than three are level 3. Keep the calls few and last.

### PI1: measured regex cost

yaraQA times each regex on a sample text and compares it against a baseline set by a known-bad regex (`[\w\-.]{1,3}@[\w\-.]{1,3}`) and a known-good one. A regex slower than the midpoint is reported. Replace it with strings or an anchored, bounded regex.

## Resource checks

### HS1, HS2: many strings

Strings named `$filter*`, `$fp*`, `$false*`, or `$exclu*` don't count. Long lists usually contain similar strings (many error messages, many paths, many registry keys); keep the most distinctive ones.

### HS3, HS4: many regex strings

In more than 90% of cases a rule can be written without regex.

## Style checks

### SV2: hex that could be text

```yara
$s1 = { 46 72 6F 6D 42 61 73 65 36 34 }   // SV2
$s1 = "FromBase64"                         // fixed
```

Not reported when the bytes include control characters such as `\t` or `\n`; those may stay hex.

## Rule set checks

These need the whole rule set:

- **`MO1`** reports a module (other than `math` and `hash`) that is used by fewer than 1% of the rules, or by only two rules in a set of more than 30. Loading a module costs time on every scanned file, so a module that few rules need is expensive. Only modules referenced in a condition count.
- **`DU1`** reports rules whose strings and condition hash to the same value.

## Limits of the checks

yaraQA works on the parsed rule text and uses heuristics. It doesn't judge false-positive risk, string specificity, metadata, or naming; use [style.md](style.md) and [issue-identifiers.md](issue-identifiers.md) for those. It also doesn't compile the rule: run the validator for syntax errors and engine warnings.

In yaraQA as of commit `df60c14` (June 2026), `DS1`, `DU1`, and `HS4` are defined but never emitted because of bugs in the code (a rule with five regex strings gets `HS3`). Report them from manual review; the IDs and their meaning stay valid.
