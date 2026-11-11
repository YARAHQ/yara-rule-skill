# YARA Performance Reference

Source: [Neo23x0/YARA-Performance-Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines), revision 1.6 (February 2025), which applies to YARA versions above 3.7. It builds on input from Victor M. Alvarez, Wesley Shields, and the YARA community. Sections marked *Skill addition* extend the guidelines.

> "Think of YARA as a two-step process: first, searching for all patterns listed in the strings, and second, evaluating the conditions. You can't use well-formed conditions to make up for poorly chosen strings." — Wesley Shields

## Contents

- [How a scan works](#how-a-scan-works)
- [Atoms](#atoms)
- [Strings to avoid](#strings-to-avoid)
- [Modifiers and alternations](#modifiers-and-alternations)
- [Regular expressions](#regular-expressions)
- [Too many matches and slow scanning](#too-many-matches-and-slow-scanning)
- [Conditions and short-circuit evaluation](#conditions-and-short-circuit-evaluation)
- [Modules](#modules)
- [Metadata](#metadata)
- [Engine warnings](#engine-warnings)
- [Quick diagnosis](#quick-diagnosis)

## How a scan works

Example rule:

```yara
import "math"

rule example_php_webshell_rule {
   meta:
      description = "Just an example php webshell rule"
      date = "2021-02-16"
   strings:
      $php_tag = "<?php"
      $input1 = "GET"
      $input2 = "POST"
      $payload = /assert[\t ]{0,100}\(/
   condition:
      filesize < 20KB
      and $php_tag
      and $payload
      and any of ($input*)
      and math.entropy(500, filesize-500) >= 5
}
```

1. **Compiling the rules.** Before the scan, YARA picks **atoms** from each string to feed the Aho-Corasick automaton. Here it might pick `<?ph`, `GET`, `POST`, and `sser` (from `assert`).
2. **Aho-Corasick search.** Every file is searched for all atoms at once. Hits go to the bytecode engine.
3. **Bytecode engine.** For a hit on `sser`, YARA checks for the preceding `a` and following `t`, then runs the regex remainder `[\t ]{0,100}\(` from there. The slow regex engine never runs over the whole file.
4. **Conditions.** After all pattern matching, conditions are evaluated. Short-circuit evaluation means the CPU-heavy `math.entropy` only runs when the four checks before it are true.

## Atoms

Atoms are substrings of up to 4 bytes that YARA extracts from anywhere in a string. When an atom is found, YARA verifies whether the full string matches. YARA tries to choose the atoms that will cause the fewest hits:

| String | Atom choice |
|--------|-------------|
| `/abc.*cde/` | `abc` or `cde`; equal quality, so the first (`abc`) |
| `/(one|two)three/` | `thre` (or `hree`) instead of both `one` and `two`: longer, and fewer repeated letters |
| `{ 00 00 00 00 [1-4] 01 02 03 04 }` | `01 02 03 04`; `00 00 00 00` is too common |
| `{ 01 02 [1-4] 01 02 03 04 }` | `01 02 03 04`; longer than `01 02` |

Strings need good atoms. These contain only short or common ones:

```
{ 00 00 00 00 [1-2] FF FF [1-2] 00 00 00 00 }
{ AB [1-2] 03 21 [1-2] 01 02 }
/a.*b/
/a(c|d)/
```

The worst strings have no atom at all. YARA must then try them at every offset of the file:

```
/\w.*\d/
/[0-9]+\n/
```

## Strings to avoid

### Too short

Any string under 4 bytes probably appears in many files, or as uniform content in XORed files. Extend it with neighboring bytes, or use a `uint` comparison when it's a header at a fixed offset:

```yara
// instead of: $mz = "MZ"  ...  $mz at 0
condition:
   uint16(0) == 0x5a4d
```

yaraQA: `PA2` (short string), `PA1` (short string at a fixed position).

### Uniform content

Long but uniform strings cause "too many matches" errors:

```
$s1 = "22222222222222222222222222222222222222222222222222222222222222"
$s2 = "\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20"  // wide spaces
```

```
error scanning yara-killer.dat: string "$mz" in rule "shitty_mz" caused too many matches
```

yaraQA: `SV1` (string made of one repeated character).

## Modifiers and alternations

Describe strings as narrowly as possible. Without modifiers, `ascii` is assumed.

Few atoms (one per encoding):

```
$s1 = "cmd.exe"                  // ascii only
$s2 = "cmd.exe" ascii            // same as $s1
$s3 = "cmd.exe" wide             // UTF-16 only
$s4 = "cmd.exe" ascii wide       // both: two atoms
$s5 = { 63 6d 64 2e 65 78 65 }   // ascii char codes in hex
```

Many atoms: `nocase` generates every upper/lower-case combination of the chosen atom (`Cmd.`, `cMd.`, `cmD.`, ...). That means more memory and more iterations.

```
$s6 = "cmd.exe" nocase
```

- Check whether the target language is case-insensitive at all (PHP, Windows batch) before using `nocase`.
- When only one or two letters vary, use a regex: `$re = /[Pp]assword/`.
- yaraQA: `NC1` (`nocase` on a letters-only string), `NO1` (`ascii wide nocase` together).

Alternations produce short atoms:

```
$re = /(a|b)cde/
$hex = { C7 C3 00 (31 | 33) }
```

With few variants, write separate strings:

```
$re1 = /acde/
$re2 = /bcde/
$hex1 = { C7 C3 00 31 }
$hex2 = { C7 C3 00 33 }
```

*Skill addition:* `xor` searches one variant per key (256 keys, `0x00`-`0xff`, by default) and `base64`/`base64wide` search several encoded forms. Restrict the `xor` range (`xor(0x01-0x1f)`) when the key space is known, and use these modifiers only when samples need them.

## Regular expressions

Use regex only when necessary. Regex evaluation is slower than string matching and uses **significant memory**. Don't use it when a hex string with jumps and wildcards can do the job.

### Quantifiers

Avoid greedy `.*` and even reluctant `.*?`. Use bounded ranges like `.{1,30}` or `.{1,3000}`, and always give an upper bound (not `.{2,}`).

Two situations occur:

- **One fixed beginning, variable suffix:** YARA returns the longest possible match. `.*`, `.+`, or `.{2,}` can produce very long matches and slow scanning.
- **Several possible beginnings:** YARA returns all of them.

```
$re1 = /Tom.{0,2}/    // finds "Tomxx" in "Tomxx"
$re2 = /.{0,2}Tom/    // finds "Tom", "xTom", "xxTom" in "xxTom"
```

Many short overlapping matches can exceed the match limit and cause "too many matches".

Email addresses illustrate this. A leading quantified character class matches the same address many times. Match a small, still informative subset instead:

```
USE
/[-a-z0-9._%+]@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
/@[-a-z0-9.]{2,10}\.[a-z]{2,4}/

AVOID
/[-a-z0-9._%+]*@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
/[-a-z0-9._%+]+@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
/[-a-z0-9._%+]{x,y}@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
```

### Offsets instead of regex

To check that `exec` is followed by `/bin/sh`, compare match offsets instead of spanning them with a regex:

```yara
// slow
$ = /exec.*\/bin\/sh/

// fast
strings:
   $exec = "exec"
   $sh = "/bin/sh"
condition:
   $exec and $sh and @exec < @sh
```

### Anchors

Include long fixed sequences that can serve as atoms. Longer is better:

```
BAD     $s1 = /http:\/\/[.]*\.hta/                       // greedy [.]*
BETTER  $s1 = /http:\/\/[a-z0-9\.\/]{3,70}\.hta/          // upper bound
BEST    $s1 = /mshta\.exe http:\/\/[a-z0-9\.\/]{3,70}\.hta/ // long anchor
```

yaraQA: `RE1` (no 4-byte anchor), `PI1` (measurable runtime cost), `HS3`/`HS4` (many regex strings). In more than 90% of cases a rule can be written without regex.

## Too many matches and slow scanning

**Too many matches** comes from strings that are too general and occur too often, or from YARA matching one instance many times.

**Slow scanning** comes from strings with too-short atoms or none at all, which force YARA into naive matching.

Fix steps for both:

1. Check for the quantifiers `.*`, `.+`, `.*?`.
2. Check for quantifiers without an upper bound, such as `x{14,}`.
3. Check for very large ranges, such as `x{1,300000}`.
4. Check for big jumps in hex strings.
5. Check wildcards: can they be more precise, or can the string be split in two at the wildcard?
6. Check alternations: can they be split into separate strings?
7. Add word-boundary constraints (`fullword`, `\b`).

Condition changes (next section) help speed in general but **do not fix** either error.

## Conditions and short-circuit evaluation

Conditions are evaluated left to right. Put the parts most likely to be false first, so YARA can skip the rest of the rule sooner. The gain depends on cost differences: if all parts cost about the same, reordering changes little.

```
// no meaningful gain from reordering
$string1 and $string2 and uint16(0) == 0x5A4D

// SLOW: expensive, then cheap
math.entropy(0, filesize) > 7.0 and uint16(0) == 0x5A4D

// FAST: cheap, then expensive
uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.0
```

yaraQA: `CF1` (calculation over almost the whole file), `CF2` (any `math` call; more than three is an error).

### Loops

Short-circuit evaluation was introduced for expensive `for` expressions. With

```
$mz at 0 and for all i in (1..filesize) : ( whatever )
```

the loop runs only for files starting with `MZ`. Bounding the size caps the iterations:

```
$mz at 0 and filesize < 100KB and for all i in (1..filesize) : ( whatever )
```

Loops over match counts have the same problem when the string is common:

```yara
strings:
   $a = { 00 00 }
condition:
   for all i in (1..#a) : ( @a[i] < 10000 )
```

`$a` is too common, so `#a` can be huge and the loop body runs thousands of times.

Since YARA 3.10, integer range loops stop as soon as the result is decided:

```
for all i in (0..100) : ( false )   // stops after the first iteration
for any i in (0..100) : ( true )    // stops after the first iteration
```

### No short-circuit for strings

All strings, regex included, are searched before any condition runs. This rule is slow on every file, not only on files under 200 bytes:

```yara
strings:
   $expensive_regex = /\$[a-z0-9_]+\(/ nocase
condition:
   filesize < 200 and $expensive_regex
```

Short-circuit evaluation exists since YARA 3.4.

## Modules

Modules such as `pe`, `elf`, and `magic` parse the file before the condition can use them, which adds scan time.

- Use `uint16(0) == 0x5A4D` instead of `pe.is_pe` to identify PE files.
- Use modules only when the rule needs deep inspection (imports, signatures, sections).

### `magic`

Avoid the `magic` module: it isn't available on Windows and slows scanning. *Skill addition:* YARA-X has no `magic` module at all. Compare header bytes directly:

```yara
rule gif_1 {
   condition:
      (uint32be(0) == 0x47494638 and uint16be(4) == 0x3961)
      or (uint32be(0) == 0x47494638 and uint16be(4) == 0x3761)
}
```

Instead of:

```
import "magic"
rule gif_2 {
   condition:
      magic.mime_type() == "image/gif"
}
```

*Skill addition:* in a rule set, a module that only a few rules use slows down every scan for little benefit (yaraQA `MO1`, which ignores `math` and `hash`). YARA-Forge caps the score of rules that import `elf` at 40, which keeps them in the full package only.

## Metadata

All metadata is loaded into RAM. Inserting 100,000 hashes into a rule makes the difference measurable. Don't strip metadata from your source rules, but when memory is tight you can remove unneeded fields in the deployment step, right before scanning.

## Engine warnings

*Skill addition.* Both engines report some of these problems at compile time. Verified with YARA 4.5.4 and YARA-X 1.23:

| Problem | YARA 4.x warning | YARA-X warning |
|---------|------------------|----------------|
| String without usable atom (`/[0-9]+\n/`, `{ 00 00 00 00 }`) | `string "$a" may slow down scanning` | `slow_pattern` |
| `.*`, `.+`, `.*?`, `.{n,}` in regex (dot only; `[a-z]{2,}` isn't reported) | `$a contains .*, .+ or .{x,} consider using .{,N}, .{1,N} or {x,N} with a reasonable value for N` | none |
| `for ... in (1..filesize)` | none | `potentially_slow_loop` |
| `N of them` above string count | `expression always false - requesting N of M` | `invariant_expr` |

Neither engine warns about 2-3 byte strings, `nocase` on letters, or uniform text like `AAAA...`. Those need yaraQA or a manual review.

## Quick diagnosis

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Whole rule set slow | String with short or no atom; unanchored regex | Extend to 4+ distinctive bytes; anchor regex (`PA2`, `RE1`) |
| "too many matches" | Uniform or very common string; quantifier matching one instance many times | Anchor with different bytes; bound quantifiers; split alternations (`SV1`) |
| High memory use | `nocase` on many strings; many regex; large metadata | Narrow modifiers; replace regex; trim metadata at deployment (`NC1`, `HS3`) |
| Slow on large files | Calculation or loop over the full file | Cheap checks and `filesize` limit first; calculation last (`CF1`) |
| Every file parsed by a module | Module used as a file type check | `uint16(0)` / `uint32(0)` comparison (`MO1`) |
| Slow despite `filesize <` guard | Expecting conditions to stop string search | Fix the string itself; conditions don't help |

Video: [Introduction Into YARA - Writing Efficient YARA Rules](https://www.youtube.com/watch?v=xKeF_cPKXt0) by @herrcore covers these topics.
