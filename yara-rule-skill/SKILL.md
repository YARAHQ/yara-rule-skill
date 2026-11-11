---
name: yara-rule-skill
description: Writes, reviews, and optimizes YARA rules using the YARA Style Guide, the YARA Performance Guidelines, yaraQA checks, and YARA-Forge quality criteria. Use when the user wants a new YARA rule, a review or quality assessment of an existing rule or rule set, help with a slow, noisy, or non-compiling rule, an explanation of a yaraQA issue ID, or rules that should pass YARA-Forge QA.
---

# YARA Rule Authoring and Review

Version 2.0. This skill turns four sources into working practice:

| Source | Governs | Details |
|--------|---------|---------|
| [YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide) | Rule names, metadata, string groups, condition layout | [references/style.md](references/style.md) |
| [YARA Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines) (rev. 1.6) | Atoms, regex, condition order, modules | [references/performance.md](references/performance.md) |
| [yaraQA](https://github.com/Neo23x0/yaraQA) | Automated checks with IDs (`PA2`, `SM4`, `CE1`, ...) | [references/yaraqa-checks.md](references/yaraqa-checks.md) |
| [YARA-Forge](https://github.com/YARAHQ/yara-forge) | Compile gates, quality score, package tiers | [references/yara-forge.md](references/yara-forge.md) |

Guideline items that no tool checks have their own IDs in [references/issue-identifiers.md](references/issue-identifiers.md).

## How YARA spends its time

Most guidance below follows from the scan model:

1. **Compile:** YARA extracts **atoms** (substrings of up to 4 bytes) from every string.
2. **Search:** one Aho-Corasick pass looks for all atoms of all rules.
3. **Verify:** each atom hit is expanded to a full string match. Regex runs only here.
4. **Condition:** evaluated left to right, stopping at the first decisive result.

What follows from it:

- String choice is the main cost. A condition cannot stop a string from being searched: `filesize < 200 and $slow_regex` is still slow on every file.
- A string without a good atom (shorter than 4 bytes, uniform like `00 00 00 00`, or a regex with no fixed 4-byte run) slows the **whole rule set**, not just its own rule.
- Short-circuit evaluation helps only with condition work. Put cheap checks (`uint16(0)`, `filesize`) before expensive ones (`math.*`, hashes, loops, module fields).

## Workflow: write a new rule

Copy this checklist into your working notes and complete it in order:

```
- [ ] 1. Scope: target samples, file type, disk or memory, specific family or generic trait
- [ ] 2. Category and rule name
- [ ] 3. Strings: 3-7 diverse strings grouped as $x / $s / $a / $fp
- [ ] 4. Condition: header -> filesize -> other limits -> strings -> FP filters -> expensive checks
- [ ] 5. Metadata: description, author, reference, date, hash, score
- [ ] 6. Validate with scripts/validate_rule.py; fix and repeat until clean
- [ ] 7. Self-review against "Quick checks" below
```

**Never invent evidence.** Strings, hashes, and references must come from the user's samples or sources. If the user gave no sample data, ask for it or deliver a clearly marked template with placeholders. Don't present a placeholder as a working detection.

### 1. Scope

Ask (or infer from the request) what the rule must match and what it must never match. A rule for one malware family, a rule for a hack tool, and a heuristic for a suspicious trait need different strings, conditions, and scores.

### 2. Name

Format: `CATEGORY_[CLASSIFIERS_]Descriptor_Suffix`, ordered from generic to specific, joined with `_`.

| Main category | Use for |
|---------------|---------|
| `MAL` | Malware |
| `HKTL` | Hack tools (including dual-use offensive tooling) |
| `WEBSHELL` | Web shells |
| `EXPL` | Exploit code, PoCs, exploit payloads |
| `VULN` | Vulnerable components (drivers, libraries) |
| `SUSP` | Anomalies and suspicious traits (obfuscation, odd import sets, shellcode) |
| `PUA` | Potentially unwanted applications |

Add classifiers as needed (`APT`, `CRIME`, `RANSOM`, `LNX`, `MacOS`, `ELF`, `PS1`, `NET`, `GO`, `OBFUSC`, `InMemory`, ...) and end with a uniqueness suffix: month and year (`May23`) and, if needed, a number (`_1`). Examples: `MAL_APT_CozyBear_ELF_Loader_Apr18`, `SUSP_Anomaly_LNK_Huge_Apr22`, `HKTL_Go_EasyHack_Oct23`. Full vocabulary: [references/style.md](references/style.md#rule-names).

Rule names are identifiers: letters, digits, and `_` only, no leading digit, at most 128 characters. Write `NET`, not `.NET`.

### 3. Strings

Group strings by role. The prefixes make the condition read like the intent:

| Prefix | Role | Typical use in condition |
|--------|------|--------------------------|
| `$x*` | Highly specific; one hit is enough | `1 of ($x*)` |
| `$s*` | Weak alone, meaningful together | `all of ($s*)`, `3 of ($s*)` |
| `$a*` | Pre-selection; narrows file type or format | `$a1 and ...` |
| `$fp*` | Known benign content; vetoes a match | `not 1 of ($fp*)` |

Selection rules:

- **Prefer 3-7 strings.** More than about 10 usually means redundant or weak strings. yaraQA flags more than 20 (`HS1`) and more than 40 (`HS2`), not counting `$fp*` filters.
- **Diversify.** Take strings from different categories (usage text, error messages, PDB or build paths, mutex or pipe names, C2 URL patterns, unique function or class names, typos, opcodes). Eight log lines with the same `[DEBUG]` prefix all break when the author changes that prefix.
- **Avoid shared code.** Library, runtime, and framework strings (OpenSSL, zlib, Go runtime, MSVC CRT, common Windows API names) match goodware. They can be `$a*` or `$s*`, never `$x*`.
- **Give every string a good atom:** at least 4 bytes, not uniform, not a common byte run. Extend short strings with neighboring bytes (a space, quote, `\x00`).
- **Use regex only when a string or hex pattern can't express it.** Then include a fixed run of 4+ bytes and bound every quantifier (`.{1,64}`, not `.*`).
- **Readable values.** Write text as text, not hex (`SV2`). For hex that encodes text, add a comment with the readable form; wrap long hex every 16 bytes.
- **Concise identifiers:** `$x1`, `$s2`, `$eval`, not `$string_value_footer_1`.

Modifiers (default is `ascii`; add others only when the samples need them):

| Modifier | Effect | Guidance |
|----------|--------|----------|
| `wide` | Searches the UTF-16LE form | Use for strings stored as UTF-16 (.NET user strings, resources). `ascii wide` searches both. |
| `nocase` | Searches every case variant of the atom (up to 16 for 4 letters) | Only for case-insensitive content (PHP, batch, PowerShell keywords). Prefer `/[Pp]assword/`, or include a digit, space, or symbol in the string (`NC1`). |
| `fullword` | Requires non-alphanumeric characters (or file boundaries) on both sides | Don't use on strings starting or ending with `\`, `/`, `.`, `_`, `-`, `(`, `)`: the match fails or misbehaves (`SM2`-`SM5`). |
| `xor`, `xor(a-b)` | One search pattern per key; 256 keys (`0x00`-`0xff`) by default | Narrow the key range when known. Can't combine with `nocase`. |
| `base64`, `base64wide` | Searches base64-encoded forms of the string | YARA-X needs at least 3 bytes of plaintext; longer plaintext yields better atoms. Can't combine with `nocase`, `xor`, or `fullword`. |

PDB paths are always ASCII: never use `wide` on a `.pdb` string (`SM1`, `SM6`).

### 4. Condition

Order the parts as the Style Guide prescribes. The same order makes the most of short-circuit evaluation:

```yara
condition:
   uint16(0) == 0x5a4d          // 1. header (file type)
   and filesize < 2MB           // 2. size limit
   and pe.number_of_signatures == 0  // 3. other limitations
   and (                        // 4. string combinations
      1 of ($x*)
      or all of ($s*)
   )
   and not 1 of ($fp*)          // 5. false positive filters
```

Expensive work (`math.entropy`, `hash.*`, loops over sections or matches) goes last.

Layout: start each `and` on a new line; put `or` groups in an indented, parenthesized block. In YARA, `and` binds tighter than `or`, so `A and B or C` means `(A and B) or C`. A trailing top-level `or 4 of them` is a deliberate pattern: it matches when many strings are present, regardless of file type or size (unpacked code in memory, embedded payloads). Use it on purpose, never by accident.

Header checks (little-endian `uint` reads; verified byte orders):

| Format | Check |
|--------|-------|
| PE (`MZ`) | `uint16(0) == 0x5a4d` |
| ELF | `uint32(0) == 0x464c457f` |
| Mach-O 64-bit / 32-bit (little-endian) | `uint32(0) == 0xfeedfacf` / `uint32(0) == 0xfeedface` |
| ZIP, OOXML, JAR, APK (`PK\x03\x04`) | `uint32(0) == 0x04034b50` |
| OLE2 / CFB (legacy Office, MSI) | `uint32(0) == 0xe011cfd0` |
| LNK | `uint32(0) == 0x0000004c` |
| RTF (`{\rt`) | `uint32(0) == 0x74725c7b` |
| GIF (`GIF89a` / `GIF87a`) | `uint32be(0) == 0x47494638 and (uint16be(4) == 0x3961 or uint16be(4) == 0x3761)` |

Scripts and text formats have no magic bytes. Use an `$a*` pre-selection string (`"<?php"`, `"<%@"`) and a tight `filesize` limit instead.

Don't replace these checks with modules: `pe.is_pe` parses the whole file, and the `magic` module doesn't exist in YARA-X.

### 5. Metadata

Mandatory: `description` (starts with "Detects ...", 60-400 characters, no URLs), `author` (full name or handle; one field, comma-separated for several authors), `reference` (stable public URL, report name, or "Internal Research"), `date` (creation date, `YYYY-MM-DD`; changes go into `modified`).

Recommended: `hash` (SHA256 of the file the rule targets, not of an archive containing it; repeat the field for several samples) and `score`:

| Score | Meaning | Examples |
|-------|---------|----------|
| 0-39 | Very low | Capabilities, common packers (useful in combination) |
| 40-59 | Noteworthy | Uncommon packers, PE header anomalies |
| 60-79 | Suspicious | Heuristics, obfuscation, generic detections |
| 80-100 | High | Direct malware or hack tool matches |

Optional: `modified`, `old_rule_name`, `tags` (comma-separated, for classifiers that don't fit the name), `license`.

Always set `score` explicitly. Without it, YARA-Forge infers one from keywords anywhere in the metadata (see [references/yara-forge.md](references/yara-forge.md#score)).

### 6. Validate

Run the validator on every rule before showing it to the user (see [Validation](#validation)).

### 7. Quick checks

Before returning a rule, confirm:

- [ ] Compiles in YARA and YARA-X without errors **and without warnings**
- [ ] Every string is referenced; no `N of them` with N above the string count (`CE1`)
- [ ] No string shorter than 4 bytes (`PA2`); no `$s at 0` for a 1-2 byte header (`PA1`); no regex without a 4-byte anchor (`RE1`)
- [ ] File type check and `filesize` limit present when the target type is known
- [ ] Expensive checks last; no `math.*` or hash over the whole file early in the condition (`CF1`, `CF2`)
- [ ] `fullword` not on path-like strings (`SM2`-`SM5`); no `wide` on PDB strings (`SM1`, `SM6`)
- [ ] No generic or library string can fire the rule alone
- [ ] Name has a main category and suffix; all mandatory metadata present; `score` fits the category

## Workflow: review an existing rule

1. Validate it first. A compile failure or an always-false condition outranks every style issue.
2. Walk through it in this order: compile result → logic (can it match? can it misfire?) → false-positive risk → performance → metadata → naming and layout.
3. Tag each finding with an ID: yaraQA IDs from [references/yaraqa-checks.md](references/yaraqa-checks.md); YARA-Forge compile IDs `SI1`/`SI2`; manual-review IDs from [references/issue-identifiers.md](references/issue-identifiers.md). Don't invent IDs.
4. Write the output in the format below.

### Review output format

Produce three parts:

1. **Verdict:** one or two sentences, e.g. "Works, but slow on large files (unanchored regex) and missing metadata."
2. **Findings table**, most severe first. Severity follows yaraQA and YARA-Forge levels: `critical` (doesn't compile), `error` (never matches, or major performance or logic flaw), `warning` (FP risk or performance impact), `info` (style).

   | ID | Severity | Finding | Fix |
   |----|----------|---------|-----|
   | `RE1` | warning | `$r1` has no fixed 4-byte run | Add a literal prefix, e.g. `/mshta\.exe http:\/\/.../` |

3. **Assessed rule:** the author's rule with minimal fixes and inline comments, not a rewrite. This teaches the author and keeps their decisions visible.
   - Fix only clear-cut problems: compile errors, `PA1`-style header checks, metadata typos (`link` → `reference`), missing mandatory fields you can fill from the rule itself, and an obviously missing header check or generous `filesize` limit when the target file type is evident. Anything that changes what the rule matches beyond that stays a comment.
   - Don't fill gaps with guesses: no invented dates, references, or hashes. Mark them as missing in a comment.
   - Renaming to the naming convention is fine; record the previous name in `old_rule_name`.
   - Keep the author's string identifiers (`$ama_*` stays `$ama_*`); suggest regrouping in comments.
   - Put every suggestion in a `//` or `/* */` comment.
   - **The assessed rule must compile.** Never reference strings that don't exist (`all of ($op*)` with no `$op*` strings), never add placeholder hex. A suggestion that needs new strings goes in a comment.

Offer a full rewrite only when the user asks for one or the rule can't be repaired in place; follow the authoring workflow for it.

Example assessed rule:

```yara
rule MAL_Amaranth_Loader_Aug23 {   // naming: added category (MAL_) and suffix from the rule date
   meta:
      description = "Detects Amaranth Loader based on code patterns of its payload decryption routine"   // was: "Amaranth Loader"
      author = "@Tera0017/@_CPResearch_"
      reference = "https://research.checkpoint.com/"   // was: link
      date = "2023-08-15"
      old_rule_name = "Amaranth_Loader"                // added: keeps the previous name searchable
      score = 80                                       // added: direct malware match
   strings:
      // Consider grouping: $ama_iv and $ama_decr look unique enough for $x*,
      // $ama_size is weaker and fits a $s* group
      $ama_size = {41 BD 01 00 00 00 41 BC 00 40 06 00 E9 92 00 00 00}
      $ama_iv = {C7 84 24 30 02 00 00 12 34 56 78}
      $ama_decr = {FF C1 48 D3 E8 41 30 00 FF C2 49 FF C0}
      // removed: $mz = "MZ" (PA1/PA2, replaced by uint16 check below)
   condition:
      uint16(0) == 0x5a4d          // was: $mz at 0 (PA1)
      and filesize < 10MB          // added: size limit
      and any of ($ama*)
      // Consider: (1 of ($ama_iv, $ama_decr) or 2 of them) to require
      // either a unique pattern or two weaker ones
}
```

## Workflow: diagnose a slow rule or "too many matches"

Conditions don't fix either problem; strings do. Check in this order:

1. Regex quantifiers `.*`, `.+`, `.*?`, and unbounded `{n,}`; give each an upper bound.
2. Very large ranges (`{1,300000}`) and big jumps in hex strings.
3. Hex wildcards that can be narrowed, or a string that can be split at the wildcard.
4. Alternations (`/(a|b)cde/`, `{ C7 C3 00 (31 | 33) }`): split into separate strings.
5. Short strings (< 4 bytes) and uniform content (`AAAA...`, `00 20 00 20 ...`).
6. `nocase` on long letter-only strings; `xor` or `base64` without need.
7. Loops bounded by `filesize` or by a match count (`#a`) of a common string; add a `filesize` limit before them.
8. Modules used only for a file type check.

Details and examples: [references/performance.md](references/performance.md).

## Validation

**Every rule you write or modify must pass validation before you return it.** Don't rely on reading the rule.

```bash
python scripts/validate_rule.py rule.yar          # from a file
python scripts/validate_rule.py --stdin < rule.yar
python scripts/validate_rule.py rule.yar --strict # treat warnings as failures
python scripts/validate_rule.py rule.yar --json
```

The script compiles with YARA-X and, if `yara-python` is installed, with YARA 4.x too. It reports errors and warnings from both. Run `pip install -r scripts/requirements.txt` first if the import fails.

Loop: validate → fix → validate again until it passes. Then:

- **Warnings matter.** YARA-Forge compiles with warnings as errors and penalizes a warning with -70 quality (`SI2`), which keeps the rule out of the core and extended packages. Fix warnings unless the user explicitly accepts them.
- If the validator can't run (no Python, no network to install packages), say so plainly and list what you checked by hand. Never claim a rule compiles without having compiled it.
- If the user has [yaraQA](https://github.com/Neo23x0/yaraQA) available, suggest `python3 yaraQA.py -f rule.yar` for the automated quality checks.

Engine differences that cause "compiles here, fails there" (verified with YARA 4.5.4 and YARA-X 1.23):

| Construct | YARA 4.x | YARA-X |
|-----------|----------|--------|
| Unreferenced string (`$b` unused) | Error | Error. Prefix `$_` to keep an unused string in both. |
| Literal `{` in regex (`/abc{/`) | Accepted | Error; escape it: `/abc\{/` |
| `base64` on a string under 3 bytes | Accepted | Error |
| `import "magic"` | Only in builds with libmagic (never on Windows) | Error (no such module) |
| `.*`, `.+`, `.*?`, `.{n,}` in regex | Warning (only after `.`; `[a-z]{2,}` passes) | Accepted silently |
| Same string value twice | Accepted | Warning (`duplicate_pattern_value`) |
| `uint16(0) == 0x5a4d5a` (value can't fit) | Accepted | Warning (`unsatisfiable_expr`) |
| `for ... in (1..filesize)` | Accepted | Warning (`potentially_slow_loop`) |
| `N of them` with N above string count | Warning | Warning (`invariant_expr`) |

Both engines reject invalid escapes in text strings (`"C:\Windows"` must be `"C:\\Windows"`), duplicate modifiers, `xor nocase`, and references to undefined string sets.

## Rule template

```yara
rule HKTL_Go_EasyHack_Oct23 {
   meta:
      description = "Detects EasyHack, a Go based hack tool that injects payloads into remote processes"
      author = "John Galt"
      reference = "https://example.com/EasyHack"
      date = "2023-10-23"
      hash = "0000000000000000000000000000000000000000000000000000000000000000"  // placeholder: SHA256 of the sample
      score = 80
   strings:
      $a1 = "Go build ID: \""                     // pre-selection: Go binary

      $x1 = "Usage: easyhack.exe -t [IP] -p [PORT]"
      $x2 = "c0d3d by @EdgyHackerFreak"

      $s1 = "main.injectPayload"
      $s2 = "main.loadShellcode"
      $s3 = "easyhack/internal/"

      $fp1 = "Copyright by CrappySoft" wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20MB
      and $a1
      and (
         1 of ($x*)
         or all of ($s*)
      )
      and not 1 of ($fp*)
}
```

## Reference files

Read only what the task needs:

| File | Read when |
|------|-----------|
| [references/style.md](references/style.md) | Choosing a name (full classifier list), writing metadata, structuring strings and conditions |
| [references/performance.md](references/performance.md) | Choosing atoms, writing regex, diagnosing slow rules or "too many matches" |
| [references/yaraqa-checks.md](references/yaraqa-checks.md) | Citing or explaining a yaraQA ID; exact thresholds and levels |
| [references/issue-identifiers.md](references/issue-identifiers.md) | Citing a guideline issue that yaraQA doesn't check; all IDs at a glance |
| [references/yara-forge.md](references/yara-forge.md) | Preparing rules for YARA-Forge; explaining a rule's Forge score, quality, or package tier |
