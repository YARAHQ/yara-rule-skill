# Issue Identifiers

Every finding in a review gets an ID. Three families exist:

| Family | Emitted by | Defined in |
|--------|------------|------------|
| yaraQA checks: `CE`, `SM`, `DS`, `CS`, `SV`, `PA`, `RE`, `NC`, `NO`, `CF`, `PI`, `MO`, `HS`, `DU` | yaraQA (automated) | [yaraqa-checks.md](yaraqa-checks.md) |
| YARA-Forge compile checks: `SI1`, `SI2` | YARA-Forge (automated) | [yara-forge.md](yara-forge.md#qa-checks) |
| Manual review: `NM`, `MF`, `TR`, `SS`, `CL`, `FM`, `ID`, `RX`, `CC` | This skill (reviewer judgment) | This file |

Manual-review IDs cover YARA Style Guide and Performance Guidelines items that no tool checks. Use the yaraQA ID whenever one fits; use a manual ID only for what yaraQA doesn't cover. Never invent IDs outside these lists.

Levels follow yaraQA: **info** (1), **warning** (2), **error** (3). YARA-Forge adds **critical** (4) for rules that don't compile.

## Contents

- [All IDs at a glance](#all-ids-at-a-glance)
- [NM: naming](#nm-naming)
- [MF: metadata](#mf-metadata)
- [TR: string selection](#tr-string-selection)
- [SS: string style](#ss-string-style)
- [CL: condition logic](#cl-condition-logic)
- [FM, ID: layout](#fm-id-layout)
- [RX: performance guidelines](#rx-performance-guidelines)
- [CC: compatibility](#cc-compatibility)
- [Changes from version 1.x](#changes-from-version-1x)

## All IDs at a glance

| ID | Level | Issue |
|----|-------|-------|
| `SI1` | critical | Doesn't compile (YARA-Forge) |
| `SI2` | error | Compiles only with warnings (YARA-Forge) |
| `CE1` | error | Condition can never match (yaraQA) |
| `NM1` | warning | No main category prefix |
| `NM2` | info | Classifiers not ordered generic to specific |
| `NM3` | info | No uniqueness suffix |
| `NM4` | info | Technology or file type not in name |
| `NM5` | info | Non-Windows platform not in name |
| `NM6` | info | Modifier (`OBFUSC`, `InMemory`, ...) not in name |
| `NM7` | warning | Category doesn't match the rule's confidence |
| `MF1` | warning | Mandatory metadata field missing |
| `MF2` | info | Description doesn't start with "Detects" |
| `MF3` | info | URL in description |
| `MF4` | info | Description under 60 or over 400 characters |
| `MF5` | info | URL in author field |
| `MF6` | info | Several `author` fields |
| `MF7` | warning | Date not `YYYY-MM-DD` |
| `MF8` | warning | Reference unstable or private |
| `MF9` | info | No `score` |
| `MF10` | warning | Score doesn't fit category or specificity |
| `MF11` | warning | Hash of a container instead of the matched file |
| `MF12` | info | Changed rule without `modified` |
| `MF13` | info | Non-standard name for a standard field |
| `TR1` | info | No `$a*` pre-selection although the file type is known |
| `TR2` | warning | String prefix doesn't match its role |
| `TR3` | info | Generic rule without `$fp*` filters |
| `TR4` | warning | `$fp*` string not negated in the condition |
| `TR5` | warning | Generic or shared-code string can fire the rule alone |
| `TR6` | info | Low string diversity |
| `TR7` | info | More than about 10 strings |
| `TR8` | info | Modifiers the samples don't need |
| `SS1` | info | Hex string could be text (same as yaraQA `SV2`; cite `SV2`) |
| `SS2` | info | Long hex not wrapped at 16 bytes |
| `SS3` | info | Hex for text without a readable comment |
| `SS4` | info | Verbose or meaningless string identifier |
| `CL1` | warning | No file type check although the type is known |
| `CL2` | info | No `filesize` limit |
| `CL3` | warning | `and`/`or` precedence changes the intended meaning |
| `CL4` | info | Redundant sub-expression |
| `FM1` | info | No line break before `and` |
| `FM2` | info | `or` group not in an indented block |
| `FM3` | info | Nested groups without parentheses |
| `ID1` | info | Inconsistent indentation |
| `ID2` | warning | No indentation |
| `RX1` | warning | Hash or loop instead of a string match |
| `RX2` | warning | Short string searched across the whole file |
| `RX3` | warning | Regex with unbounded quantifier |
| `RX4` | warning | Expensive check before cheap checks |
| `RX5` | warning | Module unused or used only for a file type check |
| `RX6` | warning | `magic` module |
| `RX7` | warning | Loop over the file or a match count without a size limit |
| `RX8` | warning | Uniform content not caught by `SV1` |
| `RX9` | info | Alternation that produces short atoms |
| `RX10` | warning | Very large jump or range |
| `CC1` | error | Compiles in one engine only (YARA 4.x vs YARA-X) |
| `CC2` | warning | Feature not available in all scanners |

## NM: naming

Source: YARA Style Guide, rule names. See [style.md](style.md#rule-names).

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `NM1` | warning | Name doesn't start with `MAL`, `HKTL`, `WEBSHELL`, `EXPL`, `VULN`, `SUSP`, or `PUA` | `CobaltStrike_Loader` → `MAL_CobaltStrike_Loader_May23` |
| `NM2` | info | Values not ordered generic to specific | `Loader_MAL_APT_CozyBear` → `MAL_APT_CozyBear_ELF_Loader_Apr18` |
| `NM3` | info | No month-year or number suffix | Add `_Apr18` or `_1` |
| `NM4` | info | Strings or header check reveal a technology (`GO`, `NET`, `ELF`, `PS1`, `LNK`) the name omits | Add the technology classifier |
| `NM5` | info | Linux or macOS rule without `LNX` / `MacOS` (only `WIN` may be omitted) | Add the platform |
| `NM6` | info | Rule targets obfuscated, encoded, unpacked, or in-memory content without saying so | Add `OBFUSC`, `Encoded`, `Unpacked`, `InMemory` |
| `NM7` | warning | Category overstates or understates confidence: a generic heuristic named `MAL_`, a specific family rule named `SUSP_` | Use `SUSP_` for heuristics and anomalies, `MAL_`/`HKTL_` for specific detections |

## MF: metadata

Source: YARA Style Guide, metadata. See [style.md](style.md#metadata).

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `MF1` | warning | `description`, `author`, `reference`, or `date` missing | Add the field |
| `MF2` | info | Description doesn't start with "Detects" | "This rule finds X" → "Detects X ..." |
| `MF3` | info | Description contains a URL | Move the URL to `reference` |
| `MF4` | info | Description under 60 or over 400 characters | Say what is detected and its scope, concisely |
| `MF5` | info | Author field is a URL | Name or handle instead |
| `MF6` | info | `author` repeated | One field, comma-separated |
| `MF7` | warning | Date in another format (`15.05.2023`, `2023/05/15`, `May 2023`) | `YYYY-MM-DD` |
| `MF8` | warning | Reference to a paste site, expiring link, login-only or private resource | Stable public URL, report name, or "Internal Research" |
| `MF9` | info | No `score` | Add one; see score table in [style.md](style.md#score) |
| `MF10` | warning | Score contradicts category or specificity (`SUSP_` heuristic at 95; `MAL_` family rule at 45) | `SUSP_` usually 60-79; specific `MAL_`/`HKTL_` 80-100 |
| `MF11` | warning | `hash` is the archive or dropper that contained the matched file | Hash of the file the rule matches (memory form for `InMemory` rules) |
| `MF12` | info | Rule was changed but has no `modified` date, or `date` was overwritten | Keep `date` as creation; add `modified` |
| `MF13` | info | Standard information under non-standard keys: `desc`, `ref`, `link`, `url`, `created`, `Author`, `sha256` | Use `description`, `reference`, `date`, `author`, `hash` |

## TR: string selection

Source: YARA Style Guide (triad, `$fp*`) and skill additions. See [style.md](style.md#strings).

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `TR1` | info | Rule for a known file type has no `$a*` pre-selection or header check | Add a pre-selection string or `uint` header check |
| `TR2` | warning | Prefix contradicts role: `$a*` string used as the only trigger, `$x*` string that is common | Rename to the matching prefix and adjust the condition |
| `TR3` | info | Generic or heuristic rule has no `$fp*` filters for known benign matches | Add `$fp*` strings for the known false positives |
| `TR4` | warning | `$fp*` string defined but the condition doesn't contain `not ... $fp*` | Add `and not 1 of ($fp*)` |
| `TR5` | warning | A string that also occurs in goodware can fire the rule alone: library or runtime strings, common API names, generic words, version strings | Move it to `$s*` or `$a*`; require it together with specific strings |
| `TR6` | info | Most strings share one template (same log prefix, same path) | Replace some with strings from other categories |
| `TR7` | info | More than about 10 strings (yaraQA `HS1` starts at 21) | Keep the 3-7 most specific |
| `TR8` | info | `wide`, `nocase`, `xor`, or `base64` without evidence in the samples | Remove the modifier, or narrow it (`xor(0x01-0x1f)`) |

## SS: string style

Source: YARA Style Guide, strings. See [style.md](style.md#strings).

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `SS1` | info | Hex string could be text | Cite yaraQA `SV2` instead |
| `SS2` | info | Hex string longer than 16 bytes on one line | Wrap every 16 bytes |
| `SS3` | info | Hex that encodes mostly text has no comment | Add the readable form as a comment |
| `SS4` | info | Identifier verbose or meaningless (`$string_value_footer_1`, `$selection_14`) | `$s1`, `$x1`, or a short descriptive name |

## CL: condition logic

Source: YARA Style Guide, conditions, and review practice.

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `CL1` | warning | Strings are typical for one file type, but the condition has no header check, so documents, logs, or memory dumps that quote them match too | Add `uint16(0) == 0x5a4d` (or the right header) |
| `CL2` | info | No `filesize` limit for a file-type rule | Add a limit that fits the samples with margin |
| `CL3` | warning | `and` and `or` mixed without parentheses so the meaning differs from the intent: `uint16(0) == 0x5a4d and $a or $b` also fires on `$b` in any file | Parenthesize; keep a top-level `or N of them` only when intended |
| `CL4` | info | Sub-expression that can't change the result: `($a and $c) or all of them` | Simplify to the equivalent shorter form |

`CE1` (count above the number of strings) and undefined string references (`SI1`) are condition errors too; cite those IDs.

## FM, ID: layout

Source: YARA Style Guide, indentation and condition layout.

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `FM1` | info | Several `and` terms on one line in a multi-part condition | Line break before each `and` |
| `FM2` | info | `or` group written inline: `and ( 1 of ($x*) or all of ($s*) )` | Indented block, one alternative per line |
| `FM3` | info | Nested combinations without parentheses, hard to read even if correct | Parenthesize each level |
| `ID1` | info | Mixed tabs and spaces, or inconsistent depth | 3 or 4 spaces (or tabs) consistently |
| `ID2` | warning | No indentation inside the rule | Indent section keywords once, content twice |

## RX: performance guidelines

Source: YARA Performance Guidelines. See [performance.md](performance.md). Use the yaraQA ID when one applies (`PA1`, `PA2`, `RE1`, `CF1`, `CF2`, `NC1`, `SV1`, `MO1`).

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `RX1` | warning | Section or region hashed in a loop to find known bytes | Put the bytes in a hex string |
| `RX2` | warning | Short string searched across the whole file (no `at`, no context bytes) | Extend it or use a `uint` check; usually reported as `PA2` |
| `RX3` | warning | Regex with `.*`, `.+`, `.*?`, or any `{n,}` | Upper bound: `.{1,64}`, `[a-z]{2,32}`. YARA 4.x warns only for the `.` forms, so check character classes by hand. |
| `RX4` | warning | Module field, loop, or hash evaluated before cheap checks | Header and `filesize` first, expensive checks last (`CF1` for math and hash) |
| `RX5` | warning | Module imported only to identify the file type (`pe.is_pe`), or imported and not used at all; YARA 4.x runs every imported module on every scanned file | `uint16(0) == 0x5a4d`; remove unused imports |
| `RX6` | warning | `magic` module | Compare header bytes; YARA-X has no `magic` module |
| `RX7` | warning | `for ... in (1..filesize)` or `for ... in (1..#a)` with a common `$a` and no size limit | `filesize` limit before the loop; more specific string |
| `RX8` | warning | Uniform content that `SV1` misses: zero runs (`{ 00 00 00 00 }`), repeated pairs (`\x00\x20\x00\x20`) | Anchor with distinctive bytes |
| `RX9` | info | Alternation that yields short atoms: `/(a|b)cde/`, `{ C7 C3 00 (31 | 33) }` | Split into separate strings |
| `RX10` | warning | Very large jump or range: `[0-300000]`, `.{1,300000}`, many wildcards | Narrow it, or split into two strings and compare offsets |

## CC: compatibility

Source: skill addition, verified with YARA 4.5.4 and YARA-X 1.23. See the engine table in [SKILL.md](../SKILL.md#validation).

| ID | Level | Check | Fix |
|----|-------|-------|-----|
| `CC1` | error | Compiles in YARA 4.x but not YARA-X, or the reverse: unescaped `{` in regex, `base64` on strings under 3 bytes | Use syntax both engines accept |
| `CC2` | warning | Needs something not every scanner has: `magic` or `cuckoo` module, external variables, includes | Rewrite without it, or document the requirement |

## Changes from version 1.x

Version 1.x used `NC1`-`NC6` for naming, which collided with yaraQA's `NC1` (`nocase`). Naming IDs are now `NM1`-`NM6`, with the same numbers. All other 1.x IDs keep their meaning. New in 2.0: `NM7`, `MF13`, `TR5`-`TR8`, `CL1`-`CL4`, `RX8`-`RX10`, `CC1`-`CC2`, and the YARA-Forge IDs `SI1`/`SI2`.

| 1.x ID | 2.0 ID |
|--------|--------|
| `NC1` Missing main category | `NM1` |
| `NC2` Incorrect category order | `NM2` |
| `NC3` Missing date suffix | `NM3` |
| `NC4` Ambiguous technology tag | `NM4` |
| `NC5` Platform omission | `NM5` |
| `NC6` Modifier not in name | `NM6` |
