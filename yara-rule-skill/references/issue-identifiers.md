# YARA Rule Issue Identifiers

*Complete identifier reference for all YARA rule conventions, errors, and recommendations. Combines yaraQA automated checks with style guide and performance manual review items.*

## Identifier Scheme

| Code | Category | Source | Level |
|------|----------|--------|-------|
|`CE`|Condition Error|yaraQA|Error 🔴|
|`CF`|Condition Fail (performance)|yaraQA|Warning 🟡|
|`CS`|Combination/String|yaraQA|Warning 🟡|
|`DS`|Duplicate String|yaraQA|Warning 🟡|
|`DU`|Duplicate Rule|yaraQA|Warning 🟡|
|`HS`|High String count|yaraQA|Info/Warning 🔵🟡|
|`MF`|Meta Field|Style Guide|Info/Warning 🔵🟡|
|`MO`|Module usage|yaraQA|Info 🔵|
|`NC`|Naming Convention|Style Guide|Warning 🟡|
|`NO`|Nocase+Other modifiers|yaraQA|Info 🔵|
|`PA`|Performance Atom|yaraQA|Warning 🟡|
|`PI`|Performance Impact|yaraQA|Warning 🟡|
|`RE`|Regex Error|yaraQA|Warning 🟡|
|`RX`|Performance eXtended|Performance|Warning 🟡|
|`SM`|String Modifier|yaraQA|Info/Error 🔵🔴|
|`SS`|String Style|Style Guide|Info 🔵|
|`ST`|String Triad|Style Guide|Info 🔵|
|`SV`|String Value (style)|yaraQA|Info/Warning 🔵🟡|
|`ID`|Indentation/Formatting|Style Guide|Info 🔵|
|`FM`|condition Formatting|Style Guide|Info 🔵|

---

## NC — Naming Convention Issues

*From YARA Style Guide — Rule naming standards*

### NC1 — Missing Main Category

**Level:** Warning 🟡
**Check:** Rule name lacks a main category prefix

```yara
// WRONG: No category
rule CobaltStrike_Loader { ... }

// CORRECT:
rule MAL_CobaltStrike_Loader_May23 { ... }
rule HKTL_CobaltStrike_Beacon_Jan24 { ... }
```

**Main Categories Required:**
- `MAL` — Malware
- `HKTL` — Hack tool
- `WEBSHELL` — Web shell
- `EXPL` — Exploit code
- `VULN` — Vulnerable component
- `SUSP` — Suspicious/generic
- `PUA` — Potentially unwanted application

---

### NC2 — Incorrect Category Order

**Level:** Info 🔵
**Check:** Naming components not ordered from generic to specific

```yara
// SUBOPTIMAL: Specific before generic
rule Loader_MAL_APT_CozyBear_ELF_Apr18 { ... }

// CORRECT: Generic to specific
rule MAL_APT_CozyBear_ELF_Loader_Apr18 { ... }
```

**Correct Order:** `CATEGORY → INTENTION → ACTOR → PLATFORM → TYPE → DATE`

---

### NC3 — Missing Date Suffix

**Level:** Info 🔵
**Check:** Rule lacks MonthYear or numeric suffix

```yara
// SUBOPTIMAL: No date
rule MAL_APT_CozyBear_ELF_Loader { ... }

// CORRECT:
rule MAL_APT_CozyBear_ELF_Loader_Apr18 { ... }
rule MAL_APT_CozyBear_ELF_Loader_1 { ... }
```

---

### NC4 — Ambiguous Technology Tag

**Level:** Info 🔵
**Check:** File type detectable from strings but not in name

```yara
// INCONSISTENT: Go binary detection but not in name
rule MAL_APT_CozyBear_Loader_Apr18 {
    strings:
        $a1 = "Go build"  // Clearly Go binary
    ...
}

// CORRECT:
rule MAL_APT_CozyBear_GO_Loader_Apr18 { ... }
```

---

### NC5 — Platform Omission When Non-Windows

**Level:** Info 🔵
**Check:** Non-Windows rule missing platform indicator

```yara
// SUBOPTIMAL: ELF binary without LNX
rule MAL_APT_CozyBear_ELF_Loader_Apr18 { ... }

// CORRECT:
rule MAL_APT_CozyBear_LNX_ELF_Loader_Apr18 { ... }
```

**Note:** `WIN` is default and often omitted, but `LNX`, `MacOS` should be explicit.

---

### NC6 — Modifier Not Reflected in Name

**Level:** Info 🔵
**Check:** Rule detects obfuscated/encoded/InMemory but name doesn't indicate

```yara
// INCONSISTENT: Detects obfuscation but not in name
rule MAL_CRIME_RANSOM_PS1_Loader_May23 {
    strings:
        $a1 = /[Bb]64[Dd]ecode/  // Obfuscated Base64
    ...
}

// CORRECT:
rule MAL_CRIME_RANSOM_PS1_OBFUSC_Loader_May23 { ... }
```

**Common Modifiers:** `OBFUSC`, `Encoded`, `Unpacked`, `InMemory`

---

## MF — Meta Field Issues

*From YARA Style Guide — Metadata standards*

### MF1 — Missing Mandatory Meta Field

**Level:** Warning 🟡
**Check:** Rule lacks description, author, reference, or date

```yara
// WRONG: Missing fields
rule MAL_Test_May23 {
    meta:
        description = "Detects malware"
        // Missing: author, reference, date
    ...
}

// CORRECT:
rule MAL_Test_May23 {
    meta:
        description = "Detects X malware family"
        author = "Analyst Name / Company"
        reference = "https://blog.example.com/analysis"
        date = "2023-05-15"
    ...
}
```

**Mandatory Fields:** `description`, `author`, `reference`, `date`

---

### MF2 — Description Without "Detects"

**Level:** Info 🔵
**Check:** Description doesn't start with "Detects ..."

```yara
// SUBOPTIMAL:
description = "This is a rule for malware X"

// CORRECT:
description = "Detects X malware family used by APT Y"
```

---

### MF3 — Description Contains URL

**Level:** Info 🔵
**Check:** Description field includes URL (should be in reference)

```yara
// WRONG:
description = "Detects malware from https://evil.com/campaign"

// CORRECT:
description = "Detects malware from Evil campaign"
reference = "https://evil.com/campaign"
```

---

### MF4 — Description Too Short or Too Long

**Level:** Info 🔵
**Check:** Description < 60 or > 400 characters

```yara
// TOO SHORT (< 60):
description = "Detects evil"

// TOO LONG (> 400):
description = "Detects a very complex malware that does many things including ... [300 more chars]"

// CORRECT (60-400 chars):
description = "Detects X malware family used by APT Y in Z campaign targeting financial institutions"
```

---

### MF5 — Author Field Contains URL

**Level:** Info 🔵
**Check:** Author field has URL instead of name/handle

```yara
// WRONG:
author = "https://twitter.com/analyst"

// CORRECT:
author = "Analyst Name (@twitterhandle)"
author = "Security Team / Company Name"
```

---

### MF6 — Multiple Author Fields

**Level:** Info 🔵
**Check:** Multiple authors as separate fields instead of comma-separated

```yara
// WRONG:
meta:
    author = "Alice"
    author = "Bob"
    author = "Charlie"

// CORRECT:
meta:
    author = "Alice, Bob, Charlie"
```

---

### MF7 — Date Format Incorrect

**Level:** Warning 🟡
**Check:** Date not in YYYY-MM-DD format

```yara
// WRONG:
date = "15-05-2023"
date = "May 15, 2023"
date = "2023"

// CORRECT:
date = "2023-05-15"
```

---

### MF8 — Reference is Unstable/Private

**Level:** Warning 🟡
**Check:** Reference points to private repo, paste bin, or temporary URL

```yara
// PROBLEMATIC:
reference = "https://pastebin.com/raw/abc123"  // Expires
reference = "https://private.intel/internal/123"  // Inaccessible

// PREFERRED:
reference = "https://blog.public-site.com/analysis"
reference = "https://github.com/vendor/advisory/blob/main/CVE-2023-1234.md"
reference = "Internal Research"  // If truly internal
```

---

### MF9 — Missing Score for Detection Rules

**Level:** Info 🔵
**Check:** High-confidence malware rule lacks score field

```yara
// SUBOPTIMAL: No score for malware detection
rule MAL_APT_CozyBear_Implant_Apr18 {
    meta:
        description = "Detects CozyBear implant"
    ...
}

// CORRECT:
rule MAL_APT_CozyBear_Implant_Apr18 {
    meta:
        description = "Detects CozyBear implant"
        score = 85  // High: direct malware match
    ...
}
```

---

### MF10 — Score Mismatch with Rule Type

**Level:** Warning 🟡
**Check:** Score inconsistent with rule's detection target

```yara
// MISMATCH: Generic heuristic with high score
rule SUSP_Obfuscated_PS1_May23 {
    meta:
        score = 95  // Too high for suspicious/heuristic
    ...
}

// MISMATCH: Known malware with low score
rule MAL_APT_CozyBear_Implant_Apr18 {
    meta:
        score = 45  // Too low for known malware
    ...
}

// CORRECT:
// SUSP rules: 60-79
// MAL rules: 80-100
```

**Score Guidelines:**
- 0-39: Very Low (capabilities, common packers)
- 40-59: Noteworthy (uncommon packers, anomalies)
- 60-79: Suspicious (heuristics, obfuscation)
- 80-100: High (direct malware/hack tool matches)

---

### MF11 — Using Archive Hash Instead of File Hash

**Level:** Warning 🟡
**Check:** Hash is for ZIP/RAR containing sample, not extracted file

```yara
// WRONG: Hash of the ZIP container
hash = "a1b2c3d4..."  // Hash of malware.zip

// CORRECT: Hash of extracted malware.exe
hash = "e5f6g7h8..."  // Hash of malware.exe from inside zip
```

---

### MF12 — Missing Modified Date for Updated Rules

**Level:** Info 🔵
**Check:** Rule has been updated but lacks `modified` field

```yara
// Original
rule MAL_Test_May23 {
    meta:
        date = "2023-05-15"
    ...
}

// Updated (should indicate modification)
rule MAL_Test_May23 {
    meta:
        date = "2023-05-15"
        modified = "2023-08-20"
    ...
}
```

---

## ID — Indentation and Formatting Issues

*From YARA Style Guide — Code formatting*

### ID1 — Inconsistent Indentation

**Level:** Info 🔵
**Check:** Mixed tabs/spaces or inconsistent indentation levels

```yara
// WRONG: Mixed indentation
rule Bad {
 meta:
  description = "inconsistent"
    author = "mixed"
strings:
$s1 = "value"
 condition:
filesize < 10KB
}

// CORRECT:
rule Good {
   meta:
      description = "consistent 3-space indent"
      author = "Name"
   strings:
      $s1 = "value"
   condition:
      filesize < 10KB
}
```

---

### ID2 — No Indentation Inside Rule

**Level:** Warning 🟡
**Check:** Rule content at same level as rule keyword

```yara
// WRONG:
rule NoIndent {
meta:
description = "hard to read"
strings:
$s1 = "test"
condition:
filesize < 10KB
}

// CORRECT: Use 3-4 spaces per level
```

---

## TR — String Triad Issues

*From YARA Style Guide — $x/$s/$a/$fp convention*

### TR1 — Missing Pre-Selection String ($a*)

**Level:** Info 🔵
**Check:** Rule targets specific file type but lacks $a* pre-selection

```yara
// SUBOPTIMAL: No file type pre-selection
rule MAL_Go_Malware_Jan24 {
    strings:
        $x1 = "evil payload"
    condition:
        $x1
}

// CORRECT:
rule MAL_Go_Malware_Jan24 {
    strings:
        $a1 = "Go build"      // Pre-select Go binaries
        $x1 = "evil payload"
    condition:
        $a1 and $x1
}
```

---

### TR2 — Incorrect String Prefix Usage

**Level:** Warning 🟡
**Check:** String used inconsistently with its prefix

```yara
// WRONG: $a string used as unique signature
rule MAL_Test_Jan24 {
    strings:
        $a1 = "evil_unique_string"  // Should be $x
    condition:
        $a1  // Using pre-selection string alone
}

// CORRECT:
rule MAL_Test_Jan24 {
    strings:
        $a1 = "Go build"
        $x1 = "evil_unique_string"
    condition:
        $a1 and $x1
}
```

---

### TR3 — Missing False Positive Filter

**Level:** Info 🔵
**Check:** Generic rule lacks $fp* strings for known benign matches

```yara
// SUBOPTIMAL: Could match legitimate Go tools
rule HKTL_Go_Tool_Jan24 {
    strings:
        $a1 = "Go build"
        $s1 = "main.hack"
    condition:
        $a1 and $s1
}

// BETTER:
rule HKTL_Go_Tool_Jan24 {
    strings:
        $a1 = "Go build"
        $s1 = "main.hack"
        $fp1 = "Copyright by LegitimateCorp"
    condition:
        $a1 and $s1 and not $fp1
}
```

---

### TR4 — $fp String Not Used in Condition

**Level:** Warning 🟡
**Check:** $fp* string defined but not negated in condition

```yara
// WRONG: $fp defined but never checked
rule MAL_Test_Jan24 {
    strings:
        $s1 = "evil"
        $fp1 = "legitimate"
    condition:
        $s1  // Missing: and not $fp1
}

// CORRECT:
condition:
    $s1 and not $fp1
```

---

## SS — String Style Issues

*From YARA Style Guide — String formatting*

### SS1 — Hex String Could Be Text

**Level:** Info 🔵
**Check:** Hex string contains only readable ASCII characters

```yara
// SUBOPTIMAL:
$s1 = { 46 72 6F 6D 42 61 73 65 36 34 }

// CORRECT:
$s1 = "FromBase64"
```

**Exception:** Control characters (`\t`, `\n`) acceptable in hex.

---

### SS2 — Long Hex Not Wrapped at 16 Bytes

**Level:** Info 🔵
**Check:** Hex string > 16 bytes on single line

```yara
// HARD TO READ:
$s1 = { 2c 20 2a 79 6f 77 2e 69 20 26 20 30 78 46 46 29 3b 0a 20 20 70 72 69 6e 74 66 20 28 28 28 2a 79 6f 77 2e 69 20 26 20 30 78 66 66 29 }

// CORRECT (wrapped at 16):
$s1 = { 2c 20 2a 79 6f 77 2e 69 20 26 20 30 78 46 46 29 
        3b 0a 20 20 70 72 69 6e 74 66 20 28 28 28 2a 79 
        6f 77 2e 69 20 26 20 30 78 66 66 29 }
```

---

### SS3 — Hex String Missing ASCII Comment

**Level:** Info 🔵
**Check:** Hex string representing ASCII lacks comment

```yara
// SUBOPTIMAL:
$s1 = { 29 29 29 3b 0a 49 45 58 28 0a }

// CORRECT:
/* )));
IEX( */
$s1 = { 29 29 29 3b 0a 49 45 58 28 0a }
```

---

### SS4 — Long Non-Descriptive Identifier

**Level:** Info 🔵
**Check:** String identifier unnecessarily verbose

```yara
// VERBOSE:
$string_value_footer_1 = "eval("
$selection_14 = "eval("

// CONCISE:
$s1 = "eval("
$eval = "eval("
```

---

## FM — Condition Formatting Issues

*From YARA Style Guide — Condition structure*

### FM1 — Missing Newline Before AND

**Level:** Info 🔵
**Check:** Condition operators on same line

```yara
// SUBOPTIMAL:
condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of ($s*)

// CORRECT:
condition:
    uint16(0) == 0x5a4d
    and filesize < 300KB
    and all of ($s*)
```

---

### FM2 — OR Block Not Indented

**Level:** Info 🔵
**Check:** Parentheses for OR conditions not properly indented

```yara
// SUBOPTIMAL:
condition:
    uint16(0) == 0x5a4d
    and filesize < 300KB
    and ( 1 of ($x*) or all of ($s*) )

// CORRECT:
condition:
    uint16(0) == 0x5a4d
    and filesize < 300KB
    and (
        1 of ($x*)
        or all of ($s*)
    )
```

---

### FM3 — Nested OR Without Proper Grouping

**Level:** Info 🔵
**Check:** Complex nested conditions lack clear grouping

```yara
// UNCLEAR:
condition:
    uint16(0) == 0x5a4d
    and 1 of ($x*) or 2 of ($s*) and 3 of them

// CORRECT:
condition:
    uint16(0) == 0x5a4d
    and (
        1 of ($x*)
        or (
            2 of ($s*)
            and 3 of them
        )
    )
```

---

## RX — Extended Performance Guidelines

*From YARA Performance Guidelines — Manual review items*

### RX1 — Using Hash Loop Instead of String Match

**Level:** Warning 🟡
**Check:** Hash calculation in loop instead of direct string match

```yara
// SLOW:
condition:
   for any var_sect in pe.sections:
      (hash.md5(var_sect.raw_data_offset, 0x100) == "d99eb1e503...")

// FAST:
strings:
   $section = { d9 9e b1 e5 03 ca c3 a1 ... }
condition:
   $section
```

---

### RX2 — Short String Without Position Check

**Level:** Warning 🟡
**Check:** Short string (< 4 bytes) used without `at` position

```yara
// PROBLEMATIC: Searches entire file
strings:
    $mz = "MZ"
condition:
    $mz

// CORRECT: Use uint or add position
condition:
    uint16(0) == 0x5A4D

// OR:
strings:
    $mz = "MZ"
condition:
    $mz at 0  // Still triggers PA1, but better than no position
```

---

### RX3 — Regex With Unbounded Quantifier

**Level:** Warning 🟡
**Check:** Regex uses `.*`, `.+`, or `{x,}` without upper bound

```yara
// SLOW:
$re = /cmd\.exe.*\.dll/
$re = /data.{10,}/     // No upper bound

// BETTER:
$re = /cmd\.{1,50}\.dll/
$re = /data.{10,100}/
```

---

### RX4 — Condition Order Not Short-Circuit Optimized

**Level:** Warning 🟡
**Check:** Expensive checks before cheap checks

```yara
// SLOW:
condition:
    math.entropy(0, filesize) > 7
    and uint16(0) == 0x5A4D
    and filesize < 100KB

// FAST:
condition:
    uint16(0) == 0x5A4D
    and filesize < 100KB
    and math.entropy(0, filesize) > 7
```

---

### RX5 — Using Module for Simple Header Check

**Level:** Warning 🟡
**Check:** Module imported only for basic file type check

```yara
// SLOW: Parses entire PE
import "pe"
condition: pe.is_pe

// FAST: Header check
condition: uint16(0) == 0x5A4D
```

---

### RX6 — Using Magic Module

**Level:** Warning 🟡
**Check:** Magic module used (not available on Windows, slows scanning)

```yara
// SLOW and INCOMPATIBLE:
import "magic"
condition:
    magic.mime_type() == "image/gif"

// FAST:
condition:
    (uint32be(0) == 0x47494638 and uint16be(4) == 0x3961)
    or (uint32be(0) == 0x47494638 and uint16be(4) == 0x3761)
```

---

### RX7 — Loop Over Full File Without Filesize Limit

**Level:** Warning 🟡
**Check:** `for` loop without filesize limitation

```yara
// SLOW on large files:
condition:
    $mz at 0
    and for all i in (1..filesize) : (whatever)

// BETTER:
condition:
    $mz at 0
    and filesize < 100KB
    and for all i in (1..filesize) : (whatever)
```

---

## Summary Table

| ID | Issue | Level | Category |
|----|-------|-------|----------|
|NC1|Missing main category|🟡 Warning|Naming|
|NC2|Incorrect category order|🔵 Info|Naming|
|NC3|Missing date suffix|🔵 Info|Naming|
|NC4|Ambiguous technology tag|🔵 Info|Naming|
|NC5|Platform omission (non-Windows)|🔵 Info|Naming|
|NC6|Modifier not in name|🔵 Info|Naming|
|MF1|Missing mandatory meta field|🟡 Warning|Metadata|
|MF2|Description without "Detects"|🔵 Info|Metadata|
|MF3|Description contains URL|🔵 Info|Metadata|
|MF4|Description length|🔵 Info|Metadata|
|MF5|Author contains URL|🔵 Info|Metadata|
|MF6|Multiple author fields|🔵 Info|Metadata|
|MF7|Date format incorrect|🟡 Warning|Metadata|
|MF8|Unstable/private reference|🟡 Warning|Metadata|
|MF9|Missing score|🔵 Info|Metadata|
|MF10|Score mismatch|🟡 Warning|Metadata|
|MF11|Archive hash vs file hash|🟡 Warning|Metadata|
|MF12|Missing modified date|🔵 Info|Metadata|
|ID1|Inconsistent indentation|🔵 Info|Formatting|
|ID2|No indentation|🟡 Warning|Formatting|
|TR1|Missing pre-selection string|🔵 Info|Strings|
|TR2|Incorrect prefix usage|🟡 Warning|Strings|
|TR3|Missing false positive filter|🔵 Info|Strings|
|TR4|$fp not used in condition|🟡 Warning|Strings|
|SS1|Hex could be text|🔵 Info|Style|
|SS2|Hex not wrapped|🔵 Info|Style|
|SS3|Hex missing comment|🔵 Info|Style|
|SS4|Long identifier|🔵 Info|Style|
|FM1|Missing newline before AND|🔵 Info|Formatting|
|FM2|OR block not indented|🔵 Info|Formatting|
|FM3|Nested OR without grouping|🔵 Info|Formatting|
|RX1|Hash loop vs string|🟡 Warning|Performance|
|RX2|Short string without position|🟡 Warning|Performance|
|RX3|Unbounded quantifier|🟡 Warning|Performance|
|RX4|Condition order|🟡 Warning|Performance|
|RX5|Module for header check|🟡 Warning|Performance|
|RX6|Magic module usage|🟡 Warning|Performance|
|RX7|Loop without filesize limit|🟡 Warning|Performance|
