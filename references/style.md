# YARA Style Guide

*Complete reference for YARA rule structure, naming conventions, and best practices. Based on YARA Style Guide.*

> This guide focuses on readability, maintainability, and usability. For performance guidelines, see the Performance Reference.

---

## Introduction

Creating effective YARA rules requires deep understanding of the malware landscape and YARA's capabilities. This guide covers best practices for rule structure and content—helping you create rules that are accurate, concise, and easy to read and maintain.

Whether you're a seasoned security professional or just getting started, following these guidelines ensures your rules integrate well with community tools and workflows.

---

## Rule Naming Convention

Format: `CATEGORY_SUBCATEGORY_DESCRIPTOR_DATE`

The rule name is often the first information shown to a user. It should include:
- Type of threat
- Classification tags
- Descriptive identifier
- Context/period of creation

Values are ordered from **generic to specific**, separated by underscores (`_`).

### Main Categories (Required)

| Prefix | Meaning | Example |
|--------|---------|---------|
|`MAL`|Malware|`MAL_APT_CozyBear_ELF_Apr18`|
|`HKTL`|Hack tool|`HKTL_PS1_CobaltStrike_Oct23`|
|`WEBSHELL`|Web shell|`WEBSHELL_APT_ASP_China_2023`|
|`EXPL`|Exploit code|`EXPL_CVE_2023_1234_WinDrv`|
|`VULN`|Vulnerable component|`VULN_Driver_Apr18`|
|`SUSP`|Suspicious/generic|`SUSP_Anomaly_LNK_Huge_May23`|
|`PUA`|Potentially unwanted app|`PUA_Adware_Win_Trojan`|

### Intention / Background

| Prefix | Meaning |
|--------|---------|
|`APT`|Nation state actor|
|`CRIME`|Criminal activity|
|`ANOMALY`|Generic suspicious characteristics|
|`RANSOM`|Ransomware|

### Types of Malware / File

| Prefix | Meaning |
|--------|---------|
|`RAT`|Remote Access Trojan|
|`Implant`|Persistent implant|
|`Stealer`|Credential/data stealer|
|`Loader`|Payload loader|
|`Crypter`|Encryption/packing tool|
|`PEEXE`|PE executable (often omitted)|
|`DRV`|Driver|

### Operating System

| Prefix | Meaning |
|--------|---------|
|`WIN`|Windows (default, often omitted)|
|`LNX`|Linux|
|`MacOS`|macOS|

### Architecture

| Prefix | Meaning |
|--------|---------|
|`X64`|64-bit (default, often omitted)|
|`X86`|32-bit (often omitted)|
|`ARM`|ARM architecture|
|`SPARC`|SPARC architecture|

### Technology

| Prefix | Meaning |
|--------|---------|
|`PE`/`ELF`|Binary format (PE often omitted)|
|`PS`/`PS1`/`VBS`/`BAT`/`JS`|Script languages|
|`.NET`/`GO`/`Rust`|Programming languages|
|`PHP`/`JSP`/`ASP`|Web technologies|
|`MalDoc`|Malicious document|
|`LNK`|Windows shortcut|
|`ZIP`/`RAR`|Archive formats|

### Modifiers

| Prefix | Meaning |
|--------|---------|
|`OBFUSC`|Obfuscated samples|
|`Encoded`|Encoded versions of payloads|
|`Unpacked`|Unpacked payloads|
|`InMemory`|Code only found when loaded into memory|

### Packers / Installers

| Prefix | Meaning |
|--------|---------|
|`SFX`|Self-extracting archives|
|`UPX`|UPX packed|
|`Themida`|Themida packed|
|`NSIS`|NSIS installer|

### Threat Actor Identifiers

Examples (not exhaustive):
- `APT28`
- `UNC4736`
- `Lazarus`
- `CozyBear`

### Threat Identifiers

Examples:
- `CobaltStrike`
- `PlugX`
- `QakBot`
- `TrickBot`

### Other Useful Keywords

| Prefix | Meaning |
|--------|---------|
|`TINY`|Very small files|
|`HUGE`|Very big files|
|`UAC_Bypass`|UAC bypass technique|
|`Base64`|Base64 related|

### Suffixes to Guarantee Uniqueness

Recommended values:
- **MonthYear**: `May23`, `Jan19`, `Apr18`
- **Number**: `*_1`, `*_2`

### Combining Categories

Combine keywords from generic to specific:

| Pattern | Meaning |
|---------|---------|
|`SUSP_APT_*`|Forensic artifacts from threat actor compromise|
|`MAL_CRIME_RANSOM_LNX_Rust_*`|Rust ransomware for Linux|
|`WEBSHELL_APT_ASP_*`|ASP webshell from nation state actor|

### Full Rule Name Examples

```
APT_MAL_CozyBear_ELF_Loader_Apr18
    └── Rule for APT CozyBear's Linux loader (April 2018)

SUSP_Anomaly_LNK_Huge_Apr22
    └── Suspiciously large link file (April 2022)

MAL_CRIME_RANSOM_PS1_OBFUSC_Loader_May23
    └── Obfuscated PowerShell loader from ransomware campaign (May 2023)

WEBSHELL_APT_ASP_China_2023
    └── ASP webshell from nation state actor (2023)
```

---

## Rule Structure

### Complete Template

```yara
rule RULE_NAME : TAGS {
    meta:
        description = "Detects ..."
        author = "Author Name / Company / Org"
        date = "YYYY-MM-DD"
        reference = "URL / Internal Research"
        score = [0-100]
        [OPTIONAL META DATA FIELDS]
    strings:
        $string1 = "value"
    condition:
        header_check
        file_size_limitation
        other_limitations
        string_combinations
        false_positive_filters
}
```

### Rule Tags

While tags can classify rules, we recommend putting **main categories in the rule name** for straightforward identification. Additional tags less directly related to the main category go in a `tags` meta field:

```yara
rule MAL_APT_CozyBear_Win_Trojan_Apr18 {
    meta:
        tags = "APT28, Gazer, phishing"
    ...
}
```

Tags can denote threat actors, malware families, or attack types.

---

## Indentation

Use 3-4 spaces or tabs consistently.

**DON'T:**
```yara
rule MY_RULE {
meta:
description = "bad"
author = "name"
strings:
$s1 = "eval("
condition:
filesize < 10KB and all of them 
}

rule MY_RULE {
 meta:
  description = "inconsistent"
 strings:
  $s1 = "eval("
}
```

**DO:**
```yara
rule MY_RULE {
   meta:
      description = "proper indentation"
      author = "Name"
   strings:
      $s1 = "eval("
      $s2 = "WScript.Shell"
   condition:
      filesize < 10KB and all of them 
}
```

---

## Meta Data

The meta section provides additional information about the rule.

### Mandatory Fields

| Field | Format | Notes |
|-------|--------|-------|
|`description`|String|60-400 chars, start with "Detects ...", no URLs|
|`author`|String|Full name or Twitter handle, comma-separated for multiple|
|`reference`|String|URL or "Internal Research"|
|`date`|YYYY-MM-DD|Creation date only (use `modified` for updates)|

#### Description

- **Preferred Length**: 60-400 characters
- **Avoid**: URLs (use `reference` field)
- **Start with**: "Detects ..."

#### Author

- **Format**: Full name for clear attribution
- **Social**: Twitter handles preferable for social media credit
- **Multiple**: Use comma-separated list, not multiple author fields

#### Reference

- **What**: Link to report, source code, website, or "Internal Research"
- **Avoid**: Unstable links, private/restricted resources
- **Prefer**: Public, stable sources

#### Date

- **Format**: YYYY-MM-DD (creation date only)
- **Updates**: Use separate `modified` field

### Optional Fields

| Field | Format | Purpose |
|-------|--------|---------|
|`hash`|String(s)|MD5, SHA1, SHA256. SHA256 preferred. Use multiple times for multiple hashes.|
|`score`|0-100|Severity × specificity for prioritization|
|`modified`|YYYY-MM-DD|Last modification date|
|`old_rule_name`|String|Previous name for searchability after rename|
|`tags`|Comma-separated|Additional classification tags|
|`license`|String|License identifier|

#### Hash

- **Preferred**: SHA256
- **Direct reference**: Hash of the file the rule targets
- **Avoid**: Archive hashes where sample was found
- **Exception**: Memory-based matches can use memory form hash

#### Score

| Score | Significance | Examples |
|-------|--------------|----------|
|0-39|Very Low|Capabilities, common packers|
|40-59|Noteworthy|Uncommon packers, PE header anomalies|
|60-79|Suspicious|Heuristics, obfuscation, generic detection|
|80-100|High|Direct malware/hack tool matches|

---

## Rule Strings

### String Identifiers

**Opt for readable string values.** Avoid hex when standard strings work. Exception: control characters (`\t`, `\n`).

**Avoid:**
```yara
$s1 = { 46 72 6F 6D 42 61 73 65 36 34 53 74 72 69 6E 67 28 }
```

**Recommended:**
```yara
$s1 = "FromBase64String("
```

#### Choose Efficient Identifiers

Use concise, descriptive identifiers.

**Avoid:**
```yara
$string_value_footer_1 = "eval("
$selection_14 = "eval("
condition:
   all of (selection_*) and 3 of ($string_value_footer)
```

**Recommended:**
```yara
$s1 = "eval("
$eval = "eval("
condition:
   all of (s*) and $eval
```

### Hex Identifiers

Add ASCII comments for readability:

```yara
/* )));
IEX( */
$s1 = { 29 29 29 3b 0a 49 45 58 28 0a }
```

**Wrap at 16-byte intervals** for long values:

```yara
$s1 = { 2c 20 2a 79 6f 77 2e 69 20 26 20 30 78 46 46 29 
        3b 0a 20 20 70 72 69 6e 74 66 20 28 28 28 2a 79 
        6f 77 2e 69 20 26 20 30 78 66 66 29 20 3d 3d 20 }
```

### Categorizing Strings: The Triad Approach ($x*, $s*, $a*)

Organize strings into three categories:

#### 1. Highly Specific Strings ($x*)
Unique identifiers specific to a particular threat. Highly reliable indicators.

#### 2. Grouped Strings ($s*)
Not distinctive individually, but significant when found together as a group.

#### 3. Pre-Selection Strings ($a*)
Commonly found strings that narrow file type/format. Optimize performance by limiting search scope.

**Example:**
```yara
rule HKTL_Go_EasyHack_Oct23 {
   meta:
      description = "Detects a Go based hack tool"
      author = "John Galt"
      date = "2023-09-13"
      reference = "https://example.com/EasyHack"
   strings:
      $a1 = "Go build"              // Pre-selection (file type)

      $x1 = "Usage: easyhack.exe -t [IP] -p [PORT]"
      $x2 = "c0d3d by @EdgyHackerFreak"

      $s1 = "main.inject"
      $s2 = "main.loadPayload"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20MB
      and $a1 
      and (
        1 of ($x*)
        or all of ($s*)
      )
      or 4 of them
}
```

### False Positive Filters ($fp*)

Strings indicating benign patterns. Prefix with `fp`.

```yara
rule HKTL_Go_EasyHack_Oct23 {
   meta:
      description = "Detects a Go based hack tool"
      author = "John Galt"
   strings:
      $a1 = "Go build"

      $s1 = "main.inject"
      $s2 = "main.loadPayload"

      $fp1 = "Copyright by CrappySoft" wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20MB
      and $a1 
      and all of ($s*)
      and not 1 of ($fp*)
}
```

---

## Rule Condition

Conditions specify when a rule matches. Write for clarity and performance.

**Template:**
```yara
condition:
    header_check
    and file_size_limitation
    and other_limitations
    and string_combinations
    and false_positive_filters
```

### Formatting Guidelines

- New line before `and`
- Indent blocks for `or` groups
- Group related conditions with parentheses

**Example:**
```yara
condition:
    uint16(0) == 0x5a4d 
    and filesize < 300KB 
    and pe.number_of_signatures == 0
    and (
        1 of ($x*)
        or 3 of them
    )
    and not 1 of ($fp*)
```

**Multi-value conditions:**
```yara
condition:
    (
        uint16(0) == 0x5a4d     // MZ marker
        or uint16(0) == 0x457f  // ELF marker
    )
    and filesize < 300KB 
    and pe.number_of_signatures == 0
    and all of ($s*)
    and not 1 of ($fp*)
```

---

## Tweaks

### String Matching vs. Hashing

Some rules use hashing to identify patterns:

```yara
condition:
   for any var_sect in pe.sections:
      (hash.md5(var_sect.raw_data_offset, 0x100) == "d99eb1e503...")
```

This is **less efficient** than direct string matching. YARA excels at pattern matching; calculating hashes for each section is resource-intensive.

**Better approach:** Incorporate the bytes directly as a hex string:

```yara
strings:
   $section_hash = { d9 9e b1 e5 03 ca c3 a1 ... }
condition:
   $section_hash
```

This leverages YARA's efficient string matching without the CPU overhead of hashing.

---

## Quick Reference

### String Prefixes

| Prefix | Use | Condition Example |
|--------|-----|-------------------|
|`$x*`|Unique signatures|`1 of ($x*)`|
|`$s*`|Grouped strings|`all of ($s*)` or `3 of ($s*)`|
|`$a*`|Pre-selection (file type)|`$a1` alone or combined|
|`$fp*`|False positive filters|`not 1 of ($fp*)`|

### Score Ranges

| Range | Level |
|-------|-------|
|0-39|Very Low|
|40-59|Noteworthy|
|60-79|Suspicious|
|80-100|High|

### Date Format

Always use: `YYYY-MM-DD`

### Indentation

Use 3-4 spaces consistently.
