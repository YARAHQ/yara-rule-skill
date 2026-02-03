# YARA Style Guide Reference

*Quick reference for YARA rule structure and naming. Derived from Neo23x0/YARA-Style-Guide.*

## Rule Naming Convention

Format: `CATEGORY_SUBCATEGORY_DESCRIPTOR_DATE`

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

### Optional Classifiers (Combine as needed)

**Intention/Background:**
- `APT` — Nation state actor
- `CRIME` — Criminal activity
- `ANOMALY` — Suspicious characteristics
- `RANSOM` — Ransomware

**Malware Types:**
- `RAT`, `Implant`, `Stealer`, `Loader`, `Crypter`

**Platform:**
- `WIN` (default, often omitted), `LNX`, `MacOS`
- `X64` (default), `X86`, `ARM`

**Technology:**
- `PE`/`ELF`, `PS`/`PS1`/`VBS`/`BAT`/`JS`, `.NET`/`GO`/`Rust`
- `PHP`/`JSP`/`ASP`, `MalDoc`, `LNK`, `ZIP`

**Modifiers:**
- `OBFUSC` — Obfuscated
- `Encoded` — Encoded payload
- `Unpacked` — Unpacked payload
- `InMemory` — Memory-only detection

**Suffix for Uniqueness:**
- `May23`, `Jan19` — MonthYear
- `_1`, `_2` — Numeric

### Full Examples

```yara
APT_MAL_CozyBear_ELF_Loader_Apr18
SUSP_Anomaly_LNK_Huge_Apr22
MAL_CRIME_RANSOM_PS1_OBFUSC_Loader_May23
WEBSHELL_APT_ASP_China_2023
```

## Rule Structure Template

```yara
rule CATEGORY_NAME_DATE : tags {
    meta:
        description = "Detects ..."
        author = "Name / Company / Org"
        date = "YYYY-MM-DD"
        reference = "URL / Internal Research"
        score = 75              // 0-100 (optional)
        modified = "YYYY-MM-DD" // If updated (optional)
        hash = "sha256..."      // Sample hash (optional)
        tags = "APT28, TrickBot" // Extra tags (optional)
    strings:
        $x1 = "unique identifier"
        $s1 = "grouped string"
        $a1 = "preselection"
        $fp1 = "false positive filter"
    condition:
        header_check
        and file_size_limitation
        and other_limitations
        and string_combinations
        and not 1 of ($fp*)
}
```

## String Naming Convention ($x, $s, $a, $fp)

| Prefix | Purpose | Example |
|--------|---------|---------|
|`$x*`|Highly specific (unique)|`$x1 = "CozyBearImplant_v2.1"`|
|`$s*`|Grouped (need multiple)|`$s1 = "cmd.exe"`, `$s2 = "powershell.exe"`|
|`$a*`|Pre-selection (file type)|`$a1 = "MZ"`, `$a2 = "Go build"`|
|`$fp*`|False positive filter|`$fp1 = "Copyright Microsoft"`|

### Example Usage

```yara
strings:
    $a1 = "Go build"              // Pre-select Go binaries
    
    $x1 = "Usage: easyhack.exe"   // Unique signature
    $x2 = "c0d3d by @HackerFreak"
    
    $s1 = "main.inject"
    $s2 = "main.loadPayload"
    
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
```

## Indentation & Formatting

Use 3-4 spaces or tabs consistently:

```yara
rule GOOD_EXAMPLE {
   meta:
      description = "Good indentation"
      author = "Name"
   strings:
      $s1 = "value"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 300KB
      and (
          1 of ($x*)
          or 3 of them
      )
      and not 1 of ($fp*)
}
```

## Meta Fields Reference

### Mandatory

| Field | Format | Notes |
|-------|--------|-------|
|`description`|String|Start with "Detects ...", 60-400 chars, no URLs|
|`author`|String|Full name or Twitter handle, comma-separated for multiple|
|`reference`|String|URL or "Internal Research"|
|`date`|YYYY-MM-DD|Creation date (use `modified` for updates)|

### Optional

| Field | Format | Purpose |
|-------|--------|---------|
|`score`|0-100|Severity × specificity (80-100 = high confidence malware)|
|`hash`|String(s)|SHA256 preferred (can use multiple times)|
|`modified`|YYYY-MM-DD|Last update date|
|`old_rule_name`|String|For renamed rules, old name for searchability|
|`tags`|Comma-separated|Extra classification tags|
|`license`|String|License identifier|

### Score Guidelines

| Score | Level | Use Case |
|-------|-------|----------|
|0-39|Very Low|Capabilities, common packers|
|40-59|Noteworthy|Uncommon packers, PE anomalies|
|60-79|Suspicious|Heuristics, obfuscation, generic rules|
|80-100|High|Direct malware/hack tool matches|

## Hex String Formatting

```yara
// Add ASCII comment for readability
/* )));\nIEX( */
$s1 = { 29 29 29 3b 0a 49 45 58 28 0a }

// Wrap at 16 bytes
$s1 = { 2c 20 2a 79 6f 77 2e 69 20 26 20 30 78 46 46 29 
        3b 0a 20 20 70 72 69 6e 74 66 20 28 28 28 2a 79 
        6f 77 2e 69 20 26 20 30 78 66 66 29 20 3d 3d 20 }
```

## Condition Formatting

- New line before `and`
- Indent blocks for `or` groups
- Group related conditions with parentheses

```yara
condition:
    uint16(0) == 0x5a4d
    and filesize < 300KB
    and pe.number_of_signatures == 0
    and (
        1 of ($x*)
        or (
            2 of ($s*)
            and 3 of them
        )
    )
    and not 1 of ($fp*)
```
