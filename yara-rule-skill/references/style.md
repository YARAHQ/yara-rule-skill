# YARA Style Guide Reference

Source: [Neo23x0/YARA-Style-Guide](https://github.com/Neo23x0/YARA-Style-Guide). The guide covers readability, maintainability, and usability. Performance is covered in [performance.md](performance.md). Sections marked *Skill addition* extend the guide; they aren't part of it.

## Contents

- [Rule names](#rule-names)
- [Rule structure](#rule-structure)
- [Indentation](#indentation)
- [Tags](#tags)
- [Metadata](#metadata)
- [Strings](#strings)
- [Conditions](#conditions)
- [Tweaks](#tweaks)
- [Complete example](#complete-example)

## Rule names

The rule name is often the first, sometimes the only, information a user sees. It should state the type of threat, classifying tags, a descriptive identifier, and the period the rule was written in.

- Values are separated by `_`.
- Values go from **generic to specific**.
- The lists below are examples, not limits. Extend them when needed.

YARA identifier rules apply: letters, digits, and `_` only; no leading digit; at most 128 characters; case sensitive.

### Main categories

Every rule name starts with one of these:

| Prefix | Meaning | Use for |
|--------|---------|---------|
| `MAL` | Malware | Malware |
| `HKTL` | Hack tool | Hack tools |
| `WEBSHELL` | Web shell | Web shells |
| `EXPL` | Exploit | Exploit code: proof-of-concept code, exploit payloads |
| `VULN` | Vulnerability | Vulnerable components: drivers, Java libraries |
| `SUSP` | Suspicious | Anomalies and suspicious capabilities: obfuscated code, shellcode, suspicious import combinations, suspicious command sets in scripts |
| `PUA` | Potentially unwanted application | PUAs |

### Classifiers

| Group | Values |
|-------|--------|
| Intention / background | `APT` (nation-state actor), `CRIME` (crime group), `ANOMALY` (generic suspicious characteristics), `RANSOM` |
| Malware / file type | `RAT`, `Implant`, `Stealer`, `Loader`, `Crypter`, `PEEXE` (often omitted), `DRV` (driver) |
| Operating system | `WIN` (often omitted), `LNX`, `MacOS` |
| Architecture | `X64` (often omitted), `X86` (often omitted), `ARM`, `SPARC` |
| Technology | `PE` (often omitted), `ELF`, `PS`, `PS1`, `VBS`, `BAT`, `JS`, `NET`, `GO`, `Rust`, `PHP`, `JSP`, `ASP`, `MalDoc`, `LNK`, `ZIP`, `RAR` |
| Modifiers | `OBFUSC` (obfuscated), `Encoded` (encoded payload), `Unpacked` (unpacked payload), `InMemory` (only present when loaded in memory) |
| Packers / installers | `SFX` (self-extracting archive), `UPX`, `Themida`, `NSIS` |
| Threat actors (examples) | `APT28`, `UNC4736`, `Lazarus` |
| Threats (examples) | `CobaltStrike`, `PlugX`, `QakBot` |
| Other keywords | `TINY` (very small files), `HUGE` (very big files), `UAC_Bypass`, `Base64` |

### Uniqueness suffixes

Suffixes lower the chance that two analysts pick the same name:

- Month and year: `May23`, `Jan19`
- Number: `_1`, `_2`

Both can be combined: `..._Mar21_1`.

### Combining categories

| Pattern | Meaning |
|---------|---------|
| `SUSP_APT_*` | Forensic artifacts on systems compromised by a threat actor: tool output, command-line flag combinations, redirected output, log contents |
| `MAL_CRIME_RANSOM_LNX_Rust_*` | Malware of a ransomware crime group, written in Rust, for Linux |
| `WEBSHELL_APT_ASP_*` | ASP web shell used by a nation-state actor |

### Examples

| Name | Meaning |
|------|---------|
| `MAL_APT_CozyBear_ELF_Loader_Apr18` | April 2018 rule for a Cozy Bear loader for Linux |
| `SUSP_Anomaly_LNK_Huge_Apr22` | April 2022 rule for suspiciously big link files |
| `MAL_CRIME_RANSOM_PS1_OBFUSC_Loader_May23` | May 2023 rule for an obfuscated PowerShell loader seen in a ransomware campaign |

## Rule structure

```yara
rule RULE_NAME : TAGS {
   meta:
      description = "Detects ..."
      author = "Author Name / Company / Org"
      date = "YYYY-MM-DD"
      reference = "URL / Internal Research"
      score = 75
      // optional metadata fields
   strings:
      $s1 = "value"
   condition:
      header_check
      and file_size_limitation
      and other_limitations
      and string_combinations
      and false_positive_filters
}
```

## Indentation

Use 3 or 4 spaces, or tabs, consistently. Indent section keywords once and their content twice.

Don't:

```yara
rule MY_RULE {
meta:
description = "my test rule"
author = "John Galt"
strings:
$s1 = "eval("
$s2 = "WScript.Shell"
condition:
filesize < 10KB and all of them
}
```

Do:

```yara
rule MY_RULE {
   meta:
      description = "my test rule"
      author = "John Galt"
   strings:
      $s1 = "eval("
      $s2 = "WScript.Shell"
   condition:
      filesize < 10KB and all of them
}
```

## Tags

Put the main categories in the rule name. Put additional, less directly related tags (actor names, families, attack types) in a `tags` metadata field as a comma-separated list:

```yara
rule MAL_APT_Gazer_Backdoor_Aug17 {
   meta:
      description = "Detects the Gazer backdoor used by Turla"
      tags = "Turla, Gazer, backdoor"
   ...
}
```

YARA's native rule tags (`rule NAME : TAG1 TAG2`) remain valid. YARA-Forge merges them with the `tags` field (see [yara-forge.md](yara-forge.md#metadata-normalization)).

## Metadata

### Mandatory fields

| Field | Format | Guidance |
|-------|--------|----------|
| `description` | String, 60-400 characters | Start with "Detects ...". State what the rule detects and its scope. No URLs. |
| `author` | String | Author, group, or organization. Full name preferred; Twitter/X handles fine. No URLs. One field; several authors comma-separated. |
| `reference` | String (URL preferred) | Report, source repository, website, private report name, or identifier the rule derives from. Prefer stable public links; avoid links that expire or need a login. Use "Internal Research" for your own work. |
| `date` | `YYYY-MM-DD` | Creation date only. Not the publication or modification date. |

### Optional fields

| Field | Format | Purpose |
|-------|--------|---------|
| `hash` | MD5, SHA1, or SHA256; SHA256 preferred | Sample(s) the rule was written for. Repeat the field for multiple samples. |
| `score` | Integer 0-100 | Severity × specificity, for prioritizing matches |
| `modified` | `YYYY-MM-DD` | Last modification |
| `old_rule_name` | String | Previous name, so searches for it still work after a rename |
| `tags` | Comma-separated string | Additional classifiers |
| `license` | String | License the rule is released under |

### Hash

- Use the hash of the file the rule actually matches.
- Don't use the hash of an archive the sample came in.
- Exception: rules meant for memory may use the hash of the unpacked or loaded form, if the on-disk sample doesn't match.

### Score

The score combines **severity** (how harmful the detected thing is) and **specificity** (how uniquely the rule identifies it). Analysts use it to prioritize matches.

| Score | Significance | Examples |
|-------|--------------|----------|
| 0-39 | Very low | Capabilities, packers; often combined with other rules for a higher total |
| 40-59 | Noteworthy | Uncommon packers or packers popular with malware; PE header anomalies |
| 60-79 | Suspicious | Heuristic matches, obfuscation rules, generic detection rules |
| 80-100 | High | Malware, hack tools, and other malicious items identified with high accuracy |

*Skill addition:* a `SUSP_` rule normally scores 60-79 and a `MAL_` or `HKTL_` rule with specific strings 80-100. A mismatch (a `SUSP_` heuristic at 95, a `MAL_` family rule at 45) is worth questioning in a review.

## Strings

### Readable values

Write text as text. Hex is for binary data and for strings with control characters (`\t`, `\n`).

```yara
$s1 = { 46 72 6F 6D 42 61 73 65 36 34 53 74 72 69 6E 67 28 }  // avoid
$s1 = "FromBase64String("                                       // prefer
```

### Identifiers

Use concise or descriptive identifiers. Long, meaningless ones make conditions hard to read.

```yara
// avoid
$string_value_footer_1 = "eval("
$selection_14 = "eval("

// prefer
$s1 = "eval("
$eval = "eval("
```

### Hex strings

When hex encodes mostly readable text, add the readable form as a comment. Wrap long hex strings every 16 bytes so the length is visible without scrolling:

```yara
/* )));\nIEX( */
$s1 = { 29 29 29 3b 0a 49 45 58 28 0a }

$s2 = { 2c 20 2a 79 6f 77 2e 69 20 26 20 30 78 46 46 29
        3b 0a 20 20 70 72 69 6e 74 66 20 28 28 28 2a 79
        6f 77 2e 69 20 26 20 30 78 66 66 29 20 3d 3d 20 }
```

### The triad: `$x*`, `$s*`, `$a*`

1. **Highly specific strings (`$x*`):** unique to the threat. Their presence alone is a reliable indicator.
2. **Grouped strings (`$s*`):** not distinctive alone, but indicative when found together.
3. **Pre-selection strings (`$a*`):** common strings that don't indicate a threat but narrow the file type or format.

### False positive filters (`$fp*`)

Strings that indicate benign content get the `fp` prefix. If a rule matches malicious patterns and also a `$fp*` string, it doesn't fire:

```yara
condition:
   ...
   and not 1 of ($fp*)
```

### String count *(Skill addition)*

Prefer 3-7 well-chosen strings and rarely more than 10. Long lists usually contain redundant or weak strings, are harder to maintain, and cost memory. yaraQA reports more than 20 strings (`HS1`) and more than 40 (`HS2`), not counting strings named `$fp*`, `$filter*`, `$false*`, or `$exclu*`. When trimming:

- Keep the most specific strings.
- Drop strings that also appear in goodware.
- Drop near-duplicates (log lines with the same prefix, similar paths).
- Keep at most one or two opcode patterns.

### String diversity *(Skill addition)*

Pick strings from different categories so one change by the malware author doesn't break the rule:

| Category | Examples |
|----------|----------|
| Usage / help text | `"Usage: tool.exe <host> <port>"` |
| Error and log messages | `"[ERROR] Connection failed"`, `"[-] Injection failed: %d"` |
| Format strings | `"%s:%d/%s"` |
| Build artifacts | `"\\Release\\hackme.pdb"`, `"/home/dev/src/main.go"` |
| File paths and names | `"C:\\Users\\Public\\svc.dat"`, `"/tmp/.X11-cache"` |
| Mutex, pipe, event names | `"Global\\M7x2Q"`, `"\\\\.\\pipe\\msupd"` |
| Network | C2 URL paths, unusual user agents, custom headers |
| Code identifiers | `"main.injectPayload"`, `"StealCookies"`, `"g_hConfig"` |
| Opcodes | `{ 8B 45 08 33 C9 8A 0C 01 80 F1 ?? }` |

Fragile (one prefix change breaks all of them):

```yara
$s1 = "[DEBUG] WinHTTP session opened"
$s2 = "[DEBUG] Download URL: %s"
$s3 = "[DEBUG] Download complete!"
$s4 = "[DEBUG] Starting PE execution"
```

Resilient:

```yara
$x1 = "Usage: stager.exe <url>"   // usage text
$s1 = "stager_debug.log"          // file name
$s2 = "https://%s:%d/%s"          // format string
$s3 = "[DEBUG] Download URL: %s"  // one log line
```

## Conditions

### Order

```yara
condition:
   header_check
   and file_size_limitation
   and other_limitations
   and string_combinations
   and false_positive_filters
```

### Layout

- Put a line break before each `and`.
- Wrap `or` combinations in a parenthesized, indented block.
- Nest blocks the same way.

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

```yara
condition:
   uint16(0) == 0x5a4d
   and filesize < 300KB
   and (
      1 of ($x*)
      or (
         2 of ($s*)
         and 3 of them
      )
   )
```

Alternative values (several file types) use the same block format:

```yara
condition:
   (
      uint16(0) == 0x5a4d       // MZ marker
      or uint32(0) == 0x464c457f  // ELF marker
   )
   and filesize < 300KB
   and all of ($s*)
   and not 1 of ($fp*)
```

### Top-level `or N of them`

The guide's triad example ends with `... or 4 of them` outside the parentheses. Because `and` binds tighter than `or`, this reads as "(PE and size limit and pre-selection and specific strings) **or** any 4 strings". The second branch deliberately matches without header and size checks, for example in memory dumps or in payloads embedded in other files. Keep it only when that is intended; otherwise every `or` belongs inside parentheses.

## Tweaks

### String matching instead of hashing

Some rules loop over PE sections and hash part of each one:

```yara
condition:
   for any var_sect in pe.sections:
      ( hash.md5(var_sect.raw_data_offset, 0x100) == "d99eb1e503cac3a1e90450d0c07e3ffc" )
```

YARA is built for pattern matching; hashing every section costs CPU on every PE file. Put the 256 bytes in the rule as a hex string instead:

```yara
strings:
   $sect_start = { d9 9e b1 e5 ... }  // the 0x100 bytes, wrapped at 16
condition:
   $sect_start
```

## Complete example

```yara
rule HKTL_Go_EasyHack_Oct23 {
   meta:
      description = "Detects EasyHack, a Go based hack tool that injects payloads into remote processes"
      author = "John Galt"
      reference = "https://example.com/EasyHack"
      date = "2023-10-23"
      score = 80
   strings:
      $a1 = "Go build ID: \""

      $x1 = "Usage: easyhack.exe -t [IP] -p [PORT]"
      $x2 = "c0d3d by @EdgyHackerFreak"

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
}
```
