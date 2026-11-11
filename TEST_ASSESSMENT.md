# Example Assessments

Three rules from public repositories, reviewed with the skill's output format: verdict, findings table, assessed rule. Compile results come from `scripts/validate_rule.py` (YARA-X 1.23 and YARA 4.5.4); IDs are defined in [issue-identifiers.md](yara-rule-skill/references/issue-identifiers.md) and [yaraqa-checks.md](yara-rule-skill/references/yaraqa-checks.md).

## Rule 1: MSIETabularActivex (CVE-2010-0805)

Source: YARA-Rules community, `cve_rules/CVE-2010-0805.yar`

```yara
rule MSIETabularActivex
{
        meta:
                ref = "CVE-2010-0805"
                impact = 7
                hide = true
                author = "@d3t0n4t0r"
        strings:
                $cve20100805_1 = "333C7BC4-460F-11D0-BC04-0080C7055A83" nocase fullword
                $cve20100805_2 = "DataURL" nocase fullword
                $cve20100805_3 = "true"
        condition:
                ($cve20100805_1 and $cve20100805_3) or (all of them)
}
```

**Verdict:** Compiles cleanly, but the condition reduces to "CLSID and the word `true`", so `DataURL` never matters and almost any page that embeds the Tabular Data Control matches.

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| `CL4` | warning | `(A and C) or (all of them)` equals `A and C`: `$cve20100805_2` ("DataURL") can't change the result | Probably meant `all of them`; left to the author because it changes what matches |
| `TR5` | warning | `"true"` occurs in nearly every HTML or JavaScript file, so it adds no specificity | Drop it or replace it with exploit-specific content |
| `NM1` | warning | No main category | `EXPL_CVE_2010_0805_IE_TDC_ActiveX` plus a date suffix |
| `MF1` | warning | No `description` or `date`; reference only as `ref` | Add the fields |
| `MF13` | info | Non-standard keys `ref`, `impact`, `hide` | `reference`; express `impact` as `score` |
| `NC1` | info | `"DataURL" nocase`: letters only, many atom variants | Keep `nocase` only if case varies in samples (HTML attributes are case-insensitive, so it's justified here) |
| `CL2` | info | No `filesize` limit | Add one that fits exploit pages |

Assessed rule:

```yara
rule EXPL_CVE_2010_0805_IE_TDC_ActiveX {   // naming: added EXPL_ category; add a date suffix (e.g. _Mar10) if known
   meta:
      description = "Detects web pages that instantiate the Internet Explorer Tabular Data Control ActiveX object with a DataURL parameter, as used in CVE-2010-0805 exploits"   // added
      author = "@d3t0n4t0r"
      reference = "CVE-2010-0805"   // was: ref
      old_rule_name = "MSIETabularActivex"
      score = 70                    // was: impact = 7
      hide = true
   strings:
      $cve20100805_1 = "333C7BC4-460F-11D0-BC04-0080C7055A83" nocase fullword   // CLSID of the Tabular Data Control: specific, a good $x candidate
      $cve20100805_2 = "DataURL" nocase fullword
      $cve20100805_3 = "true"   // TR5: too generic to add specificity
   condition:
      ($cve20100805_1 and $cve20100805_3) or (all of them)
      // CL4: this equals ($cve20100805_1 and $cve20100805_3); "DataURL" never matters.
      // Probably intended: all of them
      // Better still, drop $cve20100805_3 and use: $cve20100805_1 and $cve20100805_2
      // CL2: consider a filesize limit that fits the exploit pages, e.g. filesize < 1MB
}
```

## Rule 2: Big_Numbers0

Source: YARA-Rules community, `crypto/crypto_signatures.yar`

```yara
rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}
```

**Verdict:** Slows down the whole rule set and matches any file with a 20-character hex token (hashes, IDs, hex dumps). Not usable as a detection; at most a very low-score capability marker.

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| `SI2` | error | YARA 4.x warns `string "$c0" may slow down scanning`; YARA-Forge treats the warning as an error (-70 quality) | Needs a regex with a fixed anchor, or a different approach |
| `RE1` | warning | Regex has no literal run of 4+ bytes, so YARA has no atom and tries it at every offset | Anchor it with context the target really has; a `filesize` check doesn't help (no short-circuit for strings) |
| `TR5` | warning | A lone generic pattern decides the match | Combine with specific strings, or keep it as a low-score marker |
| `NM1` | warning | No main category | `SUSP_Crypto_BigNumber_Hex20_Jul16` |
| `MF7` | warning | `date = "2016-07"` isn't `YYYY-MM-DD` | Full date; YARA-Forge's date parser would otherwise guess the day |
| `MF1` | warning | No `reference` | Add one or "Internal Research" |
| `MF2` | info | Description doesn't start with "Detects" and is under 60 characters (`MF4`) | "Detects hexadecimal numbers of exactly 20 digits stored as text ..." |
| `MF9` | info | No `score` | 0-39 (capability) |

Assessed rule. It still carries `RE1`/`SI2`: no anchor can be added without knowing what the author was after, and the review doesn't invent one.

```yara
rule SUSP_Crypto_BigNumber_Hex20_Jul16 {   // naming: added SUSP_ category and suffix
   meta:
      description = "Detects hexadecimal numbers of exactly 20 digits stored as text, a weak heuristic for embedded crypto constants"   // was: "Looks for big numbers 20:sized"
      author = "_pusher_"
      date = "2016-07"                  // MF7: use YYYY-MM-DD once the day is known
      old_rule_name = "Big_Numbers0"
      score = 20                        // added: capability marker
      // MF1: add reference (source report or "Internal Research")
   strings:
      $c0 = /[0-9a-fA-F]{20}/ fullword ascii   // RE1/SI2: no atom, scanned at every offset of every file
      // If the numbers always follow a known prefix, anchor on it, e.g. /modulus = [0-9a-fA-F]{20}/
   condition:
      $c0
}
```

## Rule 3: DebuggerCheck__PEB

Source: YARA-Rules community, `antidebug_antivm/antidebug_antivm.yar`

```yara
import "pe"

private rule WindowsPE
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}
```

**Verdict:** Matches the word `IsDebugged` in any file type: documentation, source code, debuggers, and security tools included. Fine as a low-score capability tag once it's limited to PE files, which the file already has a private rule for.

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| `CL1` | warning | No file type check although the string is meant for executables | Use the existing `WindowsPE` private rule |
| `TR5` | warning | A single API-structure name triggers the rule; it's common in legitimate tools | Keep the score low or require more anti-debug indicators |
| `RX5` | info | `import "pe"` isn't used by this rule; YARA 4.x runs every imported module on every scanned file | Remove it if no rule in the file uses `pe.*` |
| `NM1` | warning | No main category | `SUSP_AntiDebug_PEB_IsDebugged` |
| `MF1` | warning | No `description` or `date` | Add the fields |
| `MF13` | info | `Author` (capitalized) and `weight` are non-standard | `author`; express the weight as `score` |
| `CL2` | info | No `filesize` limit | Add one |

Assessed rule:

```yara
import "pe"   // RX5: unused here; remove if no rule in this file uses pe.*

private rule WindowsPE
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule SUSP_AntiDebug_PEB_IsDebugged : AntiDebug DebuggerCheck {   // naming: added SUSP_ category; add a date suffix once the date is known
   meta:
      description = "Detects PE files that reference the IsDebugged field of the PEB, a common anti-debugging check"   // added
      author = "naxonez"   // was: Author
      reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
      old_rule_name = "DebuggerCheck__PEB"
      score = 30           // was: weight = 1; capability marker
      // add: date (creation date of the original rule)
   strings:
      $ = "IsDebugged"
   condition:
      WindowsPE            // added: use the existing private rule (CL1)
      and filesize < 20MB  // added: size limit (CL2)
      and any of them
}
```

## Summary

| Rule | Main issue | Severity |
|------|-----------|----------|
| MSIETabularActivex | Condition ignores one of its three strings; generic `"true"` | warning |
| Big_Numbers0 | Regex without atom slows the whole rule set; compile warning | error |
| DebuggerCheck__PEB | No file type restriction for a generic string | warning |

Takeaways:

1. Read the condition as YARA does: `(A and C) or (A and B and C)` is just `A and C`.
2. A regex without a fixed 4-byte run costs every scan, whatever the condition says.
3. Generic strings belong in `$s*` groups or low-score capability rules, not alone in a detection.
4. Validate with both engines: YARA-X accepted `Big_Numbers0` silently, YARA 4.x warned.
