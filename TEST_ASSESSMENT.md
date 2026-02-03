# YARA Rule Assessment Report

## Test Rules from Public Repositories

---

## Rule 1: MSIETabularActivex (CVE-2010-0805)

**Source:** YARA-Rules Community / CVE Rules  
**File:** `cve_rules/CVE-2010-0805.yar`

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

### Issues Found

| ID | Severity | Issue | Fix |
|----|----------|-------|-----|
| **Style** | 🔵 Info | Rule name doesn't follow convention | Should be `EXPL_CVE_2010_0805_IE_Tabular_ActiveX` |
| **SM5** | 🟡 Warning | `"true"` with `fullword` - problematic end char | `$cve20100805_3` ends with `"true"` but has no `fullword`. Actually OK here, but `$cve20100805_2` uses `fullword` on `"DataURL"` which is fine |
| **NC1** | 🔵 Info | `nocase` on GUID without special chars | GUID has digits, so actually OK (atom quality is good) |
| **Logic** | 🟡 Warning | Condition logic is redundant | `($a and $c) or (all of them)` = `all of them` since if all match, $a and $c match |
| **Style** | 🔵 Info | Meta fields non-standard | Use `reference` not `ref`, `description` missing, `date` missing |
| **CE1** | 🔴 Error | Actually none - strings match condition |

### Assessment: ⚠️ **Needs Improvement**

**Recommendations:**
1. Simplify condition to just `all of them` (the `or` clause is redundant)
2. Add proper meta: `description`, `date`, use `reference` not `ref`
3. Rename to: `EXPL_CVE_2010_0805_ActiveX_DataURL`
4. Consider if `"true"` is specific enough (very common string)

---

## Rule 2: Big_Numbers0-5 Series

**Source:** YARA-Rules Community / Crypto Signatures  
**File:** `crypto/crypto_signatures.yar`

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

### Issues Found

| ID | Severity | Issue | Fix |
|----|----------|-------|-----|
| **RE1** | 🟡 Warning | Regex without 4+ byte anchor | Pattern `[0-9a-fA-F]{20}` has NO fixed anchor |
| **PA2** | 🟡 Warning | Short atom (technically) | While {20} is long, no fixed bytes means atom extraction fails |
| **Perf** | 🔴 Critical | **Catastrophic regex** | Matches every hex string of exactly 20 chars - will match millions of times |
| **Style** | 🔵 Info | Rule name | Should be `SUSP_BigNumbers_20HexChars` or similar |

### Assessment: 🔴 **Performance Disaster**

**Analysis:**
This rule uses `/[0-9a-fA-F]{20}/` - a regex with **NO fixed anchor**. YARA cannot extract a 4-byte atom from this pattern. This means:

1. **Atom extraction fails** - No fixed bytes to search for
2. **Naïve matching** - Regex engine must test every single offset in the file
3. **Millions of matches** - Any file with hex strings (executables, JSON, URLs) will match repeatedly
4. **"Too many matches" error** or **extremely slow scanning**

**Recommendations:**
```yara
// BAD - No anchor, will cause performance issues
$c0 = /[0-9a-fA-F]{20}/ fullword ascii

// BETTER - If you need this, add context
$c0 = /hash[=:][0-9a-fA-F]{20}/ fullword ascii

// BEST - Use specific prefix if known
$c0 = /sha1[=:][0-9a-fA-F]{40}/ fullword ascii
```

These rules should probably be **deprecated** or given very specific filetype preconditions.

---

## Rule 3: DebuggerCheck__PEB

**Source:** YARA-Rules Community / Antidebug Antivm  
**File:** `antidebug_antivm/antidebug_antivm.yar`

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

### Issues Found

| ID | Severity | Issue | Fix |
|----|----------|-------|-----|
| **PA2** | 🟡 Warning | Short atom: `"IsDebugged"` has 10 chars but common substring | Actually OK length-wise |
| **SM5** | 🟡 Warning | String starts with uppercase I, `fullword` not used | Could match inside `ThisDebuggedThing` |
| **Logic** | 🔴 Critical | **Rule has no filetype restriction!** | Will match `IsDebugged` in ANY file type |
| **Style** | 🔵 Info | Anonymous string `$ =` | Better: `$s1 = "IsDebugged"` |
| **Style** | 🔵 Info | `Author` vs `author` (case) | Use lowercase `author` |
| **MO1** | 🔵 Info | `import "pe"` defined but not used | The import is in the file but rule doesn't reference `pe` module |
| **DU1** | 🔵 Info | Multiple rules with same structure | 20+ rules with identical pattern, just different strings |

### Assessment: ⚠️ **High False Positive Risk**

**Analysis:**
The rule `DebuggerCheck__PEB` (and 20+ similar rules in the file) matches `"IsDebugged"` **in any file type**. This is a generic Windows API string that could appear in:
- Documentation
- Legitimate debug tools
- Security software
- Analysis tools
- Blogs/articles about debugging

**Recommendations:**
```yara
// CURRENT - Matches anything
condition:
    any of them

// BETTER - Restrict to PE files
condition:
    uint16(0) == 0x5A4D and
    any of them

// BEST - Use the private rule that's already defined!
condition:
    WindowsPE and
    $s1

// EVEN BETTER - Add filesize limit
condition:
    uint16(0) == 0x5A4D and
    filesize < 10MB and
    $s1
```

Also consider combining these 20+ single-string rules into fewer rules with multiple strings:
```yara
rule SUSP_AntiDebug_APIs {
    strings:
        $s1 = "IsDebugged"
        $s2 = "NtGlobalFlags"
        $s3 = "CheckRemoteDebuggerPresent"
        // ... etc
    condition:
        uint16(0) == 0x5A4D and
        2 of them  // Require at least 2 indicators
}
```

---

## Summary

| Rule | Quality | Main Issue |
|------|---------|------------|
| MSIETabularActivex | ⚠️ Fair | Redundant condition, non-standard naming |
| Big_Numbers0-5 | 🔴 Poor | Catastrophic regex performance |
| DebuggerCheck__PEB | ⚠️ Fair | No filetype restriction = high FP rate |

**Key Takeaways:**
1. **Always anchor regex** - `/[0-9a-fA-F]{20}/` is a performance killer
2. **Restrict filetypes** - Don't match API strings in every file type
3. **Follow naming conventions** - Use standard prefixes like `SUSP_`, `MAL_`, `EXPL_`
4. **Simplify conditions** - Remove redundant logic like `($a and $c) or all of them`
