# YARA Rule Skill (Community Edition)

An **LLM agent skill** for writing, reviewing, and optimizing YARA rules. It puts the practices behind [YARA-Forge](https://github.com/YARAHQ/yara-forge) and [yaraQA](https://github.com/Neo23x0/yaraQA) into your AI assistant's context.

## What This Skill Does

With the skill installed, your agent can:

- **Write** rules from samples or strings you provide, following the YARA Style Guide
- **Review** existing rules and report findings with yaraQA and guideline IDs
- **Optimize** slow rules and fix "too many matches" errors
- **Validate** every rule it outputs by compiling it with YARA-X and YARA 4.x
- **Prepare** rules for YARA-Forge (no compile warnings, explicit score, clean metadata)

Paste a rule and ask, or describe what you want to detect.

## Installation

### Option 1: Copy the skill folder (recommended)

```bash
git clone https://github.com/YARAHQ/yara-rule-skill.git

# Claude Code (personal skills)
cp -r yara-rule-skill/yara-rule-skill ~/.claude/skills/

# OpenClaw
cp -r yara-rule-skill/yara-rule-skill ~/.openclaw/skills/
```

Install the validator dependencies:

```bash
pip install -r yara-rule-skill/yara-rule-skill/scripts/requirements.txt
```

### Option 2: Package as a .skill file

```bash
git clone https://github.com/YARAHQ/yara-rule-skill.git
cd yara-rule-skill
python3 installer/package_skill.py
cp yara-rule-skill.skill ~/.openclaw/skills/
```

### Supported platforms

Any agent that supports `SKILL.md` skills:

- **Claude Code**: `~/.claude/skills/` (personal) or `.claude/skills/` (project)
- **OpenClaw**: `~/.openclaw/skills/`
- **Other agents**: see your platform's documentation

## Usage

The skill activates when you talk about YARA rules.

### Review a rule
> "Review this YARA rule and suggest improvements"

You get a verdict, a findings table (ID, severity, fix), and your rule back with minimal fixes and inline comments. The returned rule always compiles.

### Assess public rules
> "Assess the quality of this rule I found online"

Checks logic errors (conditions that never match, `fullword` on paths), performance (short atoms, unanchored regex, expensive conditions), false-positive risk, metadata, and naming.

### Diagnose performance
> "This rule causes performance issues, why?"

Walks through the Performance Guidelines' checklist: regex quantifiers, short or uniform atoms, alternations, loops, modules.

### Write a rule
> "Write a YARA rule for these strings from the sample"

Produces a named, documented rule with grouped strings (`$x*`, `$s*`, `$a*`, `$fp*`), validated before it's returned.

## What's Included

### Sources

| Source | Covers |
|--------|--------|
| [YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide) | Naming, metadata, string groups, condition layout |
| [YARA Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines) | Atoms, regex, short-circuit evaluation, modules |
| [yaraQA](https://github.com/Neo23x0/yaraQA) | 25 automated checks with exact thresholds and levels |
| [YARA-Forge](https://github.com/YARAHQ/yara-forge) | Compile gates, metadata normalization, score and quality, package tiers |

### String groups

| Prefix | Purpose | Condition |
|--------|---------|-----------|
| `$x*` | Highly specific; one hit is enough | `1 of ($x*)` |
| `$s*` | Weak alone, meaningful together | `all of ($s*)` |
| `$a*` | Pre-selection (file type, format) | `$a1 and ...` |
| `$fp*` | False positive filters | `not 1 of ($fp*)` |

### Rule naming

```
MAL_APT_CozyBear_ELF_Loader_Apr18
 │   │      │     │    │      └─ suffix: month and year
 │   │      │     │    └─ type
 │   │      │     └─ technology
 │   │      └─ threat actor
 │   └─ intention
 └─ main category (MAL, HKTL, WEBSHELL, EXPL, VULN, SUSP, PUA)
```

### Issue IDs

- **yaraQA (automated):** `CE1`, `SM1`-`SM6`, `DS1`, `CS1`, `SV1`, `SV2`, `PA1`, `PA2`, `RE1`, `NC1`, `NO1`, `CF1`, `CF2`, `PI1`, `MO1`, `HS1`-`HS4`, `DU1`
- **YARA-Forge (automated):** `SI1` (doesn't compile), `SI2` (compiles with warnings)
- **Manual review:** naming `NM*`, metadata `MF*`, strings `TR*`/`SS*`, conditions `CL*`, layout `FM*`/`ID*`, performance `RX*`, compatibility `CC*`

## Example Assessment

[TEST_ASSESSMENT.md](TEST_ASSESSMENT.md) shows reviews of real rules from public repositories in the skill's output format.

## Repository Structure

```
yara-rule-skill/                     # repository
├── README.md
├── TEST_ASSESSMENT.md               # example reviews
├── installer/
│   └── package_skill.py             # builds yara-rule-skill.skill
└── yara-rule-skill/                 # the skill (copy this folder)
    ├── SKILL.md                     # workflows and core rules
    ├── references/
    │   ├── style.md                 # YARA Style Guide
    │   ├── performance.md           # YARA Performance Guidelines
    │   ├── yaraqa-checks.md         # yaraQA checks, thresholds, levels
    │   ├── issue-identifiers.md     # all issue IDs, manual-review IDs
    │   └── yara-forge.md            # YARA-Forge QA, scoring, packages
    └── scripts/
        ├── validate_rule.py         # compiles with YARA-X and YARA 4.x
        ├── requirements.txt
        └── README.md
```

## Website

[https://YARAHQ.github.io/yara-rule-skill-site/](https://YARAHQ.github.io/yara-rule-skill-site/) has an overview, use cases, and installation instructions.

## Contributing

Contributions welcome:

- Rule examples and assessments
- Corrections where the skill diverges from its sources
- Validator improvements
- Documentation

## License

This skill is derived from Florian Roth's YARA guides and yaraQA tool, and from YARA-Forge. See the source repositories for licensing:

- [YARA-Performance-Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)
- [YARA-Style-Guide](https://github.com/Neo23x0/YARA-Style-Guide)
- [yaraQA](https://github.com/Neo23x0/yaraQA)
- [YARA-Forge](https://github.com/YARAHQ/yara-forge)

## Acknowledgments

- **Florian Roth** (@cyb3rops): creator of the guides, yaraQA, and YARA-Forge
- **Thomas Roccia** (@fr0gger): validation script
- **YARA HQ**: community organization for YARA excellence
- **Victor M. Alvarez**: creator of YARA and YARA-X
