# YARA Rule Skill

An **LLM Agent Skill** for expert YARA rule authoring, review, and optimization. Embeds industry best practices from the creator of [YARA-Forge](https://github.com/YARAHQ/yara-forge) and [yaraQA](https://github.com/Neo23x0/yaraQA) into your AI assistant's context.

## 🎯 What This Skill Does

The **yara-rule-skill** transforms your LLM agent into a YARA rule expert, capable of:

- **Writing** high-quality, performant YARA rules from scratch
- **Reviewing** existing rules for quality issues and performance problems
- **Optimizing** slow rules by identifying performance bottlenecks
- **Validating** rules against 20+ automated quality checks from yaraQA

All through natural language conversation — just paste a rule and ask.

## 📦 Installation

### Direct Download

```bash
# Download the skill
curl -L -o yara-rule-skill.skill https://github.com/YARAHQ/yara-rule-skill/releases/latest/download/yara-rule-skill.skill

# Add to your agent's skills folder
# (location varies by platform)
cp yara-rule-skill.skill ~/.openclaw/skills/
```

### Supported Platforms

This skill works with any LLM agent that supports skill files:

- **OpenClaw** — `~/.openclaw/skills/`
- **Claude Desktop** — (skills folder location varies)
- **Other MCP-based agents** — Check your platform's documentation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/YARAHQ/yara-rule-skill.git
cd yara-rule-skill

# Package the skill
python3 scripts/package_skill.py .

# Install
cp yara-rule-skill.skill ~/.openclaw/skills/
```

## 🚀 Usage

Once installed, the skill activates automatically when you discuss YARA rules. Just ask:

### Use Case 1: Review My Rule
> "Review this YARA rule and suggest improvements"

The skill analyzes:
- Naming conventions (`MAL_`, `HKTL_`, `SUSP_`, etc.)
- String selection (atom quality, modifiers)
- Condition logic (short-circuit evaluation)
- Metadata completeness

### Use Case 2: Assess Public Rules
> "Assess the quality of this rule I found online"

The skill checks against 20+ automated quality checks:
- Logic errors (conditions that never match)
- Performance issues (short atoms, unanchored regex)
- Style violations (naming, formatting)
- Resource problems (too many strings/regex)

### Use Case 3: Performance Diagnosis
> "This rule causes performance issues, why?"

The skill identifies:
- Missing regex anchors (`.*`, `.+`)
- Short atoms (< 4 bytes)
- Expensive calculations before cheap checks
- Module usage that could be replaced

## 📚 What's Included

### Core Knowledge

The skill combines three authoritative sources into your agent's context:

1. **[YARA Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)** — Optimization techniques, atom selection, condition ordering
2. **[YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide)** — Naming conventions, rule structure, metadata standards  
3. **[yaraQA](https://github.com/Neo23x0/yaraQA)** — 20+ automated quality checks

### String Categories

The skill teaches the `$x*`, `$s*`, `$a*`, `$fp*` naming convention:

| Prefix | Purpose | Example Usage |
|--------|---------|---------------|
| `$x*` | Highly specific (unique) | `1 of ($x*)` — triggers on signature |
| `$s*` | Grouped strings | `all of ($s*)` — need multiple matches |
| `$a*` | Pre-selection (file type) | `$a1` — narrows to PE files first |
| `$fp*` | False positive filters | `not 1 of ($fp*)` — exclude benign |

### Rule Naming Convention

```yara
rule MAL_APT_CozyBear_ELF_Loader_Apr18 {
    // MAL      = Malware
    // APT      = Nation state actor
    // CozyBear = Threat actor name
    // ELF      = Linux platform
    // Loader   = Malware type
    // Apr18    = Date (April 2018)
}
```

### Quality Checks

The skill covers all 20 yaraQA issue IDs:

**Logic Errors:** `CE1`, `SM1-6`, `DS1`, `CS1`, `DU1`  
**Performance:** `PA1-2`, `RE1`, `CF1-2`, `PI1`, `NC1`, `NO1`, `MO1`  
**Style:** `SV1-2`  
**Resources:** `HS1-4`

## 🧪 Example Assessment

See [TEST_ASSESSMENT.md](TEST_ASSESSMENT.md) for real-world rule reviews from public repositories.

## 🏗️ Repository Structure

```
yara-rule-skill/
├── SKILL.md                      # Main skill file
├── references/
│   ├── performance.md            # Performance optimization guide
│   ├── style.md                  # Style and naming conventions
│   └── yaraqa-checks.md          # Complete yaraQA check reference
├── scripts/
│   └── package_skill.py          # Packaging script
└── README.md                     # This file
```

## 🌐 Website

Visit [https://YARAHQ.github.io/yara-rule-skill-site/](https://YARAHQ.github.io/yara-rule-skill-site/) for:

- Overview of the skill
- Use case examples
- Installation instructions

## 🤝 Contributing

Contributions welcome! Areas to help:

- Additional rule examples
- New quality checks
- Performance benchmarks
- Documentation improvements

## 📄 License

This skill is derived from Florian Roth's YARA guides and yaraQA tool. See individual source repositories for licensing details.

- [YARA-Performance-Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)
- [YARA-Style-Guide](https://github.com/Neo23x0/YARA-Style-Guide)
- [yaraQA](https://github.com/Neo23x0/yaraQA)

## 🙏 Acknowledgments

- **Florian Roth** (@cyb3rops) — Creator of the original guides and yaraQA
- **YARA HQ** — Community organization for YARA excellence
- **Victor M. Alvarez** — Creator of YARA
