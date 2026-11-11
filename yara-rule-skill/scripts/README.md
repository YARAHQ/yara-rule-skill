# YARA Skill Scripts

Rule validation for the YARA rule skill.

**Original author:** Thomas Roccia (@fr0gger)

## Requirements

```bash
pip install -r requirements.txt
```

`yara-x` is required. `yara-python` is optional: when installed, the validator also compiles with YARA 4.x (libyara), the engine YARA-Forge uses, and reports its warnings.

## Usage

```bash
# Validate a rule file
python validate_rule.py rule.yar

# Validate from stdin
echo 'rule test { condition: true }' | python validate_rule.py --stdin

# Fail on warnings too (recommended before publishing rules)
python validate_rule.py rule.yar --strict

# JSON output
python validate_rule.py rule.yar --json

# PASS/FAIL only
python validate_rule.py --stdin --quiet
```

## What it checks

- Compile errors in YARA-X and YARA 4.x (syntax, unreferenced strings, undefined identifiers, invalid modifiers)
- Compile warnings from both engines (slow patterns, unbounded regex quantifiers, always-false conditions, slow loops)

It doesn't run yaraQA's quality checks; see [references/yaraqa-checks.md](../references/yaraqa-checks.md).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Valid (with `--strict`: valid and no warnings) |
| 1 | Invalid, warnings with `--strict`, or input error |
