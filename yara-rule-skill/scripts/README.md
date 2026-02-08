# YARA Skill Scripts

YARA rule validation utilities.

**Author:** Thomas Roccia (@fr0gger)

## Requirements

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Validate rule from file
python validate_rule.py rule.yar

# Validate rule from stdin
echo 'rule test { condition: true }' | python validate_rule.py --stdin

# JSON output
python validate_rule.py rule.yar --json

# Quiet mode (pass/fail)
python validate_rule.py --stdin --quiet
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid rule |
| 1 | Invalid rule |
