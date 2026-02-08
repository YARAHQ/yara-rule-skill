#!/usr/bin/env python3
"""
YARA Rule Validator

Validates YARA rules syntax using YARA-X compiler.

Author: Thomas Roccia (@fr0gger)

Usage:
    python validate_rule.py rule.yar
    python validate_rule.py --stdin < rule.yar
    echo 'rule test { condition: true }' | python validate_rule.py --stdin
    python validate_rule.py rule.yar --json
    python validate_rule.py --stdin --quiet
"""

import sys
import json
import re
from pathlib import Path
from typing import List, Tuple
from dataclasses import dataclass

import yara_x


@dataclass
class ValidationResult:
    """Result of rule validation."""
    is_valid: bool
    rule_name: str
    errors: List[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


def extract_rule_name(rule_text: str) -> str:
    """Extract rule name from YARA rule text."""
    match = re.search(r'rule\s+(\w+)', rule_text)
    if match:
        return match.group(1)
    return "unknown"


def validate_rule(rule_text: str) -> ValidationResult:
    """
    Validate YARA rule syntax using YARA-X.
    Returns ValidationResult with status, errors, and warnings.
    """
    rule_name = extract_rule_name(rule_text)
    result = ValidationResult(
        is_valid=False,
        rule_name=rule_name,
    )

    try:
        compiler = yara_x.Compiler()
        compiler.add_source(rule_text)

        for warn in compiler.warnings():
            result.warnings.append(f"{warn.get('title', 'Warning')}: {warn.get('text', '')[:200]}")

        compiler.build()
        result.is_valid = True

    except yara_x.CompileError as e:
        result.errors.append(f"Compilation error: {str(e)}")

    except Exception as e:
        result.errors.append(f"Unexpected error: {str(e)}")

    return result


def format_report(result: ValidationResult) -> str:
    """Format validation result as human-readable report."""
    lines = [
        "",
        "=" * 50,
        "YARA RULE VALIDATION",
        "=" * 50,
        "",
        f"Rule: {result.rule_name}",
        "",
    ]

    if result.is_valid:
        lines.append("✓ Compilation: PASSED")
    else:
        lines.append("✗ Compilation: FAILED")
        for err in result.errors:
            lines.append(f"  └─ {err}")

    if result.warnings:
        lines.append("")
        lines.append("⚠ Warnings:")
        for warn in result.warnings:
            lines.append(f"  └─ {warn}")

    lines.extend(["", "=" * 50])
    return '\n'.join(lines)


def main():
    """CLI interface for validation."""
    import argparse

    parser = argparse.ArgumentParser(description='Validate YARA rule syntax')
    parser.add_argument('rule', nargs='?', help='Path to YARA rule file')
    parser.add_argument('--stdin', action='store_true', help='Read rule from stdin')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only output pass/fail')

    args = parser.parse_args()

    # Read rule from stdin or file
    if args.stdin:
        rule_text = sys.stdin.read()
    elif args.rule:
        rule_path = Path(args.rule)
        if not rule_path.exists():
            print(f"Error: File not found: {args.rule}", file=sys.stderr)
            sys.exit(1)
        rule_text = rule_path.read_text()
    else:
        parser.print_help()
        sys.exit(1)

    # Validate
    result = validate_rule(rule_text)

    # Output
    if args.json:
        output = {
            'is_valid': result.is_valid,
            'rule_name': result.rule_name,
            'errors': result.errors,
            'warnings': result.warnings,
        }
        print(json.dumps(output, indent=2))
    elif args.quiet:
        print("PASS" if result.is_valid else "FAIL")
    else:
        print(format_report(result))

    sys.exit(0 if result.is_valid else 1)


if __name__ == '__main__':
    main()
