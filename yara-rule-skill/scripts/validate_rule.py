#!/usr/bin/env python3
"""
YARA Rule Validator

Compiles YARA rules with YARA-X and, when yara-python is installed, with
YARA 4.x (libyara) as well. Reports errors and warnings from both engines.

YARA-Forge compiles with libyara and treats warnings as errors, so a rule
that is meant for broad deployment should pass both engines without warnings.

Original author: Thomas Roccia (@fr0gger)

Usage:
    python validate_rule.py rule.yar
    python validate_rule.py --stdin < rule.yar
    echo 'rule test { condition: true }' | python validate_rule.py --stdin
    python validate_rule.py rule.yar --json
    python validate_rule.py rule.yar --strict     # warnings fail validation
    python validate_rule.py --stdin --quiet

Exit codes:
    0  valid (with --strict: valid and no warnings)
    1  invalid, or input error
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import yara_x
except ImportError:  # pragma: no cover - reported at runtime
    yara_x = None

try:
    import yara  # yara-python (libyara 4.x)
except ImportError:
    yara = None


RULE_NAME_RE = re.compile(
    r'^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.MULTILINE,
)


@dataclass
class EngineResult:
    """Compilation result of one engine."""
    engine: str
    available: bool
    is_valid: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    """Combined validation result."""
    rule_names: List[str]
    engines: List[EngineResult]

    @property
    def is_valid(self) -> bool:
        ran = [e for e in self.engines if e.available]
        return bool(ran) and all(e.is_valid for e in ran)

    @property
    def has_warnings(self) -> bool:
        return any(e.warnings for e in self.engines if e.available)

    @property
    def rule_name(self) -> str:
        """First rule name (kept for backwards compatibility)."""
        return self.rule_names[0] if self.rule_names else "unknown"


def strip_comments(rule_text: str) -> str:
    """Remove // and /* */ comments so rule names in comments are ignored.
    Good enough for name extraction; string contents are not parsed."""
    text = re.sub(r'/\*.*?\*/', '', rule_text, flags=re.DOTALL)
    return re.sub(r'//[^\n]*', '', text)


def extract_rule_names(rule_text: str) -> List[str]:
    """Extract all rule names from YARA rule text."""
    return RULE_NAME_RE.findall(strip_comments(rule_text))


def validate_yara_x(rule_text: str) -> EngineResult:
    """Compile with YARA-X."""
    result = EngineResult(engine="YARA-X", available=yara_x is not None)
    if yara_x is None:
        result.errors.append("yara-x is not installed (pip install yara-x)")
        return result
    try:
        compiler = yara_x.Compiler()
        compiler.add_source(rule_text)
        for warn in compiler.warnings():
            text = warn.get('text') or warn.get('title', 'warning')
            result.warnings.append(text)
        compiler.build()
        result.is_valid = True
    except yara_x.CompileError as exc:
        result.errors.append(str(exc))
    except Exception as exc:  # noqa: BLE001 - report anything unexpected
        result.errors.append(f"Unexpected error: {exc}")
    return result


def validate_libyara(rule_text: str) -> EngineResult:
    """Compile with YARA 4.x via yara-python; collect warnings separately."""
    result = EngineResult(engine="YARA 4.x", available=yara is not None)
    if yara is None:
        return result
    try:
        rules = yara.compile(source=rule_text)
        result.is_valid = True
    except yara.SyntaxError as exc:
        result.errors.append(str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"Unexpected error: {exc}")
        return result
    if hasattr(rules, 'warnings'):  # yara-python >= 4.3
        result.warnings.extend(str(w) for w in rules.warnings)
    else:  # older yara-python: warnings only surface as an exception
        try:
            yara.compile(source=rule_text, error_on_warning=True)
        except Exception as exc:  # noqa: BLE001
            result.warnings.extend(str(w) for w in getattr(exc, 'warnings', [exc]))
    return result


def validate_rule(rule_text: str) -> ValidationResult:
    """Validate rule text with all available engines."""
    return ValidationResult(
        rule_names=extract_rule_names(rule_text),
        engines=[validate_yara_x(rule_text), validate_libyara(rule_text)],
    )


def format_report(result: ValidationResult, strict: bool) -> str:
    """Format validation result as a human-readable report."""
    names = ", ".join(result.rule_names) if result.rule_names else "unknown"
    lines = ["", "=" * 50, "YARA RULE VALIDATION", "=" * 50, "",
             f"Rule(s): {names}", ""]

    for eng in result.engines:
        if not eng.available:
            if eng.errors:
                lines.append(f"✗ {eng.engine}: NOT AVAILABLE")
                lines.extend(f"  └─ {e}" for e in eng.errors)
            else:
                lines.append(f"- {eng.engine}: skipped (pip install yara-python to enable)")
            continue
        status = "PASSED" if eng.is_valid else "FAILED"
        mark = "✓" if eng.is_valid else "✗"
        lines.append(f"{mark} {eng.engine} compilation: {status}")
        for err in eng.errors:
            lines.extend(f"  └─ {line}" if i == 0 else f"     {line}"
                         for i, line in enumerate(err.splitlines()))
        for warn in eng.warnings:
            lines.append("  ⚠ warning:")
            lines.extend(f"     {line}" for line in warn.splitlines())

    lines.append("")
    if not result.is_valid:
        lines.append("RESULT: FAILED")
    elif result.has_warnings:
        lines.append("RESULT: FAILED (warnings, --strict)" if strict
                     else "RESULT: PASSED WITH WARNINGS (fix them; YARA-Forge rejects warnings)")
    else:
        lines.append("RESULT: PASSED")
    lines.extend(["", "=" * 50])
    return "\n".join(lines)


def main() -> None:
    """CLI interface for validation."""
    parser = argparse.ArgumentParser(description='Validate YARA rule syntax with YARA-X and YARA 4.x')
    parser.add_argument('rule', nargs='?', help='Path to YARA rule file')
    parser.add_argument('--stdin', action='store_true', help='Read rule from stdin')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only output PASS/FAIL')
    parser.add_argument('--strict', action='store_true', help='Treat warnings as failures')
    args = parser.parse_args()

    if args.stdin:
        rule_text = sys.stdin.read()
    elif args.rule:
        rule_path = Path(args.rule)
        if not rule_path.exists():
            print(f"Error: File not found: {args.rule}", file=sys.stderr)
            sys.exit(1)
        rule_text = rule_path.read_text(encoding='utf-8', errors='replace')
    else:
        parser.print_help()
        sys.exit(1)

    result = validate_rule(rule_text)
    passed = result.is_valid and not (args.strict and result.has_warnings)

    if args.json:
        output = {
            'is_valid': result.is_valid,
            'has_warnings': result.has_warnings,
            'passed': passed,
            'rule_name': result.rule_name,
            'rule_names': result.rule_names,
            'errors': [e for eng in result.engines for e in eng.errors if eng.available],
            'warnings': [w for eng in result.engines for w in eng.warnings],
            'engines': [
                {
                    'engine': eng.engine,
                    'available': eng.available,
                    'is_valid': eng.is_valid,
                    'errors': eng.errors,
                    'warnings': eng.warnings,
                }
                for eng in result.engines
            ],
        }
        print(json.dumps(output, indent=2))
    elif args.quiet:
        print("PASS" if passed else "FAIL")
    else:
        print(format_report(result, args.strict))

    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
