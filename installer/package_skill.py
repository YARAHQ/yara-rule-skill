#!/usr/bin/env python3
"""
Package the yara-rule-skill for distribution.

Usage: python3 installer/package_skill.py
"""

import os
import zipfile
from pathlib import Path


def package_skill():
    """Package the skill into a .skill file."""

    skill_name = "yara-rule-skill"
    skill_dir = Path(skill_name)
    skill_file = f"{skill_name}.skill"

    # Files to include (relative to skill directory)
    include_files = [
        "SKILL.md",
        "references/performance.md",
        "references/style.md",
        "references/yaraqa-checks.md",
        "references/issue-identifiers.md",
        "scripts/validate_rule.py",
        "scripts/requirements.txt",
        "scripts/README.md",
    ]

    print(f"Packaging {skill_name}...")

    with zipfile.ZipFile(skill_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in include_files:
            full_path = skill_dir / file_path
            if full_path.exists():
                zf.write(full_path, file_path)
                print(f"  Added: {file_path}")
            else:
                print(f"  Warning: {file_path} not found")

    size = os.path.getsize(skill_file)
    print(f"\n✅ Created: {skill_file} ({size:,} bytes)")

    return skill_file


if __name__ == "__main__":
    # Change to repo root directory
    os.chdir(Path(__file__).parent.parent)
    package_skill()
