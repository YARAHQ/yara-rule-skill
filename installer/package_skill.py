#!/usr/bin/env python3
"""
Package the yara-rule-skill for distribution.

Usage: python3 installer/package_skill.py
"""

import os
import zipfile
from pathlib import Path

SKIP_NAMES = {"__pycache__", ".DS_Store"}
SKIP_SUFFIXES = {".pyc"}


def package_skill():
    """Package every file of the skill directory into a .skill (zip) file."""

    skill_name = "yara-rule-skill"
    skill_dir = Path(skill_name)
    skill_file = f"{skill_name}.skill"

    print(f"Packaging {skill_name}...")

    with zipfile.ZipFile(skill_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for full_path in sorted(skill_dir.rglob("*")):
            if not full_path.is_file():
                continue
            if any(part in SKIP_NAMES for part in full_path.parts) or full_path.suffix in SKIP_SUFFIXES:
                continue
            arcname = full_path.relative_to(skill_dir).as_posix()
            zf.write(full_path, arcname)
            print(f"  Added: {arcname}")

    size = os.path.getsize(skill_file)
    print(f"\n✅ Created: {skill_file} ({size:,} bytes)")

    return skill_file


if __name__ == "__main__":
    # Change to repo root directory
    os.chdir(Path(__file__).parent.parent)
    package_skill()
