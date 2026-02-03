#!/usr/bin/env python3
"""
Package the yara-rule-skill for distribution
Usage: python3 scripts/package_skill.py
"""

import os
import sys
import zipfile
from pathlib import Path

def package_skill():
    """Package the skill into a .skill file"""
    
    skill_name = "yara-rule-skill"
    skill_file = f"{skill_name}.skill"
    
    # Files to include
    include_files = [
        "SKILL.md",
        "references/performance.md",
        "references/style.md",
        "references/yaraqa-checks.md",
    ]
    
    # Create the skill package
    print(f"Packaging {skill_name}...")
    
    with zipfile.ZipFile(skill_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in include_files:
            if os.path.exists(file_path):
                zf.write(file_path, file_path)
                print(f"  Added: {file_path}")
            else:
                print(f"  Warning: {file_path} not found")
    
    # Get file size
    size = os.path.getsize(skill_file)
    print(f"\n✅ Created: {skill_file} ({size:,} bytes)")
    
    return skill_file

if __name__ == "__main__":
    # Change to script directory
    os.chdir(Path(__file__).parent.parent)
    package_skill()
