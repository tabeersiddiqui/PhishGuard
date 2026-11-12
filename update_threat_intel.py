#!/usr/bin/env python3

"""
Force-refresh the PhishGuard v2.4 phishing intelligence cache.
"""

import shutil
from pathlib import Path


BASE = Path(__file__).resolve().parent
CACHE = BASE / "threat_intel"


if CACHE.exists():
    shutil.rmtree(CACHE)

print(
    "Old threat-intelligence cache cleared."
)

import phishguard_v24

print()
print(
    "Threat-intelligence refresh complete."
)
