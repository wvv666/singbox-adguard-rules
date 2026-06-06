#!/usr/bin/env python3
"""
Merge and deduplicate ad-blocking rules from multiple sources.
Outputs a combined sing-box JSON rule-set file.
"""

import json
import re
import sys
from pathlib import Path

FILTERS_DIR = Path(__file__).parent.parent / "Filters"

# --- Parsers ---

def parse_singbox_json(filepath: Path) -> set[str]:
    """Extract domains from sing-box JSON rule-set."""
    with open(filepath) as f:
        data = json.load(f)
    domains = set()
    for rule in data.get("rules", []):
        domains.update(rule.get("domain", []))
    return domains

def parse_adguard_txt(filepath: Path) -> tuple[set[str], set[str]]:
    """Extract block and exception domains from AdGuard format file.
    
    Returns (blocked_domains, exception_domains).
    Handles: ||domain^, @@||domain^, with optional modifiers.
    """
    blocked = set()
    exceptions = set()
    
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('!') or line.startswith('['):
                continue
            
            # Exception rule
            if line.startswith('@@||'):
                domain = line[4:].split('^')[0].split('$')[0].strip('.')
                if domain and '*' not in domain:
                    exceptions.add(domain)
                continue
            
            # Block rule
            if line.startswith('||'):
                domain = line[2:].split('^')[0].split('$')[0].strip('.')
                if domain and '*' not in domain:
                    blocked.add(domain)
                continue
    
    return blocked, exceptions

# --- Main ---

def main():
    # Parse AWAvenue (sing-box JSON)
    awavenue_file = FILTERS_DIR / "AWAvenue-Ads-Rule-Singbox.json"
    awavenue_domains = parse_singbox_json(awavenue_file)
    print(f"AWAvenue: {len(awavenue_domains)} domains")

    # Parse GOODBYEADS (AdGuard TXT)
    goodbyeads_file = FILTERS_DIR / "GOODBYEADS-dns.txt"
    goodbyeads_blocked, goodbyeads_ex = parse_adguard_txt(goodbyeads_file)
    print(f"GOODBYEADS: {len(goodbyeads_blocked)} blocked, {len(goodbyeads_ex)} exceptions")

    # Parse 10007 (AdGuard TXT)
    adb_file = FILTERS_DIR / "adb.txt"
    adb_blocked, adb_ex = parse_adguard_txt(adb_file)
    print(f"10007: {len(adb_blocked)} blocked, {len(adb_ex)} exceptions")

    # Merge all exceptions
    all_exceptions = goodbyeads_ex | adb_ex
    print(f"Total exceptions: {len(all_exceptions)}")

    # Merge all blocked domains
    all_blocked = awavenue_domains | goodbyeads_blocked | adb_blocked
    
    # Remove exceptions from blocked list
    before = len(all_blocked)
    all_blocked -= all_exceptions
    removed = before - len(all_blocked)
    if removed:
        print(f"Removed {removed} domains due to exceptions")

    # Dedup stats
    total_raw = len(awavenue_domains) + len(goodbyeads_blocked) + len(adb_blocked)
    duplicates = total_raw - len(all_blocked) - len(all_exceptions)
    print(f"\n--- Summary ---")
    print(f"Total raw rules: {total_raw}")
    print(f"After dedup + exceptions: {len(all_blocked)}")
    print(f"Duplicates removed: {duplicates}")

    # Output combined sing-box JSON
    combined = {
        "version": 2,
        "rules": [
            {
                "domain": sorted(all_blocked)
            }
        ]
    }
    
    output_file = FILTERS_DIR / "combined.json"
    with open(output_file, 'w') as f:
        json.dump(combined, f, separators=(',', ':'))
    
    print(f"\n✅ Written: {output_file} ({len(all_blocked)} domains)")

if __name__ == "__main__":
    main()
