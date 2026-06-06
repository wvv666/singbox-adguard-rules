#!/usr/bin/env python3
"""
Merge and deduplicate ad-blocking rules from multiple sources.
Supported input formats: sing-box JSON, AdGuard TXT, hosts file.
Output: combined sing-box JSON rule-set file.
"""

import json
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

def parse_hosts(filepath: Path) -> set[str]:
    """Extract blocked domains from hosts file format.
    
    Handles: 0.0.0.0 domain, 127.0.0.1 domain, :: domain
    Also handles comments (# or !) and inline comments.
    """
    domains = set()
    
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # Strip inline comments
            if '#' in line:
                line = line[:line.index('#')].strip()
            
            # Parse: IP domain [domain2 ...]
            parts = line.split()
            if len(parts) < 2:
                continue
            
            ip = parts[0]
            if ip not in ('0.0.0.0', '127.0.0.1', '::', '::1'):
                continue
            
            for domain in parts[1:]:
                domain = domain.strip('.').lower()
                if domain and '*' not in domain and domain != 'localhost':
                    domains.add(domain)
    
    return domains

# --- Format Detection ---

def detect_and_parse(filepath: Path) -> tuple[set[str], set[str]]:
    """Auto-detect file format and parse accordingly.
    
    Returns (blocked_domains, exception_domains).
    """
    with open(filepath) as f:
        first_lines = [f.readline().strip() for _ in range(5)]
    
    first_line = first_lines[0] if first_lines else ""
    
    # sing-box JSON
    if first_line.startswith('{'):
        return parse_singbox_json(filepath), set()
    
    # AdGuard TXT (starts with [ or ! or ||)
    if first_line.startswith('[') or first_line.startswith('!') or first_line.startswith('||'):
        return parse_adguard_txt(filepath)
    
    # hosts file (starts with IP address or comment)
    if first_line.startswith('#') or first_line.startswith('0.0.0.0') or first_line.startswith('127.0.0.1'):
        return parse_hosts(filepath), set()
    
    # Try hosts format as fallback
    print(f"  ⚠️  Unknown format, trying hosts parser...")
    return parse_hosts(filepath), set()

# --- Main ---

def main():
    # Source files to process (add new sources here)
    sources = [
        ("AWAvenue-Ads-Rule-Singbox.json", "AWAvenue"),
        ("GOODBYEADS-dns.txt",             "GOODBYEADS"),
        ("adb.txt",                        "10007"),
        # Add more sources below, e.g.:
        # ("anti-ad.txt",                "anti-AD"),
        # ("StevenBlack-hosts",          "StevenBlack"),
    ]
    
    all_blocked = set()
    all_exceptions = set()
    total_raw = 0
    
    for filename, label in sources:
        filepath = FILTERS_DIR / filename
        if not filepath.exists():
            print(f"⏭️  {label}: {filename} not found, skipping")
            continue
        
        blocked, exceptions = detect_and_parse(filepath)
        print(f"{label}: {len(blocked)} blocked, {len(exceptions)} exceptions")
        
        all_blocked |= blocked
        all_exceptions |= exceptions
        total_raw += len(blocked) + len(exceptions)
    
    # Remove exceptions from blocked list
    before = len(all_blocked)
    all_blocked -= all_exceptions
    removed = before - len(all_blocked)
    if removed:
        print(f"Removed {removed} domains due to exceptions")
    
    # Dedup stats
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
