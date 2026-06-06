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

def parse_singbox_json(filepath: Path) -> tuple[set[str], set[str]]:
    """Extract domain and domain_suffix from sing-box JSON rule-set.
    
    Returns (domains, domain_suffixes).
    """
    with open(filepath) as f:
        data = json.load(f)
    domains = set()
    suffixes = set()
    for rule in data.get("rules", []):
        # domain and domain_suffix can be string or list
        d = rule.get("domain", [])
        s = rule.get("domain_suffix", [])
        if isinstance(d, str):
            domains.add(d)
        else:
            domains.update(d)
        if isinstance(s, str):
            suffixes.add(s)
        else:
            suffixes.update(s)
    return domains, suffixes

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
                domain = line[4:].split('^')[0].split('$')[0].strip('.').strip('"')
                if domain and '*' not in domain:
                    exceptions.add(domain)
                continue
            
            # Block rule
            if line.startswith('||'):
                domain = line[2:].split('^')[0].split('$')[0].strip('.').strip('"')
                if domain and '*' not in domain:
                    blocked.add(domain)
                continue
    
    return blocked, exceptions

def parse_hosts(filepath: Path) -> set[str]:
    """Extract blocked domains from hosts file format.
    
    Handles: 0.0.0.0 domain (sing-box only accepts 0.0.0.0)
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
            # sing-box only accepts 0.0.0.0 for hosts format
            if ip != '0.0.0.0':
                continue
            
            for domain in parts[1:]:
                domain = domain.strip('.').lower()
                if domain and '*' not in domain and domain != 'localhost':
                    domains.add(domain)
    
    return domains

# --- Format Detection ---

def detect_and_parse(filepath: Path) -> tuple[set[str], set[str], set[str]]:
    """Auto-detect file format and parse accordingly.
    
    Returns (domains, domain_suffixes, exceptions).
    For AdGuard/hosts formats, domain_suffixes will be empty.
    """
    with open(filepath) as f:
        first_lines = [f.readline().strip() for _ in range(5)]
    
    first_line = first_lines[0] if first_lines else ""
    
    # sing-box JSON
    if first_line.startswith('{'):
        domains, suffixes = parse_singbox_json(filepath)
        return domains, suffixes, set()
    
    # AdGuard TXT (starts with [ or ! or || or @@)
    if first_line.startswith('[') or first_line.startswith('!') or first_line.startswith('||') or first_line.startswith('@@'):
        blocked, exceptions = parse_adguard_txt(filepath)
        return blocked, set(), exceptions
    
    # hosts file (starts with # or 0.0.0.0)
    if first_line.startswith('#') or first_line.startswith('0.0.0.0'):
        return parse_hosts(filepath), set(), set()
    
    # Try hosts format as fallback
    print(f"  ⚠️  Unknown format, trying hosts parser...")
    return parse_hosts(filepath), set(), set()

# --- Main ---

def main():
    # Source files to process
    # (filename, label, has_whitelist)
    sources = [
        ("AWAvenue-Ads-Rule-Singbox.json", "AWAvenue",  False),
        ("GOODBYEADS-dns.txt",             "GOODBYEADS", False),
        ("adb.txt",                        "10007",      False),
        ("qq5460168-666-Singbox.json",     "666",        False),
        ("217heidai-adblockdns.txt",         "217heidai",  False),
        ("anti-ad.txt",                       "anti-AD",    False),
        # Add more sources below, e.g.:
        # ("anti-ad.txt",                  "anti-AD",    False),
    ]
    
    all_domains = set()
    all_suffixes = set()
    all_exceptions = set()
    total_raw = 0
    
    for filename, label, is_whitelist in sources:
        filepath = FILTERS_DIR / filename
        if not filepath.exists():
            print(f"⏭️  {label}: {filename} not found, skipping")
            continue
        
        domains, suffixes, exceptions = detect_and_parse(filepath)
        
        if is_whitelist:
            all_exceptions |= domains | exceptions
            print(f"{label}: {len(exceptions)} exceptions, {len(domains)} block rules (whitelist)")
        else:
            print(f"{label}: {len(domains)} domains, {len(suffixes)} suffixes, {len(exceptions)} exceptions")
            all_domains |= domains
            all_suffixes |= suffixes
            all_exceptions |= exceptions
            total_raw += len(domains) + len(suffixes) + len(exceptions)
    
    # Remove exceptions from blocked lists
    before_d = len(all_domains)
    before_s = len(all_suffixes)
    all_domains -= all_exceptions
    all_suffixes -= all_exceptions
    removed_d = before_d - len(all_domains)
    removed_s = before_s - len(all_suffixes)
    if removed_d or removed_s:
        print(f"Removed {removed_d} domains + {removed_s} suffixes due to exceptions")
    
    # Dedup stats
    final = len(all_domains) + len(all_suffixes)
    duplicates = total_raw - final
    print(f"\n--- Summary ---")
    print(f"Total raw rules: {total_raw}")
    print(f"After dedup + exceptions: {final} ({len(all_domains)} domains + {len(all_suffixes)} suffixes)")
    print(f"Duplicates removed: {duplicates}")
    
    # Build combined rules
    rules = []
    if all_domains:
        rules.append({"domain": sorted(all_domains)})
    if all_suffixes:
        rules.append({"domain_suffix": sorted(all_suffixes)})
    
    combined = {
        "version": 2,
        "rules": rules
    }
    
    output_file = FILTERS_DIR / "combined.json"
    with open(output_file, 'w') as f:
        json.dump(combined, f, separators=(',', ':'))
    
    print(f"\n✅ Written: {output_file} ({final} rules)")

if __name__ == "__main__":
    main()
