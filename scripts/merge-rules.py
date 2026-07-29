#!/usr/bin/env python3
"""Merge upstream rules into an AdGuard source for sing-box conversion."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path


DEFAULT_FILTERS_DIR = Path(__file__).resolve().parent.parent / "Filters"
SOURCES = (
    ("AWAvenue-Ads-Rule-Singbox.json", "AWAvenue", "sing-box"),
    ("GOODBYEADS-dns.txt", "GOODBYEADS", "adguard"),
    ("adb.txt", "10007", "adguard"),
    ("qq5460168-666-Singbox.json", "666", "sing-box"),
    ("217heidai-adblockdns.txt", "217heidai", "adguard"),
    ("anti-ad.txt", "anti-AD", "adguard"),
    ("REIJI007-adblock_reject.json", "REIJI007", "sing-box"),
)
SUPPORTED_JSON_FIELDS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "invert",
    "type",
}


def string_values(value: object, field: str) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{field} contains a non-string value")
            yield item
        return
    raise ValueError(f"{field} must be a string or list of strings")


def normalize_domain(domain: str) -> str:
    normalized = domain.strip().strip(".").lower()
    if not normalized:
        raise ValueError("domain cannot be empty")
    return normalized


def has_value(value: object) -> bool:
    return value not in (None, False, "", [], {})


def escape_re2_literal(value: str) -> str:
    """Escape characters with special meaning in Go's RE2 syntax."""
    special = set(r"\.+*?()|[]{}^$")
    return "".join(f"\\{char}" if char in special else char for char in value)


def parse_singbox_json(filepath: Path) -> set[str]:
    """Translate equivalent sing-box match fields to AdGuard syntax."""
    with filepath.open(encoding="utf-8-sig") as file:
        data = json.load(file)

    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError(f"{filepath} is not a sing-box rule-set JSON file")

    lines: set[str] = set()
    for index, rule in enumerate(data["rules"]):
        if not isinstance(rule, dict):
            raise ValueError(f"rule {index} in {filepath} is not an object")
        if rule.get("type") not in (None, "default"):
            raise ValueError(
                f"{filepath} rule {index} is logical and cannot be represented "
                "by a flat AdGuard DNS rule set"
            )
        unsupported = sorted(
            field
            for field, value in rule.items()
            if field not in SUPPORTED_JSON_FIELDS and has_value(value)
        )
        if unsupported:
            raise ValueError(
                f"{filepath} rule {index} contains fields that require AND "
                f"semantics and cannot be flattened: {', '.join(unsupported)}"
            )
        if rule.get("invert") is True:
            raise ValueError(
                f"{filepath} rule {index} uses invert and cannot be flattened"
            )

        for domain in string_values(rule.get("domain"), "domain"):
            # Anchors preserve sing-box's exact domain semantics in a mixed file.
            lines.add(f"|{normalize_domain(domain)}^")
        for suffix in string_values(rule.get("domain_suffix"), "domain_suffix"):
            child_only = suffix.strip().startswith(".")
            normalized = normalize_domain(suffix)
            lines.add(f"||{'*.' if child_only else ''}{normalized}^")
        for keyword in string_values(rule.get("domain_keyword"), "domain_keyword"):
            if keyword:
                lines.add(f"/{escape_re2_literal(keyword)}/")
        for regex in string_values(rule.get("domain_regex"), "domain_regex"):
            if regex:
                lines.add(f"/{regex}/")

        ip_cidrs = list(string_values(rule.get("ip_cidr"), "ip_cidr"))
        if ip_cidrs:
            raise ValueError(
                f"{filepath} rule {index} contains ip_cidr, which cannot be "
                "represented by an AdGuard DNS rule set"
            )

    return lines


def parse_adguard_source(filepath: Path) -> set[str]:
    """Read rules without reimplementing AdGuard matching semantics."""
    lines: set[str] = set()
    with filepath.open(encoding="utf-8-sig") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith(("!", "#", "[")):
                continue
            lines.add(line)
    return lines


def merge_sources(filters_dir: Path, *, allow_missing: bool = False) -> set[str]:
    merged: set[str] = set()
    raw_count = 0

    for filename, label, source_type in SOURCES:
        filepath = filters_dir / filename
        if not filepath.is_file():
            if allow_missing:
                print(f"SKIP {label}: {filename} not found")
                continue
            raise FileNotFoundError(f"Required source is missing: {filepath}")

        if source_type == "sing-box":
            lines = parse_singbox_json(filepath)
        elif source_type == "adguard":
            lines = parse_adguard_source(filepath)
        else:
            raise ValueError(f"Unknown source type for {filename}: {source_type}")

        print(f"{label}: {len(lines)} supported rules")
        raw_count += len(lines)
        merged.update(lines)

    print("\n--- Summary ---")
    print(f"Raw supported rules: {raw_count}")
    print(f"After exact deduplication: {len(merged)}")
    print(f"Exact duplicates removed: {raw_count - len(merged)}")
    return merged


def write_adguard_source(lines: set[str], output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8", newline="\n") as file:
        file.write("! Generated by scripts/merge-rules.py\n")
        file.write("! Converted by: sing-box rule-set convert --type adguard\n")
        for line in sorted(lines):
            file.write(f"{line}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--filters-dir",
        type=Path,
        default=DEFAULT_FILTERS_DIR,
        help="directory containing downloaded source files",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="skip missing configured sources instead of failing",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    merged = merge_sources(args.filters_dir, allow_missing=args.allow_missing)
    output_file = args.filters_dir / "combined.txt"
    write_adguard_source(merged, output_file)
    print(f"\nWritten: {output_file} ({len(merged)} rules)")


if __name__ == "__main__":
    main()
