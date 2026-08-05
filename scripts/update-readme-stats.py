#!/usr/bin/env python3
"""更新 README 的 📊 项目统计块：读取 work/out 产物 JSON，替换统计数字。

统计口径（与 README 一致）：字符串条目计数——
- default 规则的所有 list 字段中的字符串值各计 1 条
- 排除 __singbox_never_match__ 占位符
- 端口数字（非字符串）不计入

用法: python3 scripts/update-readme-stats.py [--readme README.md] [--out work/out]
"""

import argparse
import json
import re
import sys
from pathlib import Path


# 单源显示名 → 产物文件名（converted/<kind>/<stem>.json）
SINGLE_SOURCES = [
    ("217heidai", "adguard", "217heidai-adblockdns"),
    ("GOODBYEADS-dns", "adguard", "GOODBYEADS-dns"),
    ("anti-ad", "adguard", "anti-ad-adguard"),
    ("qq5460168", "adguard", "qq5460168-dns"),
    ("10007-adb", "adguard", "10007-adb"),
    ("10007-all", "hosts", "10007-all"),
    ("GOODBYEADS-allow", "adguard", "GOODBYEADS-allow"),
]

PLACEHOLDER = "__singbox_never_match__"


def count_string_entries(rules: list) -> int:
    """统计无头规则中的字符串条目数（排除占位符）。"""
    total = 0
    for rule in rules:
        if rule.get("type") == "logical":
            total += count_string_entries(rule.get("rules", []))
            continue
        for value in rule.values():
            if isinstance(value, list):
                total += sum(1 for v in value
                             if isinstance(v, str) and v != PLACEHOLDER)
    return total


def load_count(path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    return count_string_entries(data.get("rules", []))


def build_stats_block(out: Path) -> str:
    def merged(name: str) -> int:
        return load_count(out / "merged" / name / f"{name}.json")

    c, a, h = merged("combined"), merged("adguard"), merged("hosts")
    singles = [(label, load_count(out / "converted" / kind / f"{stem}.json"))
               for label, kind, stem in SINGLE_SOURCES]
    by_name = {label: n for label, n in singles}

    def fmt(n: int) -> str:
        return f"{n:,}"

    return (
        "📈 合并规则集（去重后）:\n"
        f"   combined {fmt(c)} 条  （AdGuard + hosts 全量）\n"
        f"   adguard  {fmt(a)} 条  （仅 AdGuard 语法）\n"
        f"   hosts    {fmt(h)} 条  （仅 hosts 格式）\n"
        "\n"
        "📦 单源规则集:\n"
        f"   217heidai  {fmt(by_name['217heidai'])} 条   "
        f"GOODBYEADS-dns  {fmt(by_name['GOODBYEADS-dns'])} 条\n"
        f"   anti-ad    {fmt(by_name['anti-ad'])} 条   "
        f"qq5460168       {fmt(by_name['qq5460168'])} 条\n"
        f"   10007-adb  {fmt(by_name['10007-adb'])} 条   "
        f"10007-all       {fmt(by_name['10007-all'])} 条\n"
        f"   GOODBYEADS-allow    {fmt(by_name['GOODBYEADS-allow'])} 条（白名单例外）"
    )


def update_readme(readme: Path, out: Path) -> str:
    text = readme.read_text(encoding="utf-8")
    # 统计块：## 📊 项目统计 之后（可含说明段落）到第一个 fenced 块
    pattern = re.compile(r"(## 📊 项目统计\n.*?\n```\n)(.*?)(\n```)", re.S)
    m = pattern.search(text)
    if not m:
        raise RuntimeError("README 统计块匹配失败（未找到 ## 📊 项目统计 后的 fenced 块）")
    block = build_stats_block(out)
    return text[:m.start(2)] + block + text[m.end(2):]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--readme", type=Path, default=Path("README.md"))
    ap.add_argument("--out", type=Path, default=Path("work/out"))
    args = ap.parse_args()
    new_text = update_readme(args.readme, args.out)
    args.readme.write_text(new_text, encoding="utf-8")
    print(f"README 统计已更新: {args.readme}")
    sys.exit(0)


if __name__ == "__main__":
    main()
