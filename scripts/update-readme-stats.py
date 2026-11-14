#!/usr/bin/env python3
"""更新 README 的 📊 项目统计块：合并产物 + 各上游源规则数。

统计口径（与 README 一致）：字符串条目计数——
- default 规则的所有 list 字段中的字符串值各计 1 条
- 排除 __singbox_never_match__ 占位符
- 端口数字（非字符串）不计入

各源规则数直接复用转换器读取 work/sources 下的原始规则计算，
顺序由 sources.json 决定；源文件缺失时跳过该源。

用法: python3 scripts/update-readme-stats.py [--readme README.md] [--out work/out]
"""

import argparse
import json
import re
import sys
from pathlib import Path, PurePath

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
import adguard2headless  # noqa: E402


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


def collect_source_entries(sources_dir: Path, config: Path) -> list[tuple[str, int]]:
    """按 sources.json 顺序统计各源转换后的规则数；缺文件则跳过。"""
    if not sources_dir.is_dir() or not config.is_file():
        return []
    try:
        items = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    result: list[tuple[str, int]] = []
    for item in items:
        name = str(item.get("name", "")).strip()
        kind = str(item.get("type", "")).strip()
        safe = PurePath(name).name
        if not safe or kind not in ("adguard", "hosts"):
            continue
        ext = "hosts" if kind == "hosts" else "txt"
        path = sources_dir / kind / f"{safe}.{ext}"
        if not path.is_file():
            continue
        rules = adguard2headless.convert(
            path.read_text(encoding="utf-8-sig"), source="auto")["rules"]
        result.append((name, count_string_entries(rules)))
    return result


def build_stats_block(out: Path,
                      sources: list[tuple[str, int]] | None = None) -> str:
    def merged(name: str) -> int | None:
        p = out / "merged" / name / f"{name}.json"
        return load_count(p) if p.exists() else None

    a = merged("adguard")
    if a is None:
        raise RuntimeError("缺少合并产物 work/out/merged/adguard/adguard.json")
    lines = ["📈 合并规则集（去重后）:",
             f"   adguard  {a:,} 条  （全部上游源合并去重）"]
    if sources:
        lines += ["", "📦 各规则源（规则数）:"]
        width = max(len(name) for name, _ in sources)
        lines += [f"   {name:<{width}}  {n:,} 条" for name, n in sources]
    return "\n".join(lines)


def parse_merged_count(block: str) -> int | None:
    """从统计块文本里取 adguard 条数（用于上游退化守卫）。"""
    m = re.search(r"adguard\s+([\d,]+)\s*条", block)
    return int(m.group(1).replace(",", "")) if m else None


def update_readme(readme: Path, out: Path,
                  max_drop_pct: float | None = None,
                  sources: list[tuple[str, int]] | None = None) -> str:
    text = readme.read_text(encoding="utf-8")
    # 统计块：## 📊 项目统计 之后（可含说明段落）到第一个 fenced 块
    pattern = re.compile(r"(## 📊 项目统计\n.*?\n```\n)(.*?)(\n```)", re.S)
    m = pattern.search(text)
    if not m:
        raise RuntimeError("README 统计块匹配失败（未找到 ## 📊 项目统计 后的 fenced 块）")
    block = build_stats_block(out, sources)
    if max_drop_pct is not None:
        old, new = parse_merged_count(m.group(2)), parse_merged_count(block)
        if old and new and new < old * (1 - max_drop_pct / 100):
            drop = (old - new) / old * 100
            raise RuntimeError(
                f"合并规则数骤降 {drop:.1f}%（{old:,} → {new:,}），"
                f"超过 {max_drop_pct:.0f}% 阈值：疑似上游源异常，拒绝提交")
    return text[:m.start(2)] + block + text[m.end(2):]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--readme", type=Path, default=Path("README.md"))
    ap.add_argument("--out", type=Path, default=Path("work/out"))
    ap.add_argument("--sources", type=Path, default=Path("work/sources"),
                    help="上游源目录，用于统计各源规则数")
    ap.add_argument("--config", type=Path, default=Path("sources.json"),
                    help="源配置，决定各源统计顺序")
    ap.add_argument("--max-drop-pct", type=float, default=None,
                    help="合并规则数相对上次允许的最大跌幅（%%），超出则失败退出")
    args = ap.parse_args()
    try:
        entries = collect_source_entries(args.sources, args.config)
        new_text = update_readme(args.readme, args.out, args.max_drop_pct, entries)
    except RuntimeError as e:
        print(f"::error::{e}", file=sys.stderr)
        sys.exit(1)
    args.readme.write_text(new_text, encoding="utf-8")
    print(f"README 统计已更新: {args.readme}")
    sys.exit(0)


if __name__ == "__main__":
    main()
