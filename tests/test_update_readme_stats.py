#!/usr/bin/env python3
"""update-readme-stats.py 单元测试。"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "update_readme_stats",
    Path(__file__).resolve().parent.parent / "scripts" / "update-readme-stats.py")
assert SPEC and SPEC.loader
urs = importlib.util.module_from_spec(SPEC)
sys.modules["update_readme_stats"] = urs
SPEC.loader.exec_module(urs)

README_TEMPLATE = """# test

## 📊 项目统计

每日更新（北京时间 10:00 自动同步并重新编译）。

```
📈 合并规则集（去重后）:
   adguard  999 条  （全部上游源合并去重）
```

## 📥 规则订阅

正文不受影响。
"""


def make_product(out: Path, rel: str, rules: list):
    p = out / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"version": 3, "rules": rules}), encoding="utf-8")


def make_fixture(td: str) -> tuple[Path, Path]:
    out = Path(td) / "out"
    # 唯一合并产物：adguard（a + b + c，logical 递归）
    make_product(out, "merged/adguard/adguard.json",
                 [{"domain": ["a.example.com", "b.example.com"]},
                  {"type": "logical", "mode": "and",
                   "rules": [{"domain_suffix": ["c.example.com"]}]}])
    # 单源产物即使存在也不应出现在统计中
    make_product(out, "converted/adguard/217heidai-adblockdns.json",
                 [{"domain_suffix": ["x1.com", "x2.com"]}])
    readme = Path(td) / "README.md"
    readme.write_text(README_TEMPLATE, encoding="utf-8")
    return readme, out


class TestStats(unittest.TestCase):
    def test_count_string_entries(self):
        rules = [
            {"domain": ["a.com", "__singbox_never_match__"]},
            {"ip_cidr": ["1.1.1.1"], "port": [8080]},  # port 数字不计
            {"type": "logical", "mode": "or",
             "rules": [{"domain_suffix": ["b.com", "c.com"]}]},
        ]
        self.assertEqual(urs.count_string_entries(rules), 4)  # a.com + 1.1.1.1 + b.com + c.com

    def test_update_readme(self):
        with tempfile.TemporaryDirectory() as td:
            readme, out = make_fixture(td)
            new_text = urs.update_readme(readme, out)
            self.assertIn("adguard  3 条", new_text)      # a + b + c（logical 递归）
            self.assertNotIn("单源规则集", new_text)
            self.assertNotIn("217heidai", new_text)
            self.assertIn("规则订阅", new_text)               # 正文不受影响
            self.assertNotIn("999 条", new_text)

    def test_update_readme_missing_block(self):
        with tempfile.TemporaryDirectory() as td:
            readme = Path(td) / "README.md"
            readme.write_text("# no stats block\n", encoding="utf-8")
            out = Path(td) / "out"
            with self.assertRaises(RuntimeError):
                urs.update_readme(readme, out)

    def test_update_readme_missing_merged_product(self):
        with tempfile.TemporaryDirectory() as td:
            readme, out = make_fixture(td)
            (out / "merged" / "adguard" / "adguard.json").unlink()
            with self.assertRaises(RuntimeError):
                urs.update_readme(readme, out)

    def test_collect_source_entries(self):
        with tempfile.TemporaryDirectory() as td:
            sources = Path(td) / "sources"
            (sources / "adguard").mkdir(parents=True)
            (sources / "adguard" / "a.txt").write_text(
                "||x.example^\n||y.example^\n@@||ok.x.example^\n", encoding="utf-8")
            config = Path(td) / "sources.json"
            config.write_text(json.dumps([
                {"name": "a", "type": "adguard", "url": "https://example.com/a.txt"},
                {"name": "missing", "type": "adguard", "url": "https://example.com/m.txt"},
            ]), encoding="utf-8")
            entries = urs.collect_source_entries(sources, config)
            # 顺序由 config 决定；缺失文件跳过
            self.assertEqual([name for name, _ in entries], ["a"])
            self.assertEqual(entries[0][1], 3)  # x + y + 白名单 ok.x

    def test_stats_block_with_sources(self):
        with tempfile.TemporaryDirectory() as td:
            _, out = make_fixture(td)
            block = urs.build_stats_block(
                out, [("short", 12), ("much-longer-source", 3456)])
            self.assertIn("📦 各规则源（规则数）:", block)
            self.assertIn("short", block)
            self.assertIn("3,456 条", block)

    def test_parse_merged_count(self):
        self.assertEqual(
            urs.parse_merged_count("adguard  257,793 条  （全部上游源合并去重）"),
            257793)
        self.assertIsNone(urs.parse_merged_count("no numbers here"))

    def test_drop_guard_triggers_on_big_drop(self):
        with tempfile.TemporaryDirectory() as td:
            readme, out = make_fixture(td)  # README 写死 999，实际产物只有 3
            with self.assertRaises(RuntimeError) as ctx:
                urs.update_readme(readme, out, max_drop_pct=20)
            self.assertIn("骤降", str(ctx.exception))

    def test_drop_guard_allows_normal_drop(self):
        with tempfile.TemporaryDirectory() as td:
            readme, out = make_fixture(td)
            text = readme.read_text(encoding="utf-8").replace("adguard  999 条", "adguard  4 条")
            readme.write_text(text, encoding="utf-8")
            # 4 → 3 是 25% 跌幅，用 30% 阈值放行
            new_text = urs.update_readme(readme, out, max_drop_pct=30)
            self.assertIn("adguard  3 条", new_text)

    def test_drop_guard_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            readme, out = make_fixture(td)
            new_text = urs.update_readme(readme, out)
            self.assertIn("adguard  3 条", new_text)


if __name__ == "__main__":
    unittest.main()
