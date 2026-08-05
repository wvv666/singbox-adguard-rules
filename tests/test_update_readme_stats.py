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
   combined 999 条  （AdGuard + hosts 全量）
   adguard  999 条  （仅 AdGuard 语法）
   hosts    999 条  （仅 hosts 格式）

📦 单源规则集:
   217heidai  999 条   GOODBYEADS-dns  999 条
   anti-ad    999 条   qq5460168       999 条
   10007-adb  999 条   10007-all       999 条
   GOODBYEADS-allow   999 条（白名单例外）
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
    # merged 三个
    make_product(out, "merged/combined/combined.json",
                 [{"domain": ["a.example.com", "b.example.com"]},
                  {"type": "logical", "mode": "and",
                   "rules": [{"domain_suffix": ["c.example.com"]}]}])
    make_product(out, "merged/adguard/adguard.json", [{"domain": ["a.example.com"]}])
    make_product(out, "merged/hosts/hosts.json", [{"domain": ["h.example.com"]}])
    # 单源 7 个（含占位符与端口）
    make_product(out, "converted/adguard/217heidai-adblockdns.json",
                 [{"domain_suffix": ["x1.com", "x2.com"]}])
    make_product(out, "converted/adguard/GOODBYEADS-dns.json",
                 [{"ip_cidr": ["1.2.3.4"], "port": [3000]}])
    make_product(out, "converted/adguard/anti-ad-adguard.json", [{"domain": ["y.com"]}])
    make_product(out, "converted/adguard/qq5460168-dns.json", [{"domain": ["z.com"]}])
    make_product(out, "converted/adguard/10007-adb.json", [{"domain": ["w.com"]}])
    make_product(out, "converted/hosts/10007-all.json", [{"domain": ["h2.com"]}])
    make_product(out, "converted/adguard/GOODBYEADS-allow.json",
                 [{"domain": ["allow1.com", "__singbox_never_match__"]}])
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
            self.assertIn("combined 3 条", new_text)      # a + b + c（logical 递归）
            self.assertIn("adguard  1 条", new_text)
            self.assertIn("hosts    1 条", new_text)
            self.assertIn("217heidai  2 条", new_text)
            self.assertIn("GOODBYEADS-dns  1 条", new_text)  # port 数字不计，只计 ip_cidr
            self.assertIn("GOODBYEADS-allow    1 条", new_text)  # 占位符排除
            self.assertIn("规则订阅", new_text)               # 正文不受影响
            self.assertNotIn("999 条", new_text)

    def test_update_readme_missing_block(self):
        with tempfile.TemporaryDirectory() as td:
            readme = Path(td) / "README.md"
            readme.write_text("# no stats block\n", encoding="utf-8")
            out = Path(td) / "out"
            with self.assertRaises(RuntimeError):
                urs.update_readme(readme, out)


if __name__ == "__main__":
    unittest.main()
