#!/usr/bin/env python3
"""download-sources.py 单元测试（污染检测逻辑）。"""

import importlib.util
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "download_sources", Path(__file__).resolve().parent.parent / "scripts" / "download-sources.py")
assert SPEC and SPEC.loader
ds = importlib.util.module_from_spec(SPEC)
sys.modules["download_sources"] = ds
SPEC.loader.exec_module(ds)


class TestPollutionDetection(unittest.TestCase):
    """WAF/HTML 拦截页污染检测。"""

    def test_html_pollution_detected(self):
        polluted = [
            "<!DOCTYPE html><html style=\"height:100%;width:100%\">",
            "<html>CloudWAF 访问被拦截",
            "您的请求疑似攻击行为，请稍后再试",
        ]
        for text in polluted:
            self.assertTrue(ds.is_polluted(text), f"应判为污染: {text[:40]!r}")

    def test_normal_rules_not_polluted(self):
        normal = [
            "! Title: AdBlock DNS\n||ads.example.com^\n",
            "[Adblock Plus 2.0]\n0.0.0.0 example.com\n",
            "# StevenBlack hosts\n127.0.0.1 localhost\n",
        ]
        for text in normal:
            self.assertFalse(ds.is_polluted(text), f"不应判为污染: {text[:40]!r}")

    def test_url_whitelist(self):
        # https + 主机白名单校验（防 file:// 与任意主机）
        self.assertTrue(ds._check_url("https://raw.githubusercontent.com/a/b/c.txt"))
        self.assertTrue(ds._check_url("https://lingeringsound.github.io/10007/adb.txt"))
        with self.assertRaises(ValueError):
            ds._check_url("file:///etc/passwd")
        with self.assertRaises(ValueError):
            ds._check_url("http://example.com/x.txt")
        with self.assertRaises(ValueError):
            ds._check_url("https://evil.com/x.txt")
        # github.com 网页会触发污染检测且禁重定向，属死配置，不列入白名单
        with self.assertRaises(ValueError):
            ds._check_url("https://github.com/user/repo/blob/main/a.txt")

    def test_html_in_body_not_detected(self):
        # 只扫描头部 8KB：HTML 出现在 8KB 之后不判污染（规则正文里的标签不是拦截页）
        body = "! 规则正文\n" + "x" * 9000 + "\n<!DOCTYPE html><html>"
        self.assertFalse(ds.is_polluted(body))


class TestDestConflict(unittest.TestCase):
    """同 basename 源名 → 解析到同一目标应报错。"""

    def test_same_basename_conflict(self):
        import contextlib
        import io
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            manifest = [
                {"name": "a/adblock", "url": "https://raw.githubusercontent.com/x/y/a.txt", "type": "adguard"},
                {"name": "c/adblock", "url": "https://raw.githubusercontent.com/x/y/b.txt", "type": "adguard"},
            ]
            mf = Path(td) / "sources.json"
            mf.write_text(json.dumps(manifest), encoding="utf-8")
            err = io.StringIO()
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
                ds.main(["--sources", str(mf), "--out", str(Path(td) / "out")])
            self.assertIn("同一目标", err.getvalue())


if __name__ == "__main__":
    unittest.main()
