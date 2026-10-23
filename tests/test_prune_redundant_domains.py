#!/usr/bin/env python3
"""冗余精确域名剪枝（prune_redundant_domains）单元测试。

语义约束：剪枝只能删除「已被同条件 domain_suffix 覆盖」的精确域名，
不得改变任何域名的拦截结果，也不得误删白名单/反向规则里的域名。
"""

import importlib.util
import sys
import unittest
from pathlib import Path


def _locate_script() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here / "adguard2headless.py", here.parent / "scripts" / "adguard2headless.py"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError("adguard2headless.py not found")


SPEC = importlib.util.spec_from_file_location("adguard2headless_prune", _locate_script())
assert SPEC and SPEC.loader
conv = importlib.util.module_from_spec(SPEC)
sys.modules["adguard2headless_prune"] = conv
SPEC.loader.exec_module(conv)


def _matches(rule: dict, domain: str) -> bool:
    """简易匹配器：仅覆盖 domain / domain_suffix（测试用，忽略条件字段）。"""
    for d in rule.get("domain", []):
        if d == domain:
            return True
    for s in rule.get("domain_suffix", []):
        if domain == s or domain.endswith("." + s):
            return True
    return False


def _blocked(rules: list, domain: str) -> bool:
    for r in rules:
        if r.get("type") == "logical":
            if r.get("mode") == "or" and not r.get("invert"):
                if _blocked(r["rules"], domain):
                    return True
            continue
        if r.get("invert"):
            continue
        if _matches(r, domain):
            return True
    return False


class TestPruneRedundantDomains(unittest.TestCase):
    def test_exact_domain_covered_by_suffix_is_pruned(self):
        rules = [
            {"domain_suffix": ["ads.example.com"]},
            {"domain": ["ads.example.com", "sub.ads.example.com", "unrelated.net"]},
        ]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(out[1]["domain"], ["unrelated.net"])
        self.assertEqual(out[0]["domain_suffix"], ["ads.example.com"])

    def test_domain_list_removed_when_fully_covered(self):
        rules = [
            {"domain_suffix": ["example.com"]},
            {"domain": ["a.example.com", "b.example.com"]},
        ]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0], {"domain_suffix": ["example.com"]})

    def test_rule_with_extra_conditions_keeps_condition_when_domains_vanish(self):
        # 只有 domain 字段的规则才会整条删除；带 query_type 的规则删空后同样整条删除
        rules = [
            {"query_type": ["A"], "domain_suffix": ["example.com"]},
            {"query_type": ["A"], "domain": ["x.example.com"]},
        ]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(out, [{"query_type": ["A"], "domain_suffix": ["example.com"]}])

    def test_different_conditions_are_not_pruned(self):
        rules = [
            {"query_type": ["A"], "domain_suffix": ["example.com"]},
            {"domain": ["x.example.com"]},  # 无 query_type → 条件不同，不可删
        ]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(out[1]["domain"], ["x.example.com"])

    def test_port_conditions_must_match(self):
        rules = [
            {"port": [8080], "domain_suffix": ["example.com"]},
            {"domain": ["x.example.com"]},
        ]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(out[1]["domain"], ["x.example.com"])

    def test_excluded_domains_are_kept(self):
        rules = [
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"invert": True, "domain_suffix": ["allow.example.com"]},
                    {"domain_suffix": ["example.com"]},
                ],
            },
            {"domain": ["ok.allow.example.com", "sub.example.com"]},
        ]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(out[1]["domain"], ["ok.allow.example.com"])

    def test_inverted_branch_is_not_a_coverage_source(self):
        rules = [
            {"invert": True, "domain_suffix": ["example.com"]},
            {"domain": ["x.example.com"]},
        ]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(out[1]["domain"], ["x.example.com"])

    def test_pruning_preserves_blocking_result(self):
        domains = ["ads.example.com", "sub.ads.example.com", "ok.net", "deep.a.example.com"]
        before = [
            {"domain_suffix": ["example.com"]},
            {"domain": list(domains)},
        ]
        after = conv.prune_redundant_domains([
            {"domain_suffix": ["example.com"]},
            {"domain": list(domains)},
        ])
        for d in domains:
            self.assertEqual(_blocked(before, d), _blocked(after, d), d)

    def test_non_domain_rules_untouched(self):
        rules = [{"ip_cidr": ["1.2.3.4/32"]}, {"domain_regex": [r"^a\.b$"]}]
        out = conv.prune_redundant_domains(rules)
        self.assertEqual(out, rules)


class TestConvertAllPruning(unittest.TestCase):
    @staticmethod
    def _exact_domains(rules: list) -> set[str]:
        found: set[str] = set()
        for r in rules:
            if r.get("type") == "logical":
                found |= TestConvertAllPruning._exact_domains(r.get("rules", []))
            else:
                found.update(r.get("domain", []))
        return found

    def test_combined_prunes_hosts_covered_by_adguard(self):
        adguard = "||example.com^\n||ads.example.com^\n"
        hosts = "0.0.0.0 sub.example.com\n0.0.0.0 standalone.net\n"
        result = conv.convert_all([("a.txt", adguard)], [("h.hosts", hosts)])
        exact = self._exact_domains(result["merged"]["combined"]["rules"])
        # sub.example.com 已被 adguard 的 domain_suffix example.com 覆盖 → 剪除
        self.assertNotIn("sub.example.com", exact)
        self.assertIn("standalone.net", exact)

    def test_hosts_product_is_not_pruned_by_combined(self):
        adguard = "||example.com^\n"
        hosts = "0.0.0.0 sub.example.com\n"
        result = conv.convert_all([("a.txt", adguard)], [("h.hosts", hosts)])
        exact = self._exact_domains(result["merged"]["hosts"]["rules"])
        self.assertIn("sub.example.com", exact)


if __name__ == "__main__":
    unittest.main()
