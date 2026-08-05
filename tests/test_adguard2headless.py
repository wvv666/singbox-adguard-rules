#!/usr/bin/env python3
"""adguard2headless 转换器单元测试。

语义基准：sing-box 官方 common/convertor/adguard/convertor_test.go
的 TestConverter / TestHosts / TestSimpleHosts 匹配列表，外加增强映射用例。
"""

import importlib.util
import ipaddress
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

def _locate_script() -> Path:
    """定位 adguard2headless.py：优先同目录，其次上级 scripts/（项目布局）。"""
    here = Path(__file__).resolve().parent
    for candidate in (here / "adguard2headless.py", here.parent / "scripts" / "adguard2headless.py"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError("adguard2headless.py not found")


SPEC = importlib.util.spec_from_file_location(
    "adguard2headless", _locate_script())
assert SPEC and SPEC.loader
conv = importlib.util.module_from_spec(SPEC)
sys.modules["adguard2headless"] = conv  # dataclass 需要模块注册
SPEC.loader.exec_module(conv)


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def matches(rule: dict, domain: str, *, query_type=None, port=None, source_ip=None) -> bool:
    """轻量匹配模拟器：按官方无头规则文档的 Default Fields 公式。

    (domain || domain_suffix || domain_keyword || domain_regex || ip_cidr) &&
    (port || port_range) && (source_port || source_port_range) && other fields
    """
    if rule.get("type") == "logical":
        if rule["mode"] == "and":
            res = all(matches(r, domain, query_type=query_type, port=port, source_ip=source_ip)
                      for r in rule["rules"])
        else:
            res = any(matches(r, domain, query_type=query_type, port=port, source_ip=source_ip)
                      for r in rule["rules"])
    else:
        res = match_default(rule, domain, query_type=query_type, port=port, source_ip=source_ip)
    return res if not rule.get("invert", False) else not res


def match_default(r: dict, domain: str, *, query_type=None, port=None, source_ip=None) -> bool:
    """default 规则匹配：域名组内 OR，修饰符组间 AND（官方文档公式）。"""
    has_domain_field = any(k in r for k in (
        "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"))
    if has_domain_field:
        domain_ok = (
            ("domain" in r and domain in r["domain"]) or
            ("domain_suffix" in r and any(
                domain == d or domain.endswith("." + d) for d in r["domain_suffix"])) or
            ("domain_keyword" in r and any(k in domain for k in r["domain_keyword"])) or
            ("domain_regex" in r and any(re.search(p, domain) for p in r["domain_regex"]))
        )
        # ip_cidr 匹配解析结果 IP，纯域名上下文无法评估（无响应 IP 时视为未命中）
        if not domain_ok:
            return False
    port_ok = "port" not in r or (port is not None and port in r["port"])
    qt_ok = "query_type" not in r or (
        query_type is not None and query_type in r["query_type"])
    src_ok = "source_ip_cidr" not in r or (
        source_ip is not None and any(
            _ip_in_cidr(source_ip, c) for c in r["source_ip_cidr"]))
    return port_ok and qt_ok and src_ok


def single_rule(text: str) -> dict:
    result = conv.convert(text)
    assert len(result["rules"]) == 1, f"期望 1 条规则，实际 {len(result['rules'])}: {result}"
    return result["rules"][0]


class TestOfficialConverterSemantics(unittest.TestCase):
    """对齐官方 convertor_test.go 的 TestConverter。"""

    RULES = """||sagernet.org^$important
@@|sing-box.sagernet.org^$important
||example.org^
|example.com^
example.net^
||example.edu
||example.edu.tw^
|example.gov
example.arpa
@@|sagernet.example.org^
"""

    MATCH = [
        "example.org", "www.example.org", "example.com", "example.net",
        "isexample.net", "www.example.net", "example.edu", "example.edu.cn",
        "example.edu.tw", "www.example.edu", "www.example.edu.cn", "example.gov",
        "example.arpa", "sagernet.org", "www.sagernet.org",
        # ||example.edu（无 ^）：x 后不限（AdGuard 宽松后缀语义）
        "example.education", "example.edu.evil.com",
    ]
    NOT_MATCH = [
        "example.org.cn", "notexample.org", "example.com.cn", "www.example.com.cn",
        "example.net.cn", "notexample.edu", "notexample.edu.cn", "www.example.gov",
        "notexample.gov", "sagernet.example.org", "sing-box.sagernet.org",
        # 放宽不越界：x 必须是完整标签边界
        "notexample.education", "badexample.edu.evil.com",
    ]

    def test_converter_semantics(self):
        rules = conv.convert(self.RULES)["rules"]
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        for domain in self.MATCH:
            self.assertTrue(matches(rule, domain), f"应匹配: {domain}")
        for domain in self.NOT_MATCH:
            self.assertFalse(matches(rule, domain), f"不应匹配: {domain}")

    def test_hosts_only_zero_ip(self):
        # 接受 0.0.0.0 / :: / 127.0.0.0/8；::1 等其他 IP 丢弃；单标签域名（localhost）非有效目标
        result = conv.convert(
            "127.0.0.1 localhost\n::1 localhost #[IPv6]\n0.0.0.0 google.com\n"
            "127.0.0.1 ads.example.com\n")
        rule = result["rules"][0]
        self.assertTrue(matches(rule, "google.com"))
        self.assertTrue(matches(rule, "ads.example.com"))  # 127.0.0.1 已接受
        self.assertFalse(matches(rule, "www.google.com"))
        self.assertFalse(matches(rule, "localhost"))       # 单标签域名被丢弃
        self.assertTrue(any("::1" in r for r in result["_ignored"]))

    def test_hosts_127_loopback(self):
        # yhosts/ad-wars 等列表用 127.0.0.1 拦广告
        rule = single_rule("127.0.0.1 ads.example.com\n127.0.0.2 track.example.com\n")
        self.assertEqual(rule, {"domain": ["ads.example.com", "track.example.com"]})

    def test_hosts_inline_comment_and_tab(self):
        # hosts 行内注释与 tab 分隔
        rule = single_rule(
            "0.0.0.0 ads.example.com # ad server\n"
            "0.0.0.0\ttrack.example.com\n"
            ":: blocked.example.com\n")
        self.assertEqual(rule, {"domain": [
            "ads.example.com", "blocked.example.com", "track.example.com"]})

    def test_simple_hosts_exact(self):
        # 官方 TestSimpleHosts：裸域名精确匹配
        rule = single_rule("example.com\nwww.example.org\n")
        self.assertEqual(rule, {"domain": ["example.com", "www.example.org"]})
        for d in ["example.com", "www.example.org"]:
            self.assertTrue(matches(rule, d))
        for d in ["example.com.cn", "www.example.com", "notexample.com", "example.org"]:
            self.assertFalse(matches(rule, d))

    def test_mixed_adguard_and_hosts(self):
        # 同一文件混合 AdGuard 语法与 hosts 语法：逐行自动识别
        rule = single_rule(
            "||ads.example^\n"           # AdGuard：后缀匹配
            "0.0.0.0 host.example.com\n" # hosts：精确匹配
            "|exact.example^\n")         # AdGuard：精确匹配
        self.assertEqual(rule, {
            "domain": ["exact.example", "host.example.com"],
            "domain_suffix": ["ads.example"],
        })
        self.assertTrue(matches(rule, "ads.example"))
        self.assertTrue(matches(rule, "sub.ads.example"))   # 后缀语义保留
        self.assertTrue(matches(rule, "host.example.com"))
        self.assertFalse(matches(rule, "sub.host.example.com"))  # hosts 精确语义保留


class TestEnhancedMappings(unittest.TestCase):
    """官方转换器丢弃、但我们增强支持的部分。"""

    def test_dnstype_to_query_type(self):
        rule = single_rule("||tracker.example^$dnstype=A\n")
        self.assertEqual(rule, {"domain_suffix": ["tracker.example"], "query_type": ["A"]})

    def test_ip_cidr(self):
        rule = single_rule("1.1.1.1\n10.0.0.\n1.1.1.0/24\n")
        self.assertEqual(rule, {"ip_cidr": ["1.1.1.0/24", "1.1.1.1", "10.0.0.0/24"]})

    def test_anchored_ip_is_domain_not_ipcidr(self):
        # ||1.2.3.4^ 带锚点：官方语义是域名（IsDomainName 接受 IP 串），进 domain_suffix
        result = conv.convert("||1.2.3.4^\n1.2.3.4\n")
        rule = result["rules"][0]
        self.assertEqual(rule["domain_suffix"], ["1.2.3.4"])
        self.assertEqual(rule["ip_cidr"], ["1.2.3.4"])

    def test_modified_ip_line_is_ipcidr(self):
        # 无锚点 + 修饰符的纯 IP：剥掉修饰符后是裸 IP → ip_cidr + query_type（AND）
        rule = single_rule("1.1.1.1$dnstype=A\n")
        self.assertEqual(rule, {"ip_cidr": ["1.1.1.1"], "query_type": ["A"]})

    def test_unknown_dnstype_dropped(self):
        # 未知 DNS 类型会让 sing-box compile 失败 → 整行丢弃
        result = conv.convert("||x.example^$dnstype=ZZZ\n||y.example^$dnstype=A\n")
        self.assertEqual(result["rules"][0], {"domain_suffix": ["y.example"], "query_type": ["A"]})
        self.assertTrue(any("ZZZ" in r for r in result["_ignored"]))

    def test_port_out_of_range_dropped(self):
        result = conv.convert("||a.example:99999^\n||b.example:8080^\n")
        self.assertEqual(result["rules"][0], {"domain_suffix": ["b.example"], "port": [8080]})
        self.assertTrue(any("99999" in r for r in result["_ignored"]))

    def test_oversized_regex_dropped(self):
        result = conv.convert(f"/{'a' * 3000}/\n||b.example^\n")
        self.assertEqual(result["rules"][0], {"domain_suffix": ["b.example"]})
        self.assertTrue(any("超长" in r for r in result["_ignored"]))

    def test_port(self):
        rule = single_rule("||bad.example.com:8080^\n")
        self.assertEqual(rule, {"domain_suffix": ["bad.example.com"], "port": [8080]})

    def test_multiple_modifiers_keep_and_semantics(self):
        rule = single_rule("||x.example^$dnstype=AAAA\n||y.example^$dnstype=AAAA\n")
        self.assertEqual(rule["domain_suffix"], ["x.example", "y.example"])
        self.assertEqual(rule["query_type"], ["AAAA"])

    def test_dnstype_multi_values(self):
        # AdGuard 多值 $dnstype=A|AAAA
        rule = single_rule("||x.example^$dnstype=A|AAAA\n")
        self.assertEqual(rule, {"domain_suffix": ["x.example"], "query_type": ["A", "AAAA"]})

    def test_modifier_buckets_do_not_collide(self):
        # 不同修饰符桶不能合并成一条 default rule（同条内多字段是 AND）
        rules = conv.convert("||a.example^$dnstype=A\n||b.example:8080^\n")["rules"]
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule["type"], "logical")
        self.assertEqual(rule["mode"], "or")
        self.assertEqual(len(rule["rules"]), 2)
        q_rule, p_rule = rule["rules"]
        self.assertEqual(q_rule.get("query_type"), ["A"])
        self.assertNotIn("port", q_rule)
        self.assertEqual(p_rule.get("port"), [8080])
        self.assertNotIn("query_type", p_rule)


class TestLogicalStructure(unittest.TestCase):
    """@@ 例外与 $important 的 logical 表达（对齐官方分组）。"""

    def test_exclude_becomes_and_invert(self):
        rule = single_rule("||ads.example^\n@@||ok.example^\n")
        self.assertEqual(rule["type"], "logical")
        self.assertEqual(rule["mode"], "and")
        excl, main = rule["rules"]
        self.assertTrue(excl["invert"])
        self.assertEqual(excl["domain_suffix"], ["ok.example"])
        self.assertEqual(main["domain_suffix"], ["ads.example"])
        self.assertTrue(matches(rule, "ads.example"))
        self.assertFalse(matches(rule, "ok.example"))
        self.assertFalse(matches(rule, "sub.ok.example"))

    def test_exclude_overrides_block(self):
        # 防回归：同域名"拦截 + 例外"共存时，@@ 例外优先于拦截（AdGuard 语义）
        rule = single_rule("||ads.example^\n@@||ads.example^\n||other.example^\n")
        self.assertFalse(matches(rule, "ads.example"))       # 被例外放行
        self.assertFalse(matches(rule, "sub.ads.example"))   # 例外覆盖子域
        self.assertTrue(matches(rule, "other.example"))      # 无关域名照常拦截

    def test_subdomain_deduped_by_parent(self):
        # 父域包含去重：sub.ads.example 被 ads.example 后缀覆盖 → 删除
        rule = single_rule("||ads.example^\n||sub.ads.example^\n||other.example^\n")
        self.assertEqual(rule["domain_suffix"], ["ads.example", "other.example"])
        # 语义不变：sub.ads.example 仍被拦截（ads.example 后缀覆盖）
        self.assertTrue(matches(rule, "sub.ads.example"))
        self.assertTrue(matches(rule, "ads.example"))

    def test_multi_level_subdomain_dedup(self):
        # 多级父域链：只留最顶层
        rule = single_rule("||ads.example^\n||b.ads.example^\n||a.b.ads.example^\n")
        self.assertEqual(rule["domain_suffix"], ["ads.example"])

    def test_exact_domain_not_deduped(self):
        # domain（精确）不适用父域去重：|sub.ads.example^ 不被 ||ads.example^ 删除（不同桶）
        rule = single_rule("||ads.example^\n|sub.ads.example^\n")
        self.assertEqual(rule["domain_suffix"], ["ads.example"])
        self.assertEqual(rule["domain"], ["sub.ads.example"])

    def test_important_becomes_or(self):
        rule = single_rule("||ads.example^\n||important.example^$important\n")
        self.assertEqual(rule["type"], "logical")
        self.assertEqual(rule["mode"], "or")
        imp, main = rule["rules"]
        self.assertEqual(imp["domain_suffix"], ["important.example"])
        self.assertEqual(main["domain_suffix"], ["ads.example"])

    def test_important_exclude(self):
        rule = single_rule("||important.example^$important\n@@|sub.important.example^$important\n")
        self.assertEqual(rule["mode"], "and")
        imp_excl, _ = rule["rules"]
        self.assertTrue(imp_excl["invert"])
        self.assertEqual(imp_excl["domain"], ["sub.important.example"])
        self.assertTrue(matches(rule, "important.example"))
        self.assertFalse(matches(rule, "sub.important.example"))


class TestSubdomainOnlyAndWildcard(unittest.TestCase):
    """||*.x^ 仅子域、* 通配符（domain_suffix 表达不了，转 domain_regex）。"""

    def test_subdomain_only(self):
        rule = single_rule("||*.child.example^\n")
        self.assertIn("domain_regex", rule)
        self.assertTrue(matches(rule, "a.child.example"))
        self.assertTrue(matches(rule, "a.b.child.example"))
        self.assertFalse(matches(rule, "child.example"))

    def test_wildcard(self):
        rule = single_rule("||ad*.example.com^\n")
        self.assertIn("domain_regex", rule)
        self.assertTrue(matches(rule, "ad123.example.com"))
        self.assertFalse(matches(rule, "ab.example.com"))


class TestIgnored(unittest.TestCase):
    """官方也丢弃的形态，应进 _ignored 而不是静默丢失。"""

    def test_ignored_kinds(self):
        result = conv.convert(
            "example.com/path/ad.js\n"
            "example.com##.banner\n"
            "||x.example^$third-party\n"
            "||y.example^$app=com.foo\n"
            "example.com~foo\n")
        self.assertEqual(result["rules"], [])
        reasons = " | ".join(result["_ignored"])
        self.assertIn("路径", reasons)
        self.assertIn("cosmetic", reasons)
        self.assertIn("third-party", reasons)
        self.assertIn("app", reasons)
        self.assertIn("~", reasons)

    def test_hash_comment_skipped(self):
        # AdGuard 的 ## cosmetic 规则以 # 开头，被注释分支静默跳过（与官方一致）
        result = conv.convert("##.banner\n#?#.ad\n! comment\n")
        self.assertEqual(result["rules"], [])
        self.assertEqual(result["_ignored"], [])


class TestDocFormula(unittest.TestCase):
    """以官方无头规则文档的 Default Fields 匹配公式为基准：

    (domain || domain_suffix || domain_keyword || domain_regex || ip_cidr) &&
    (port || port_range) && (source_port || source_port_range) && other fields
    """

    def test_domain_group_is_or(self):
        # 无修饰符的 domain + domain_suffix 合并进同一条 default rule → 组内 OR
        rule = single_rule("||ads.example^\n|exact.example^\n")
        self.assertEqual(rule, {"domain": ["exact.example"], "domain_suffix": ["ads.example"]})
        self.assertTrue(matches(rule, "ads.example"))       # suffix 命中
        self.assertTrue(matches(rule, "www.ads.example"))   # suffix 命中
        self.assertTrue(matches(rule, "exact.example"))     # domain 命中
        self.assertFalse(matches(rule, "notads.example"))   # 都未命中

    def test_query_type_is_and(self):
        rule = single_rule("||x.example^$dnstype=A\n")
        self.assertTrue(matches(rule, "x.example", query_type="A"))
        self.assertFalse(matches(rule, "x.example", query_type="AAAA"))
        self.assertFalse(matches(rule, "x.example"))  # 无上下文不命中

    def test_port_is_and(self):
        rule = single_rule("||x.example:8080^\n")
        self.assertTrue(matches(rule, "x.example", port=8080))
        self.assertFalse(matches(rule, "x.example", port=80))
        self.assertFalse(matches(rule, "x.example"))

    def test_ip_cidr_alone_needs_response_context(self):
        # 纯 ip_cidr 规则：域名查询上下文（无响应 IP）不命中
        rule = single_rule("1.1.1.1\n")
        self.assertEqual(rule, {"ip_cidr": ["1.1.1.1"]})
        self.assertFalse(matches(rule, "anything.example"))


class TestClientModifier(unittest.TestCase):
    """$client=IP|CIDR → source_ip_cidr（官方无头规则文档字段）。"""

    def test_client_cidr(self):
        rule = single_rule("||ads.com^$client=192.168.1.0/24\n")
        self.assertEqual(rule, {
            "domain_suffix": ["ads.com"],
            "source_ip_cidr": ["192.168.1.0/24"],
        })

    def test_client_multi_values(self):
        rule = single_rule("||ads.com^$client=1.1.1.1|2.2.2.0/24\n")
        self.assertEqual(rule["source_ip_cidr"], ["1.1.1.1", "2.2.2.0/24"])

    def test_client_name_dropped(self):
        # 客户端名/标签无法映射到 source_ip_cidr → 整行丢弃（fail-closed）
        result = conv.convert("||ads.com^$client=MyPhone\n||ok.com^\n")
        self.assertEqual(result["rules"][0], {"domain_suffix": ["ok.com"]})
        self.assertTrue(any("MyPhone" in r for r in result["_ignored"]))

    def test_source_ip_and_semantics(self):
        rule = single_rule("||ads.com^$client=192.168.1.0/24\n")
        self.assertTrue(matches(rule, "ads.com", source_ip="192.168.1.5"))
        self.assertFalse(matches(rule, "ads.com", source_ip="8.8.8.8"))
        self.assertFalse(matches(rule, "ads.com"))  # 无源 IP 上下文不命中

    def test_regex_line_with_client(self):
        rule = single_rule("/^ad[0-9]+\\.com$/$client=10.0.0.0/8\n")
        self.assertEqual(rule, {
            "domain_regex": ["^ad[0-9]+\\.com$"],
            "source_ip_cidr": ["10.0.0.0/8"],
        })

    def test_client_buckets_split(self):
        # 不同 $client 桶不能合并成一条（同条内多字段是 AND）
        rules = conv.convert(
            "||a.example^$client=10.0.0.0/8\n||b.example^$client=192.168.0.0/16\n")["rules"]
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule["type"], "logical")
        self.assertEqual(rule["mode"], "or")
        self.assertEqual(len(rule["rules"]), 2)
        self.assertEqual(rule["rules"][0]["source_ip_cidr"], ["10.0.0.0/8"])
        self.assertEqual(rule["rules"][1]["source_ip_cidr"], ["192.168.0.0/16"])


class TestThreeProducts(unittest.TestCase):
    """产物分三种：adguard / hosts / combined。"""

    def _collect_defaults(self, rules):
        defaults = []

        def walk(r):
            if r.get("type") == "logical":
                for sub in r["rules"]:
                    walk(sub)
            else:
                defaults.append(r)

        for r in rules:
            walk(r)
        return defaults

    def test_three_products(self):
        result = conv.convert_multi(
            adguard_texts=["||ads.example^\n|exact.example^\n"],
            hosts_texts=["0.0.0.0 host.example.com\n127.0.0.1 loop.example.com\n"])
        products = result["products"]
        self.assertEqual(set(products), {"adguard", "hosts", "combined"})

        # adguard 产物：只含 AdGuard 语法规则
        adg = self._collect_defaults(products["adguard"]["rules"])
        self.assertEqual(len(adg), 1)
        self.assertEqual(adg[0]["domain_suffix"], ["ads.example"])
        self.assertEqual(adg[0]["domain"], ["exact.example"])

        # hosts 产物：只含 hosts 规则
        h = self._collect_defaults(products["hosts"]["rules"])
        self.assertEqual(h[0]["domain"], ["host.example.com", "loop.example.com"])

        # combined 产物：两者合并（rules 数组 OR）
        c = self._collect_defaults(products["combined"]["rules"])
        domains = set()
        suffixes = set()
        for d in c:
            domains.update(d.get("domain", []))
            suffixes.update(d.get("domain_suffix", []))
        self.assertEqual(domains, {"exact.example", "host.example.com", "loop.example.com"})
        self.assertEqual(suffixes, {"ads.example"})

    def test_single_source_only(self):
        # 只有 hosts 输入：只生成 hosts + combined（不生成空 adguard）
        result = conv.convert_multi(adguard_texts=[], hosts_texts=["0.0.0.0 a.example\n"])
        self.assertEqual(set(result["products"]), {"hosts", "combined"})

    def test_source_override(self):
        # 显式 source 覆盖 auto 识别：hosts 语法行归入 adguard 类
        result = conv.convert("0.0.0.0 a.example\n", source="adguard")
        self.assertEqual(result["rules"][0]["domain"], ["a.example"])

    def test_empty_products_graceful(self):
        # 全部输入被忽略时：products 为空，不抛异常
        result = conv.convert_multi(
            adguard_texts=["! 只有注释\n# 也是注释\n"],
            hosts_texts=["# 空 hosts\n"])
        self.assertEqual(result["products"], {})


class TestFullTree(unittest.TestCase):
    """完整产物树：单源转换 + 合并去重（原始行去重）。"""

    def test_convert_all(self):
        result = conv.convert_all(
            adguard_sources=[
                ("a.txt", "||ads.example^\n0.0.0.0 dup.example\n! c1\n"),
                ("b.txt", "||other.example^\n0.0.0.0 dup.example\n"),
            ],
            hosts_sources=[
                ("h.hosts", "0.0.0.0 host.example.com\n0.0.0.0 dup.example\n"),
            ])
        # 单源转换
        self.assertEqual(set(result["per_source"]["adguard"]), {"a.txt", "b.txt"})
        self.assertEqual(set(result["per_source"]["hosts"]), {"h.hosts"})
        # merged.adguard：原始行去重（dup.example 只留一次）
        adg_text = result["merged"]["adguard"]["text"]
        self.assertEqual(adg_text.count("dup.example"), 1)
        self.assertIn("||ads.example^", adg_text)
        self.assertIn("||other.example^", adg_text)
        # merged.combined：跨类去重（dup.example 在 adguard 和 hosts 都有 → 只留一次）
        comb_text = result["merged"]["combined"]["text"]
        self.assertEqual(comb_text.count("dup.example"), 1)
        self.assertIn("||ads.example^", comb_text)
        self.assertIn("0.0.0.0 host.example.com", comb_text)

    def test_merge_dedupe_keeps_first(self):
        text = conv._merge_dedupe_texts(["a\nb\na\n! c\n", "b\nc\n"])
        self.assertEqual(text, "a\nb\n! c\nc\n")

    def test_convert_all_single_source(self):
        result = conv.convert_all(adguard_sources=[], hosts_sources=[("h.hosts", "0.0.0.0 a.example\n")])
        self.assertEqual(result["per_source"]["adguard"], {})
        self.assertEqual(set(result["merged"]), {"hosts", "combined"})

    def test_merged_three_categories(self):
        # 用户确认的设计：合并去重产物恰分三类（hosts / adguard / 两者一起）
        result = conv.convert_all(
            adguard_sources=[("a.txt", "||ads.example^\n")],
            hosts_sources=[("h.hosts", "0.0.0.0 host.example.com\n")])
        merged = result["merged"]
        # ① 恰有三类
        self.assertEqual(set(merged), {"adguard", "hosts", "combined"})
        # ② 每类都有原始文本 + 转换规则
        for name, m in merged.items():
            self.assertIn("text", m, f"{name} 缺 text")
            self.assertIn("rules", m, f"{name} 缺 rules")
        # ③ 内容按语法源归类：adguard 类只含 adguard 源行，hosts 类只含 hosts 源行
        self.assertIn("||ads.example^", merged["adguard"]["text"])
        self.assertNotIn("0.0.0.0", merged["adguard"]["text"])
        self.assertIn("0.0.0.0 host.example.com", merged["hosts"]["text"])
        self.assertNotIn("||", merged["hosts"]["text"])
        # ④ combined 含两者
        self.assertIn("||ads.example^", merged["combined"]["text"])
        self.assertIn("0.0.0.0 host.example.com", merged["combined"]["text"])

    def test_write_output_tree(self):
        # CLI 目录树集成：sources/converted/merged 全部生成（rule-sets/ 已按用户要求移除）
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            result = conv.convert_all(
                adguard_sources=[("a-rules.txt", "||ads.example^\n")],
                hosts_sources=[("h.hosts", "0.0.0.0 host.example.com\n")])
            conv.write_output_tree(
                out, result,
                adguard_sources=[("a-rules.txt", "||ads.example^\n")],
                hosts_sources=[("h.hosts", "0.0.0.0 host.example.com\n")])
            files = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
            self.assertEqual(files, [
                "converted/adguard/a-rules.json",
                "converted/hosts/h.json",
                "merged/adguard/adguard.json",
                "merged/adguard/adguard.txt",
                "merged/combined/combined.json",
                "merged/combined/combined.txt",
                "merged/hosts/hosts.json",
                "merged/hosts/hosts.txt",
                "sources/adguard/a-rules.txt",
                "sources/hosts/h.hosts",
            ])

    def test_convert_all_no_empty_product(self):
        # 纯注释输入：不生成空 merged 产物
        result = conv.convert_all(
            adguard_sources=[("c.txt", "! 只有注释\n# 注释\n")],
            hosts_sources=[])
        self.assertEqual(result["merged"], {})

    def test_name_conflicts_same_kind(self):
        # 同类内 stem 重复 → 报错级冲突
        self.assertEqual(
            conv._check_name_conflicts(
                [("a.txt", "x"), ("a.hosts", "y")], []),
            ["adguard: ['a']"])
        self.assertEqual(
            conv._check_name_conflicts([("a.txt", "x")], [("a.hosts", "y")]),
            [])  # 跨 kind 同名不冲突（converted/ 子目录分离）

    def test_reserved_name_no_error(self):
        # 输入叫 hosts.txt：目录分离不报错（rule-sets 已移除，无引用合并问题）
        self.assertEqual(
            conv._check_name_conflicts([], [("hosts.txt", "x")]),
            [])


class TestOutputShape(unittest.TestCase):
    """输出必须能被 sing-box rule-set compile 接受（字段名/结构合法）。"""

    # 官方无头规则文档字段全集（Headless Rule / Default Fields / Logical Fields）
    KNOWN_FIELDS = {
        "domain", "domain_suffix", "domain_keyword", "domain_regex",
        "ip_cidr", "source_ip_cidr", "port", "port_range",
        "source_port", "source_port_range", "query_type", "network",
        "process_name", "process_path", "process_path_regex",
        "package_name", "package_name_regex", "network_type",
        "network_is_expensive", "network_is_constrained",
        "network_interface_address", "default_interface_address",
        "wifi_ssid", "wifi_bssid", "invert", "type", "mode", "rules",
    }

    def test_output_compileable(self):
        result = conv.convert(
            "||sagernet.org^$important\n@@|sing-box.sagernet.org^$important\n"
            "||example.org^\n|example.com^\nexample.net^\n||example.edu\n"
            "example.arpa\n@@|sagernet.example.org^\n0.0.0.0 hosts.example\n"
            "1.1.1.1\n||t.example^$dnstype=A\n||p.example:8080^\n")
        self.assertEqual(result["version"], 3)
        self.assertEqual(len(result["rules"]), 1)

        def check(rule: dict):
            for field, value in rule.items():
                self.assertIn(field, self.KNOWN_FIELDS, f"未知字段: {field}")
                if field == "rules":
                    for sub in value:
                        check(sub)
                elif field in ("type", "mode", "invert", "network_is_expensive", "network_is_constrained"):
                    continue  # 字符串/布尔字段，跳过 list 校验

        check(result["rules"][0])


if __name__ == "__main__":
    unittest.main()
