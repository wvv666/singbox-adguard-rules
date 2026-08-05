#!/usr/bin/env python3
"""AdGuard DNS filter → sing-box headless-rule JSON 转换器（原型）。

目标：把 AdGuard DNS 规则"完整"转成 sing-box 无头规则的标准字段
（domain / domain_suffix / domain_regex / ip_cidr / query_type / port），
而不是官方 convert 只保留的 adguard_domain 子集。

语义基准：sing-box common/convertor/adguard/convertor.go + convertor_test.go
输出：{"version": 3, "rules": [<headless rule>...]}，可直接 sing-box rule-set compile。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

WILDCARD = "*"

# sing-box 接受的 DNS 查询类型（option.DNSQueryType UnmarshalJSON 白名单）
DNS_TYPE_WHITELIST = {
    "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "ANY",
    "CAA", "HTTPS", "SVCB", "NAPTR", "DS", "DNSKEY", "TLSA", "SSHFP",
    "IPSECKEY", "LOC", "HINFO", "CERT", "DNAME", "RP", "AFSDB", "URI",
    "OPENPGPKEY", "SMIMEA", "SPF", "TKEY", "TSIG", "IXFR", "AXFR", "OPT",
    "NSEC", "NSEC3", "NSEC3PARAM", "WKS", "NULL",
}

# 正则体长度上限（防损坏/巨型正则拖垮下游 compile）
MAX_REGEX_LEN = 2048


@dataclass
class Parsed:
    """一行 AdGuard 规则解析结果。"""
    core: str                    # 去锚点后的核心（域名 / 正则体 / IP）
    is_exclude: bool = False     # @@ 例外
    is_suffix: bool = False      # || 前缀（或 scheme:// 截断，或无前缀但带 ^）
    is_exact: bool = False       # | 前缀（精确域名）
    is_substring: bool = False   # 无前缀但带 ^：AdGuard 子串匹配（如 example.net^）
    suffix_loose: bool = False   # ||x 无 ^：x 后不限（官方测试 ||example.edu 匹配 example.edu.cn）
    is_regexp: bool = False      # /regexp/
    is_important: bool = False   # $important
    is_ip: bool = False          # 纯 IP / IP-CIDR 行
    query_types: list = field(default_factory=list)   # $dnstype=A → "A"
    ports: list = field(default_factory=list)         # example.com:8080 → [8080]
    source_ip_cidrs: list = field(default_factory=list)  # $client=1.1.1.0/24 → source_ip_cidr
    source: str = "adguard"      # 来源类别：adguard | hosts（auto 识别或显式指定）
    ignored_reason: str = ""     # 非空表示该行被丢弃


# ---------------------------------------------------------------- 解析

def _is_domain_name(s: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9.-]+", s)) and "." in s


def _parse_ip_cidr(line: str) -> Optional[str]:
    """解析 1.1.1.1、10.0.0. 前缀、1.1.1.0/24 CIDR，输出标准 CIDR 形式。"""
    explicit = None
    if "/" in line:
        base, _, pl = line.partition("/")
        if not re.fullmatch(r"\d{1,2}", pl) or not (0 <= int(pl) <= 32):
            return None
        explicit = int(pl)
        line = base
    is_prefix = line.endswith(".")
    if is_prefix:
        line = line[:-1]
    parts = line.split(".")
    if len(parts) > 4 or (len(parts) < 4 and not is_prefix and explicit is None):
        return None
    if not all(re.fullmatch(r"\d{1,3}", p) and int(p) <= 255 for p in parts):
        return None
    if explicit is not None:
        return f"{line}/{explicit}"
    if is_prefix:
        # 10.0.0. → 10.0.0.0/24（与官方 parseADGuardIPCIDRLine 的 bitLen 一致）
        return f"{'.'.join(parts + ['0'] * (4 - len(parts)))}/{len(parts) * 8}"
    return line


def _parse_hosts(line: str) -> Optional[Parsed]:
    """hosts 行：接受 0.0.0.0 / :: / 127.0.0.0/8 回环（拦截语义等价），映射为精确域名。

    支持 tab/多空格分隔与行内注释（0.0.0.0 example.com # comment）。
    """
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    ip_part, rest = parts
    domain = rest.split("#", 1)[0].strip()  # 剥离行内注释
    if not _is_domain_name(domain):
        return None
    if ip_part in ("0.0.0.0", "::"):
        return Parsed(core=domain, source="hosts")
    try:
        loopback = ipaddress.ip_address(ip_part) in ipaddress.ip_network("127.0.0.0/8")
    except ValueError:
        loopback = False
    if loopback:
        return Parsed(core=domain, source="hosts")
    return Parsed(core="", ignored_reason=f"hosts 非拦截 IP 被忽略: {line}")


def _parse_modifiers(params: str) -> Optional[Parsed]:
    """解析 $ 修饰符串（不含 $）。返回 None 表示整行丢弃。"""
    p = Parsed(core="")
    for param in params.split(","):
        name, _, value = param.partition("=")
        if name == "important":
            p.is_important = True
        elif name == "dnstype":
            if not value:
                return None
            for q in value.split("|"):  # AdGuard 多值用 | 分隔：$dnstype=A|AAAA
                if q.upper() not in DNS_TYPE_WHITELIST:
                    return None  # 未知类型整行丢弃，避免下游 compile 失败
                p.query_types.append(q.upper())
        elif name == "dnsrewrite":
            if value not in ("0.0.0.0", "::"):
                return None
        elif name == "client":
            # $client=IP|CIDR → source_ip_cidr；注：仅支持 IPv4（_parse_ip_cidr），
            # IPv6 客户端与客户端名/标签无法映射，整行丢弃（fail-closed）
            if not value:
                return None
            for c in value.split("|"):
                cidr = _parse_ip_cidr(c.strip())
                if cidr is None:
                    return None
                p.source_ip_cidrs.append(cidr)
        else:
            return None  # app/network/ctag/denyallow/to/... 官方也未支持
    return p


def parse_line(raw: str) -> Optional[Parsed]:
    """解析一行 AdGuard 规则。None = 注释/空行；ignored_reason 非空 = 丢弃。"""
    line = raw.strip()
    if not line or line.startswith(("!", "#", "[")):
        return None

    # 0) IP / IP-CIDR（先于纯域名检查：1.1.1.1 同时匹配域名正则，但 AdGuard 语义是 IP）
    ip = _parse_ip_cidr(line)
    if ip is not None:
        return Parsed(core=ip, is_ip=True)

    # 1) 纯域名
    if _is_domain_name(line):
        return Parsed(core=line)

    # 2) hosts 行
    hosts = _parse_hosts(line)
    if hosts is not None:
        return hosts

    # 3) 通用语法
    rule = line
    p = Parsed(core="")

    # 正则行带修饰符：/re/$important（正则体内部的 $ 是锚点，不参与）
    if rule.startswith("/"):
        m = re.fullmatch(r"(/.*/)(\$.*)?", rule)
        if m and m.group(2):
            mods = _parse_modifiers(m.group(2)[1:])
            if mods is None:
                return Parsed(core="", ignored_reason=f"不支持的修饰符: {line}")
            p.is_important = mods.is_important
            p.query_types = mods.query_types
            p.source_ip_cidrs = mods.source_ip_cidrs
            rule = m.group(1)
    elif "$" in rule:
        mods = _parse_modifiers(rule.split("$", 1)[1])
        if mods is None:
            return Parsed(core="", ignored_reason=f"不支持的修饰符: {line}")
        p.is_important = mods.is_important
        p.query_types = mods.query_types
        p.source_ip_cidrs = mods.source_ip_cidrs
        rule = rule.split("$", 1)[0]

    if rule.startswith("@@"):
        p.is_exclude = True
        rule = rule[2:]
    if rule.startswith("||"):
        p.is_suffix = True
        rule = rule[2:]
    elif rule.startswith("|"):
        p.is_exact = True
        rule = rule[1:]

    if rule.endswith("^"):
        rule = rule[:-1]
        # 无 || 前缀的 "x^" 是 AdGuard 子串匹配：官方测试 example.net^ 匹配
        # isexample.net（域名任意位置以完整标签边界包含 x），与 domain_suffix
        # 的"自身或其子域"不同，需转 domain_regex。
        if not p.is_suffix and not p.is_exact:
            p.is_substring = True
    elif p.is_suffix and not p.is_exact:
        # ||x（无 ^）：AdGuard 语义是 x 之后不限（官方测试 ||example.edu 匹配
        # example.edu.cn），domain_suffix 表达不了（example.edu.cn 不是 example.edu
        # 的子域），转 domain_regex。
        p.suffix_loose = True

    # 正则
    if rule.startswith("/") and rule.endswith("/"):
        body = rule[1:-1]
        if len(body) > MAX_REGEX_LEN:
            return Parsed(core="", ignored_reason=f"正则超长丢弃（>{MAX_REGEX_LEN} 字符）: {line}")
        p.is_regexp = True
        p.core = body
        return p

    # 非正则：scheme 截断、路径/query/cosmetic 等丢弃
    if "://" in rule:
        p.is_suffix = True
        rule = rule.split("://", 1)[1]
    if "/" in rule:
        return Parsed(core="", ignored_reason=f"路径规则丢弃: {line}")
    if any(c in rule for c in "?&"):
        return Parsed(core="", ignored_reason=f"query 规则丢弃: {line}")
    if any(c in rule for c in "[]()!#"):
        return Parsed(core="", ignored_reason=f"cosmetic/非法字符丢弃: {line}")
    if "~" in rule:
        return Parsed(core="", ignored_reason=f"~ 排除修饰符丢弃: {line}")

    # 注：不带锚点的纯 IP 行已在函数开头（步骤 0）处理为 ip_cidr；
    # 带锚点的 ||1.2.3.4^ 按官方语义是域名规则（IsDomainName 接受 IP 串），走下方域名分支。

    # 无锚点且带修饰符的纯 IP（如 1.1.1.1$dnstype=A）：修饰符已剥离，rule 是裸 IP → ip_cidr
    if not p.is_suffix and not p.is_exact and not p.is_substring and not p.is_exclude:
        ip2 = _parse_ip_cidr(rule)
        if ip2 is not None:
            p.is_ip = True
            p.core = ip2
            return p

    # 端口：example.com:8080（1–65535，越界丢弃）
    if ":" in rule:
        domain_part, _, port_part = rule.rpartition(":")
        if (_is_domain_name(domain_part) and re.fullmatch(r"\d+", port_part)
                and 1 <= int(port_part) <= 65535):
            p.core = domain_part
            p.ports = [int(port_part)]
            return p

    # 域名合法性（允许 * 通配符与 ./- 开头）
    if not rule:
        return Parsed(core="", ignored_reason="空域名丢弃")
    check = rule.replace("*", "x")
    check = "r" + check if check.startswith((".", "-")) else check
    if not _is_domain_name(check):
        return Parsed(core="", ignored_reason=f"非法域名丢弃: {line}")

    p.core = rule
    return p


# ---------------------------------------------------------------- 分组/生成

def _regex_escape_domain(d: str) -> str:
    """AdGuard 通配符域名转正则：* → .*（任意字符序列），其余转义。"""
    return "".join(".*" if c == WILDCARD else re.escape(c) for c in d)


def _to_regex(parsed: Parsed) -> str:
    """把不能进 domain/domain_suffix 的规则转成正则。"""
    core = parsed.core
    if parsed.is_regexp:
        return core
    if parsed.is_substring:
        # x^ → 域名以 x 结尾（子串语义，官方测试 isexample.net 也匹配）
        return rf"{_regex_escape_domain(core)}$"
    if parsed.suffix_loose:
        # ||x（无 ^）→ 域名以 x 开头/为 x 的子域，x 后不限（官方测试 example.edu.cn 匹配）
        return rf"(^|\.){_regex_escape_domain(core)}(\.|$)"
    if parsed.is_suffix and core.startswith("*."):
        # ||*.x^ 仅子域：x 的子域（不含 x 本身）
        return rf"^.+\.{_regex_escape_domain(core[2:])}$"
    if WILDCARD in core:
        # 通配符：* → .*（AdGuard 语义：任意字符序列）
        body = _regex_escape_domain(core)
        if parsed.is_suffix:
            # ||ad*.x^ → (^|\.)ad.*\.x$（匹配 x 的任意子域，含 ad 开头的层级）
            return rf"(^|\.){body}$"
        return rf"^{body}$"


def _rule_kind(p: Parsed) -> str:
    if p.is_ip:
        return "ip_cidr"
    if p.is_regexp or p.is_substring or p.suffix_loose or WILDCARD in p.core or (p.is_suffix and p.core.startswith("*.")):
        return "domain_regex"
    if p.is_exact or not p.is_suffix:
        return "domain"
    return "domain_suffix"


def _dedupe_subdomains(domains: set[str]) -> set[str]:
    """删除被同列表内父域后缀覆盖的子域（语义等价，仅精简体积）。

    例：ads.com 覆盖 sub.ads.com → 删除 sub.ads.com。
    仅适用于 domain_suffix（后缀匹配才有覆盖关系）；O(n×标签数)。
    """
    domain_set = set(domains)
    kept = set()
    for d in domains:
        parts = d.split(".")
        covered = any(".".join(parts[i:]) in domain_set for i in range(1, len(parts)))
        if not covered:
            kept.add(d)
    return kept


def _mod_key(p: Parsed):
    qt = tuple(sorted(p.query_types))
    ports = tuple(sorted(p.ports))
    src = tuple(sorted(p.source_ip_cidrs))
    if qt or ports or src:
        return (qt, ports, src)
    return None


def build_rules(parsed_list: list[Parsed]) -> list[dict]:
    """按官方分组逻辑（important/exclude 分层 + 类别/修饰符分桶）生成无头规则 JSON。"""
    groups: dict[tuple, dict] = {}
    for p in parsed_list:
        gkey = (p.is_important, p.is_exclude, _rule_kind(p), _mod_key(p))
        g = groups.setdefault(gkey, {"kind": None, "values": []})
        g["kind"] = _rule_kind(p)
        g["values"].append(p)

    def make_rule(g: dict) -> dict:
        kind, values = g["kind"], g["values"]
        if kind == "domain_regex":
            r = {"domain_regex": sorted({_to_regex(v) for v in values})}
        elif kind == "ip_cidr":
            r = {"ip_cidr": sorted({v.core for v in values})}
        else:
            field_name = "domain" if kind == "domain" else "domain_suffix"
            values_set = {v.core for v in values}
            if field_name == "domain_suffix":
                values_set = _dedupe_subdomains(values_set)
            r = {field_name: sorted(values_set)}
        p = values[0]
        if p.query_types:
            r["query_type"] = sorted(p.query_types)
        if p.ports:
            r["port"] = sorted(p.ports)
        if p.source_ip_cidrs:
            r["source_ip_cidr"] = sorted(p.source_ip_cidrs)
        return r

    def merged(gs: list[dict]) -> list[dict]:
        """按 mod_key 合并；不同修饰符桶必须拆成多条（同条 default rule 内多字段是 AND）。"""
        by_key: dict = {}
        for g in gs:
            key = _mod_key(g["values"][0])
            for field_name, values in make_rule(g).items():
                by_key.setdefault(key, {}).setdefault(field_name, []).extend(values)
        return [{k: sorted(set(v)) for k, v in d.items()} for d in by_key.values()]

    def wrap_or(gs: list[dict]) -> dict:
        """多条规则包 logical or（rules 间是 OR）。"""
        rules = merged(gs)
        if len(rules) == 1:
            return rules[0]
        return {"type": "logical", "mode": "or", "rules": rules}

    plain, excl, imp, imp_excl = [], [], [], []
    for gkey, g in groups.items():
        is_imp, is_exc = gkey[0], gkey[1]
        (imp_excl if is_imp and is_exc else
         imp if is_imp else
         excl if is_exc else plain).append(g)

    never = {"domain": ["__singbox_never_match__"]}  # 空主规则占位（default 规则需非零字段）
    current: Optional[dict] = wrap_or(plain) if plain else None
    if excl:
        current = {"type": "logical", "mode": "and",
                   "rules": [{"invert": True, **wrap_or(excl)}, current or never]}
    if imp:
        current = {"type": "logical", "mode": "or",
                   "rules": [wrap_or(imp), current or never]}
    if imp_excl:
        current = {"type": "logical", "mode": "and",
                   "rules": [{"invert": True, **wrap_or(imp_excl)}, current or never]}
    return [current] if current else []


def convert(text: str, *, source: str = "auto") -> dict:
    """解析并转换 AdGuard/hosts 文本为无头规则 JSON。

    source: adguard | hosts | auto。
    auto（默认）：逐行识别语法类别（hosts 行 → hosts，其余 → adguard）；
    显式指定时整文件归属该类别（用于产物分桶）。
    """
    if source not in ("adguard", "hosts", "auto"):
        raise ValueError(f"未知 source: {source}")
    parsed: list[Parsed] = []
    ignored: list[str] = []
    for raw in text.splitlines():
        p = parse_line(raw)
        if p is None:
            continue
        if p.ignored_reason:
            ignored.append(p.ignored_reason)
            continue
        if source != "auto":
            p.source = source
        parsed.append(p)
    rules = build_rules(parsed)
    return {"version": 3, "rules": rules, "_ignored": ignored}


def convert_multi(adguard_texts: list[str], hosts_texts: list[str]) -> dict:
    """三种产物：adguard / hosts / combined（合并，rules 数组间 OR）。

    注：combined 为两份独立编译产物的 OR 拼接，@@ 排除规则按各自文件内
    AND 分桶，跨文件的排除/important 互不联动——对广告拦截场景无影响。
    """
    adguard_rules: list[dict] = []
    hosts_rules: list[dict] = []
    ignored: list[str] = []
    for text in adguard_texts:
        r = convert(text, source="adguard")
        adguard_rules.extend(r["rules"])
        ignored.extend(r["_ignored"])
    for text in hosts_texts:
        r = convert(text, source="hosts")
        hosts_rules.extend(r["rules"])
        ignored.extend(r["_ignored"])
    products: dict = {}
    if adguard_rules:
        products["adguard"] = {"version": 3, "rules": adguard_rules}
    if hosts_rules:
        products["hosts"] = {"version": 3, "rules": hosts_rules}
    combined = adguard_rules + hosts_rules
    if combined:
        products["combined"] = {"version": 3, "rules": combined}
    return {"products": products, "_ignored": ignored}


def _merge_dedupe_texts(texts: list[str]) -> str:
    """原始行逐行去重（保留首次出现的行），用于生成合并后的原始规则文件。"""
    seen: set[str] = set()
    out: list[str] = []
    for text in texts:
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped in seen:
                continue
            seen.add(stripped)
            out.append(stripped)
    return "\n".join(out) + ("\n" if out else "")


def convert_all(adguard_sources: list[tuple[str, str]],
                hosts_sources: list[tuple[str, str]]) -> dict:
    """完整产物：每个源单独转换 + 合并去重（原始行去重）。

    adguard_sources / hosts_sources: [(name, text), ...]
    返回:
      per_source: {"adguard": {name: rules}, "hosts": {name: rules}}
      merged:     {"adguard"|"hosts"|"combined": {"text": 合并去重原始行, "rules": ...}}
    """
    per_source: dict = {"adguard": {}, "hosts": {}}
    ignored: list[str] = []
    for name, text in adguard_sources:
        r = convert(text, source="adguard")
        per_source["adguard"][name] = r["rules"]
        ignored.extend(r["_ignored"])
    for name, text in hosts_sources:
        r = convert(text, source="hosts")
        per_source["hosts"][name] = r["rules"]
        ignored.extend(r["_ignored"])

    merged: dict = {}
    if adguard_sources:
        text = _merge_dedupe_texts([t for _, t in adguard_sources])
        rules = convert(text, source="adguard")["rules"]
        if rules:  # 无有效规则则不生成空产物
            merged["adguard"] = {"text": text, "rules": rules}
    if hosts_sources:
        text = _merge_dedupe_texts([t for _, t in hosts_sources])
        rules = convert(text, source="hosts")["rules"]
        if rules:
            merged["hosts"] = {"text": text, "rules": rules}
    if merged:
        combined_text = _merge_dedupe_texts([m["text"] for m in merged.values()])
        combined_rules: list[dict] = []
        for m in merged.values():
            combined_rules.extend(m["rules"])
        merged["combined"] = {"text": combined_text, "rules": combined_rules}
    return {"per_source": per_source, "merged": merged, "_ignored": ignored}


def build_rule_set_refs(base_url: str, product_paths: dict[str, str]) -> dict[str, dict]:
    """生成 sing-box route.rule_set 引用条目。

    product_paths: 产物名 → 相对产物路径（如 "merged/combined/combined.srs"），
    url = <base_url>/<相对路径>。
    """
    base = base_url.rstrip("/")
    return {
        name: {
            "tag": name,
            "type": "remote",
            "format": "binary",
            "url": f"{base}/{relpath}",
            "download_detour": "direct",
        }
        for name, relpath in product_paths.items()
    }


def write_output_tree(out_dir: Path, result: dict,
                      adguard_sources: list[tuple[str, str]],
                      hosts_sources: list[tuple[str, str]],
                      base_url: Optional[str]) -> None:
    """写入完整产物目录树：

    sources/    上游原始文件（按语法分类）
    converted/  每个源的转换产物 json（srs 由 CI 的 sing-box compile 补）
    merged/     合并去重产物（原始文件 + json）
    rule-sets/  sing-box 引用条目（每个源 + 每个合并产物）
    """
    out = out_dir
    out.mkdir(parents=True, exist_ok=True)
    # ① sources/：上游原始文件（按语法分类）
    for kind, srcs in (("adguard", adguard_sources), ("hosts", hosts_sources)):
        for name, text in srcs:
            p = out / "sources" / kind / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            print(f"written: {p}", file=sys.stderr)
    # ② converted/：每个源的转换产物（json；srs 由 CI 的 sing-box compile 补）
    for kind in ("adguard", "hosts"):
        for name, rules in result["per_source"][kind].items():
            p = out / "converted" / kind / f"{Path(name).stem}.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"version": 3, "rules": rules},
                                    indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"written: {p}", file=sys.stderr)
    # ③ merged/：合并去重产物（原始文件 + json；srs 由 CI 补）
    for name, m in result["merged"].items():
        d = out / "merged" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{name}.txt").write_text(m["text"], encoding="utf-8")
        (d / f"{name}.json").write_text(
            json.dumps({"version": 3, "rules": m["rules"]}, indent=2, ensure_ascii=False),
            encoding="utf-8")
        print(f"written: {d / f'{name}.txt'} / {d / f'{name}.json'}", file=sys.stderr)
    # ④ rule-sets/：引用条目（每个源 + 每个合并产物，url 指向真实产物相对路径）
    if base_url:
        # 单源产物：converted/{kind}/{stem}.srs；合并产物：merged/{name}/{name}.srs
        product_paths: dict[str, str] = {}
        for kind in ("adguard", "hosts"):
            for name in result["per_source"][kind]:
                product_paths[Path(name).stem] = f"converted/{kind}/{Path(name).stem}.srs"
        for name in result["merged"]:
            product_paths[name] = f"merged/{name}/{name}.srs"
        refs = build_rule_set_refs(base_url, product_paths)
        for name, ref in refs.items():
            p = out / "rule-sets" / f"{name}.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(ref, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"written: {p}", file=sys.stderr)
    else:
        print("# 未生成 rule-sets/（需要 --base-url）", file=sys.stderr)


def _check_name_conflicts(adguard_sources: list[tuple[str, str]],
                          hosts_sources: list[tuple[str, str]]) -> list[str]:
    """同类输入内 stem 重复 → converted/ 产物互相覆盖，需报错。"""
    errors: list[str] = []
    for kind, srcs in (("adguard", adguard_sources), ("hosts", hosts_sources)):
        stems = [Path(n).stem for n, _ in srcs]
        dupes = sorted({s for s in stems if stems.count(s) > 1})
        if dupes:
            errors.append(f"{kind}: {dupes}")
    return errors


def _warn_reserved_names(adguard_sources: list[tuple[str, str]],
                         hosts_sources: list[tuple[str, str]]) -> list[str]:
    """输入 stem 与保留产物名（adguard/hosts/combined）冲突：仅影响 rule-sets 引用合并。"""
    reserved = {"adguard", "hosts", "combined"}
    all_stems = [Path(n).stem for n, _ in adguard_sources + hosts_sources]
    return sorted(s for s in set(all_stems) if s in reserved)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--adguard", type=Path, action="append", default=[], metavar="FILE",
                    help="AdGuard 规则文件（可重复指定多个）")
    ap.add_argument("--hosts", type=Path, action="append", default=[], metavar="FILE",
                    help="hosts 文件（可重复指定多个）")
    ap.add_argument("--base-url", type=str, default=None,
                    help="产物 .srs 的 URL 前缀（如 raw.githubusercontent.com/.../Filters），"
                         "用于生成 rule-sets/ 引用条目")
    ap.add_argument("-o", "--output-dir", type=Path, default=None,
                    help="输出目录：sources/ 原始文件、converted/ 单源转换、"
                         "merged/ 合并去重、rule-sets/ sing-box 引用条目")
    args = ap.parse_args()
    if not args.adguard and not args.hosts:
        ap.error("至少需要一个 --adguard 或 --hosts 输入文件")
    adguard_sources = [(p.name, p.read_text(encoding="utf-8-sig")) for p in args.adguard]
    hosts_sources = [(p.name, p.read_text(encoding="utf-8-sig")) for p in args.hosts]
    errors = _check_name_conflicts(adguard_sources, hosts_sources)
    if errors:
        ap.error(f"同类输入文件重名（converted/ 产物会互相覆盖）: {errors}（请改名）")
    for reserved in _warn_reserved_names(adguard_sources, hosts_sources):
        print(f"# 警告: 输入 '{reserved}' 与保留产物名冲突，rule-sets/ 引用会合并", file=sys.stderr)
    result = convert_all(adguard_sources, hosts_sources)
    for reason in result["_ignored"]:
        print(f"# 丢弃: {reason}", file=sys.stderr)
    if args.output_dir:
        write_output_tree(args.output_dir, result, adguard_sources, hosts_sources, args.base_url)
    else:
        prod = next(iter(result["merged"].values()), None)
        if prod is None:
            print("# 无有效规则可输出（全部输入行均被忽略）", file=sys.stderr)
            return
        print(json.dumps({"version": 3, "rules": prod["rules"]}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
