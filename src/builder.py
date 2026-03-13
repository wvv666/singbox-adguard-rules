import json
import urllib.request
import re
import os
import time
import concurrent.futures
import ipaddress  # 新增：原生 IP 地址解析库，绝杀一切伪装成域名的 IP
from publicsuffixlist import PublicSuffixList

# --- 正则与 PSL 初始化 ---
psl = PublicSuffixList()
hosts_pattern = re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::1)\s+([a-zA-Z0-9.-]+)$')
strict_domain_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^?$')
pure_domain_pattern = re.compile(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+$')
ip_rule_pattern = re.compile(r'^\|\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\^?$')
dnsmasq_pattern = re.compile(r'^(?:server|address)=/([a-zA-Z0-9.-]+)/')

class TrieNode:
    """Trie 树节点"""
    def __init__(self):
        self.children = {}
        self.is_end = False

class DomainTrie:
    """基于后缀的字典树 (用于极致域名压缩)"""
    def __init__(self):
        self.root = TrieNode()

    def insert_and_check(self, domain):
        """倒序插入域名，命中父节点则返回 False，全新型返回 True"""
        parts = domain.split('.')[::-1]
        node = self.root
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
            if node.is_end:
                return False 
        node.is_end = True
        return True

def download_with_retry(url, source_name, retries=3, delay=3):
    """带重试机制的下载函数，支持失效检测"""
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            if attempt < retries - 1: time.sleep(delay)
    print(f"❌ [网络异常] 源已失效: {source_name} ({url})")
    return None

def parse_rule(line, is_whitelist=False):
    """双轨制解析器：分离纯域名规则与复杂高级规则"""
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#'): return None, None
    if not is_whitelist:
        if line.startswith('@@') or '##' in line or '#?#' in line or '$$' in line: return None, None
    if line in ('||^', '||', '^'): return None, None
    if ip_rule_pattern.match(line): return None, None
    
    domain = None
    if is_whitelist:
        m = dnsmasq_pattern.match(line)
        if m: domain = m.group(1)
        elif line.startswith('@@||') and line.endswith('^'): domain = line[4:-1]

    if not domain:
        m = hosts_pattern.match(line)
        if m: domain = m.group(1)
        
    if not domain:
        m = strict_domain_pattern.match(line)
        if m: domain = m.group(1)
        
    if not domain:
        if pure_domain_pattern.match(line): domain = line

    if domain:
        # 1. 统一转换为小写 (DNS 大小写不敏感)
        domain = domain.lower()
        
        # 2. 忽略保留字
        if domain in ('localhost', 'broadcasthost', 'local'): return None, None
        
        # 3. 极客修复：IP 地址过滤 (防止 Hosts 中出现 0.0.0.0 1.2.3.4 被当成域名)
        try:
            ipaddress.ip_address(domain)
            return None, None # 如果能成功解析为 IP，说明不是域名，直接抛弃！
        except ValueError:
            pass # 不是 IP，继续执行域名逻辑
            
        # 4. PSL 域名边界防护
        if psl.is_public_suffix(domain): 
            return None, None
            
        return 'domain', domain
        
    return 'raw', line

def fetch_and_parse(source, is_whitelist=False):
    """多线程 Worker 函数"""
    if not source.get('enabled', True): return source, None, set(), set()
    content = download_with_retry(source['url'], source['name'])
    if not content: return source, False, set(), set()
        
    domains = set()
    raw_rules = set()
    for line in content.splitlines():
        rtype, value = parse_rule(line, is_whitelist)
        if rtype == 'domain': domains.add(value)
        elif rtype == 'raw': raw_rules.add(value)
            
    return source, True, domains, raw_rules

def main():
    print("🚀 终极构建引擎启动 (IP级过滤 + 域名标准化 + Trie压缩 + PSL防护)...")
    
    with open('upstream.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    ruleset = {
        'lite': {'domains': set(), 'raw': set()},
        'full': {'domains': set(), 'raw': set()},
        'extreme': {'domains': set(), 'raw': set()}
    }
    stats = {"ad": 0, "tracking": 0, "malicious": 0, "allow": 0}
    failed_sources = []

    # 1. 并发拉取黑名单上游
    print("⬇️ 正在并发拉取黑名单上游...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch_and_parse, src, False) for src in config.get('upstream_rules', [])]
        for future in concurrent.futures.as_completed(futures):
            source, success, domains, raw_rules = future.result()
            if not source.get('enabled', True): continue
            if not success:
                failed_sources.append(source['name'])
                continue
            
            # 分级合流
            tier_routing = {
                'lite': ['lite', 'full', 'extreme'],
                'full': ['full', 'extreme'],
                'extreme': ['extreme']
            }
            for t in tier_routing.get(source.get('tier', 'extreme'), []):
                ruleset[t]['domains'].update(domains)
                ruleset[t]['raw'].update(raw_rules)
                
            stats[source['type']] = stats.get(source['type'], 0) + len(domains) + len(raw_rules)
            print(f"    ✅ [{source['tier'].upper()}] {source['name']} 解析成功: {len(domains) + len(raw_rules)} 条")

    # 2. 拉取白名单
    print("🛡️ 正在拉取白名单...")
    allow_domains = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(fetch_and_parse, src, True) for src in config.get('whitelist', [])]
        for future in concurrent.futures.as_completed(futures):
            source, success, domains, raw_rules = future.result()
            if success: allow_domains.update(domains)

    # 3. 冲突剔除
    print("⚔️ 正在执行规则冲突化解...")
    conflict_count = len(ruleset['extreme']['domains'].intersection(allow_domains))
    for tier in ruleset:
        ruleset[tier]['domains'] -= allow_domains

    # 4. 极客级优化：Trie 树极致域名压缩
    print("🌲 开始执行 Trie 树冗余压缩算法...")
    for tier in ruleset:
        original_len = len(ruleset[tier]['domains'])
        trie = DomainTrie()
        compressed_domains = set()
        
        # 确保按点号数量(层级)优先，再按长度排序
        sorted_domains = sorted(
            list(ruleset[tier]['domains']), 
            key=lambda d: (d.count('.'), len(d))
        )
        
        for domain in sorted_domains:
            if trie.insert_and_check(domain):
                compressed_domains.add(domain)
                
        ruleset[tier]['domains'] = compressed_domains
        print(f"    [{tier.upper()}] Trie 压缩成果: 剔除 {original_len - len(compressed_domains)} 条冗余子域。")

    # 5. 组装输出
    os.makedirs('rules', exist_ok=True)
    for tier, data in ruleset.items():
        with open(f'rules/{tier}.txt', 'w', encoding='utf-8') as f:
            for domain in sorted(data['domains']): f.write(f"||{domain}^\n")
            for raw in sorted(data['raw']): f.write(f"{raw}\n")
            for w_domain in sorted(allow_domains): f.write(f"@@||{w_domain}^\n")
                
    # 6. 保存统计数据
    final_stats = {
        "lite_total": len(ruleset['lite']['domains']) + len(ruleset['lite']['raw']),
        "full_total": len(ruleset['full']['domains']) + len(ruleset['full']['raw']),
        "extreme_total": len(ruleset['extreme']['domains']) + len(ruleset['extreme']['raw']),
        "conflicts_resolved": conflict_count,
        "failed_sources": len(failed_sources)
    }
    with open('rules/stats.json', 'w', encoding='utf-8') as f:
        json.dump(final_stats, f)
        
    print("✅ 引擎运行完毕！你的代码已化身为一头毫无弱点的性能怪兽。")

if __name__ == '__main__':
    main()
    # 5. 保存统计数据供 README 生成器使用
    final_stats = {
        "lite_total": len(ruleset['lite']),
        "full_total": len(ruleset['full']),
        "extreme_total": len(ruleset['extreme']),
        "types": stats,
        "conflicts_resolved": conflict_count
    }
    with open('rules/stats.json', 'w', encoding='utf-8') as f:
        json.dump(final_stats, f)
        
    print(f"✅ 构建完成！解决冲突: {conflict_count} 条。数据已输出至 rules/ 目录。")

if __name__ == '__main__':
    main()
