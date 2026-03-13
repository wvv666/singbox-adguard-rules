import json, urllib.request, re, os, time, concurrent.futures, ipaddress
from publicsuffixlist import PublicSuffixList

# --- 初始化 ---
psl = PublicSuffixList()
hosts_pattern = re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::1)\s+([a-zA-Z0-9.-]+)$')
strict_domain_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^?$')
pure_domain_pattern = re.compile(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+$')
dnsmasq_pattern = re.compile(r'^(?:server|address)=/([a-zA-Z0-9.-]+)/')

class DomainTrie:
    def __init__(self): self.root = {}
    def insert_and_check(self, domain):
        parts = domain.split('.')[::-1]
        node = self.root
        for part in parts:
            if "__end__" in node: return False
            node = node.setdefault(part, {})
        node["__end__"] = True
        return True

def download_with_retry(url, source_name, retries=3):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode('utf-8', errors='ignore')
        except: time.sleep(3)
    print(f"❌ 源失效: {source_name}")
    return None

def parse_rule(line, is_whitelist=False):
    line = line.strip()
    if not line or line.startswith(('!', '#')): return None, None
    domain = None
    if is_whitelist:
        m = dnsmasq_pattern.match(line)
        if m: domain = m.group(1)
        elif line.startswith('@@||') and line.endswith('^'): domain = line[4:-1]
    if not domain:
        for p in [hosts_pattern, strict_domain_pattern, pure_domain_pattern]:
            m = p.match(line)
            if m: domain = m.group(1); break
    if domain:
        domain = domain.lower()
        try: ipaddress.ip_address(domain); return None, None
        except: pass
        if domain in ('localhost', 'local') or psl.publicsuffix(domain) == domain: return None, None
        return 'domain', domain
    return 'raw', line

def fetch_worker(source, is_whitelist=False):
    if not source.get('enabled'): return None
    content = download_with_retry(source['url'], source['name'])
    if not content: return None
    domains, raws = set(), set()
    for line in content.splitlines():
        rtype, val = parse_rule(line, is_whitelist)
        if rtype == 'domain': domains.add(val)
        elif rtype == 'raw': raws.add(val)
    return {"domains": domains, "raws": raws, "source": source}

def main():
    with open('upstream.json', 'r') as f: config = json.load(f)
    
    # 权重仲裁表: {domain: {"type": "allow/block", "priority": int}}
    routing = {}
    tier_raws = {'lite': set(), 'full': set(), 'extreme': set()}
    stats = {"ad": 0, "tracking": 0, "malicious": 0, "allow": 0, "failed": 0}

    all_sources = [(s, False) for s in config['upstream_rules']] + [(s, True) for s in config['whitelist']]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch_worker, s, is_w) for s, is_w in all_sources]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if not res: stats["failed"] += 1; continue
            
            src, d_set, r_set = res['source'], res['domains'], res['raws']
            prio = src.get('priority', 0)
            stype = src['type']
            
            for d in d_set:
                if d not in routing or prio > routing[d]['priority']:
                    routing[d] = {"type": "allow" if stype == "allow" else "block", "priority": prio, "tier": src.get('tier', 'global')}
            
            if stype != "allow":
                target_tiers = {'lite': ['lite', 'full', 'extreme'], 'full': ['full', 'extreme'], 'extreme': ['extreme']}
                for t in target_tiers.get(src['tier'], []): tier_raws[t].update(r_set)
            
            stats[stype] += len(d_set) + len(r_set)

    # 分级合流与 Trie 压缩
    os.makedirs('rules', exist_ok=True)
    final_stats = {"failed_sources": stats["failed"], "conflicts_resolved": 0, "allow": stats["allow"]}
    
    for t in ['lite', 'full', 'extreme']:
        tier_domains = [d for d, v in routing.items() if v['type'] == 'block' and v['tier'] in (['lite', 'full', 'extreme'] if t == 'extreme' else (['lite', 'full'] if t == 'full' else ['lite']))]
        
        trie = DomainTrie()
        compressed = sorted([d for d in sorted(tier_domains, key=lambda x: x.count('.')) if trie.insert_and_check(d)])
        
        with open(f'rules/{t}.txt', 'w') as f:
            for d in compressed: f.write(f"||{d}^\n")
            for r in sorted(tier_raws[t]): f.write(f"{r}\n")
            for d, v in routing.items(): 
                if v['type'] == 'allow': f.write(f"@@||{d}^\n")
        
        final_stats[f"{t}_total"] = len(compressed) + len(tier_raws[t]) + stats["allow"]

    with open('rules/stats.json', 'w') as f: json.dump(final_stats, f)
    print("✅ 构建完成")

if __name__ == '__main__': main()
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
