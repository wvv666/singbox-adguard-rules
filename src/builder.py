import json, urllib.request, re, os, time, concurrent.futures, ipaddress, sys
from publicsuffixlist import PublicSuffixList

# --- 初始化 ---
psl = PublicSuffixList()
hosts_pattern = re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::1)\s+([a-zA-Z0-9.-]+)$')
strict_domain_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^?$')
pure_domain_pattern = re.compile(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+$')
dnsmasq_pattern = re.compile(r'^(?:server|address)=/([a-zA-Z0-9.-]+)/')

class DomainTrie:
    def __init__(self): 
        self.root = {}
    
    def insert_and_check(self, domain):
        parts = domain.split('.')[::-1]
        node = self.root
        for part in parts:
            if "__end__" in node: 
                return False
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
        except Exception as e:
            print(f"⚠️ 下载失败 {source_name} (尝试 {i+1}/{retries}): {e}")
            time.sleep(3)
    print(f"❌ 下载失败: {source_name}")
    return None

def parse_rule(line, is_whitelist=False):
    line = line.strip()
    if not line or line.startswith(('!', '#')): 
        return None, None
    
    domain = None
    if is_whitelist:
        m = dnsmasq_pattern.match(line)
        if m: 
            domain = m.group(1)
        elif line.startswith('@@||') and line.endswith('^'): 
            domain = line[4:-1]
    
    if not domain:
        for p in [hosts_pattern, strict_domain_pattern, pure_domain_pattern]:
            m = p.match(line)
            if m: 
                domain = m.group(1)
                break
    
    if domain:
        domain = domain.lower()
        try: 
            ipaddress.ip_address(domain)
            return None, None
        except: 
            pass
        
        if domain in ('localhost', 'local'): 
            return None, None
        
        # === 修复关键：使用正确的公共后缀检查方法 ===
        # 错误方法：psl.is_public_suffix(domain) - 不存在！
        # 正确方法：使用 psl.publicsuffix(domain) == domain 判断
        try:
            # 方法1: 检查域名是否本身就是公共后缀
            # publicsuffix() 返回域名的公共后缀部分
            public_suffix = psl.publicsuffix(domain)
            # 如果整个域名就是公共后缀（如 "com", "co.uk"），则跳过
            if public_suffix == domain:
                return None, None
        except Exception as e:
            # 如果检查失败，记录但继续处理
            print(f"⚠️ 公共后缀检查失败 {domain}: {e}")
            # 可以选择跳过或继续处理
        
        return 'domain', domain
    
    return 'raw', line

def fetch_worker(source, is_whitelist=False):
    if not source.get('enabled'): 
        return None
    content = download_with_retry(source['url'], source['name'])
    if not content: 
        return None
    domains, raws = set(), set()
    for line in content.splitlines():
        rtype, val = parse_rule(line, is_whitelist)
        if rtype == 'domain': 
            domains.add(val)
        elif rtype == 'raw': 
            raws.add(val)
    return {"domains": domains, "raws": raws, "source": source}

def main():
    try:
        with open('upstream.json', 'r') as f: 
            config = json.load(f)
    except FileNotFoundError:
        print("❌ 错误：未找到 upstream.json 配置文件")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ 错误：upstream.json 格式无效：{e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 错误：读取配置文件失败：{e}")
        sys.exit(1)
    
    routing = {}
    tier_raws = {'lite': set(), 'full': set(), 'extreme': set()}
    stats = {"ad": 0, "tracking": 0, "malicious": 0, "allow": 0, "failed": 0}

    all_sources = [(s, False) for s in config.get('upstream_rules', [])] + \
                  [(s, True) for s in config.get('whitelist', [])]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch_worker, s, is_w) for s, is_w in all_sources]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if not res: 
                stats["failed"] += 1
                continue
            src, d_set, r_set = res['source'], res['domains'], res['raws']
            prio, stype = src.get('priority', 0), src.get('type', 'ad')
            
            stats_key = stype if stype in stats else "ad"
            stats[stats_key] += len(d_set) + len(r_set)
            
            for d in d_set:
                if d not in routing or prio > routing[d]['priority']:
                    routing[d] = {
                        "type": "allow" if stype == "allow" else "block", 
                        "priority": prio, 
                        "tier": src.get('tier', 'global')
                    }
            
            if stype != "allow":
                target_tiers = {
                    'lite': ['lite', 'full', 'extreme'], 
                    'full': ['full', 'extreme'], 
                    'extreme': ['extreme']
                }
                for t in target_tiers.get(src.get('tier', 'lite'), ['lite']): 
                    tier_raws[t].update(r_set)

    os.makedirs('rules', exist_ok=True)
    
    for t in ['lite', 'full', 'extreme']:
        allowed_tiers = ['lite']
        if t == 'full': 
            allowed_tiers = ['lite', 'full']
        if t == 'extreme': 
            allowed_tiers = ['lite', 'full', 'extreme']
        
        tier_domains = [d for d, v in routing.items() if v['type'] == 'block' and v['tier'] in allowed_tiers]
        trie = DomainTrie()
        compressed = sorted([d for d in sorted(tier_domains, key=lambda x: x.count('.')) if trie.insert_and_check(d)])
        
        with open(f'rules/{t}.txt', 'w', encoding='utf-8') as f:
            for d in compressed: 
                f.write(f"||{d}^\n")
            for r in sorted(tier_raws[t]): 
                f.write(f"{r}\n")
            for d, v in routing.items(): 
                if v['type'] == 'allow': 
                    f.write(f"@@||{d}^\n")
        
        stats[f"{t}_total"] = len(compressed) + len(tier_raws[t]) + sum(1 for v in routing.values() if v['type'] == 'allow')

    with open('rules/stats.json', 'w', encoding='utf-8') as f: 
        json.dump(stats, f, indent=2)
    
    print("✅ 构建完成")
    print(f"📊 统计: {stats}")

if __name__ == '__main__': 
    main()    routing = {}
    tier_raws = {'lite': set(), 'full': set(), 'extreme': set()}
    stats = {"ad": 0, "tracking": 0, "malicious": 0, "allow": 0, "failed": 0}

    all_sources = [(s, False) for s in config.get('upstream_rules', [])] + \
                  [(s, True) for s in config.get('whitelist', [])]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch_worker, s, is_w) for s, is_w in all_sources]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if not res: 
                stats["failed"] += 1
                continue
            src, d_set, r_set = res['source'], res['domains'], res['raws']
            prio, stype = src.get('priority', 0), src.get('type', 'ad')
            
            # 安全的统计更新
            stats_key = stype if stype in stats else "ad"
            stats[stats_key] += len(d_set) + len(r_set)
            
            for d in d_set:
                if d not in routing or prio > routing[d]['priority']:
                    routing[d] = {
                        "type": "allow" if stype == "allow" else "block", 
                        "priority": prio, 
                        "tier": src.get('tier', 'global')
                    }
            
            if stype != "allow":
                target_tiers = {
                    'lite': ['lite', 'full', 'extreme'], 
                    'full': ['full', 'extreme'], 
                    'extreme': ['extreme']
                }
                for t in target_tiers.get(src.get('tier', 'lite'), ['lite']): 
                    tier_raws[t].update(r_set)

    os.makedirs('rules', exist_ok=True)
    
    for t in ['lite', 'full', 'extreme']:
        allowed_tiers = ['lite']
        if t == 'full': 
            allowed_tiers = ['lite', 'full']
        if t == 'extreme': 
            allowed_tiers = ['lite', 'full', 'extreme']
        
        tier_domains = [d for d, v in routing.items() if v['type'] == 'block' and v['tier'] in allowed_tiers]
        trie = DomainTrie()
        compressed = sorted([d for d in sorted(tier_domains, key=lambda x: x.count('.')) if trie.insert_and_check(d)])
        
        with open(f'rules/{t}.txt', 'w', encoding='utf-8') as f:
            for d in compressed: 
                f.write(f"||{d}^\n")
            for r in sorted(tier_raws[t]): 
                f.write(f"{r}\n")
            for d, v in routing.items(): 
                if v['type'] == 'allow': 
                    f.write(f"@@||{d}^\n")
        
        stats[f"{t}_total"] = len(compressed) + len(tier_raws[t]) + sum(1 for v in routing.values() if v['type'] == 'allow')

    with open('rules/stats.json', 'w', encoding='utf-8') as f: 
        json.dump(stats, f, indent=2)
    
    print("✅ 构建完成")
    print(f"📊 统计: {stats}")

if __name__ == '__main__': 
    main()                    tier_raws[t].update(r_set)
            stats[stype] += len(d_set) + len(r_set)

    os.makedirs('rules', exist_ok=True)
    for t in ['lite', 'full', 'extreme']:
        allowed_tiers = ['lite']
        if t == 'full': 
            allowed_tiers = ['lite', 'full']
        if t == 'extreme': 
            allowed_tiers = ['lite', 'full', 'extreme']
        tier_domains = [d for d, v in routing.items() if v['type'] == 'block' and v['tier'] in allowed_tiers]
        trie = DomainTrie()
        compressed = sorted([d for d in sorted(tier_domains, key=lambda x: x.count('.')) if trie.insert_and_check(d)])
        with open(f'rules/{t}.txt', 'w', encoding='utf-8') as f:
            for d in compressed: 
                f.write(f"||{d}^\n")
            for r in sorted(tier_raws[t]): 
                f.write(f"{r}\n")
            for d, v in routing.items(): 
                if v['type'] == 'allow': 
                    f.write(f"@@||{d}^\n")
        stats[f"{t}_total"] = len(compressed) + len(tier_raws[t]) + sum(1 for v in routing.values() if v['type'] == 'allow')

    with open('rules/stats.json', 'w', encoding='utf-8') as f: 
        json.dump(stats, f, indent=2)
    print("✅ 构建完成")
    print(f"📊 统计: {stats}")

if __name__ == '__main__': 
    main()
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
