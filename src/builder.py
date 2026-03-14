import json, urllib.request, re, os, time, concurrent.futures, ipaddress, sys
import gzip
from io import BytesIO
from publicsuffixlist import PublicSuffixList

# --- 初始化 ---
# 初始化公共后缀列表，可选更新最新列表
psl = PublicSuffixList()
try:
    # 自动拉取最新的公共后缀列表（需要网络，失败则使用内置列表）
    psl.fetch()
except Exception as e:
    print(f"⚠️ 公共后缀列表更新失败，使用内置版本: {e}")

# 规则匹配正则
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
    # 新增gzip压缩支持，大幅降低下载流量和耗时
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept-Encoding': 'gzip, deflate'
    }
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                content_encoding = resp.getheader('Content-Encoding')
                raw_data = resp.read()
                # 自动解压gzip内容
                if content_encoding == 'gzip':
                    with gzip.GzipFile(fileobj=BytesIO(raw_data)) as f:
                        return f.read().decode('utf-8', errors='ignore')
                return raw_data.decode('utf-8', errors='ignore')
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
    # 白名单规则解析
    if is_whitelist:
        m = dnsmasq_pattern.match(line)
        if m: 
            domain = m.group(1)
        elif line.startswith('@@||') and line.endswith('^'): 
            domain = line[4:-1]
    
    # 普通拦截规则解析
    if not domain:
        for p in [hosts_pattern, strict_domain_pattern, pure_domain_pattern, dnsmasq_pattern]:
            m = p.match(line)
            if m: 
                domain = m.group(1)
                break
    
    if domain:
        domain = domain.lower()
        # 过滤IP地址
        try: 
            ipaddress.ip_address(domain)
            return None, None
        except: 
            pass
        
        # 过滤本地保留域名
        if domain in ('localhost', 'local', 'localhost.localdomain'): 
            return None, None
        
        # === 彻底修复：使用官方正确API做公共后缀判断 ===
        try:
            # 获取域名的公共后缀部分
            public_suffix = psl.publicsuffix(domain)
            # 过滤规则：
            # 1. 域名本身就是公共后缀（如 com、co.uk），无效规则
            # 2. 无有效公共后缀（如 test.abc123、xxx.local），无效规则
            if public_suffix == domain or public_suffix is None:
                return None, None
        except Exception as e:
            print(f"⚠️ 公共后缀检查失败 {domain}: {e}")
            return None, None
        
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
    # 配置文件读取
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

    # 汇总所有规则源
    all_sources = [(s, False) for s in config.get('upstream_rules', [])] + \
                  [(s, True) for s in config.get('whitelist', [])]
    
    # 并发下载与解析
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch_worker, s, is_w) for s, is_w in all_sources]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if not res: 
                stats["failed"] += 1
                continue
            src, d_set, r_set = res['source'], res['domains'], res['raws']
            prio, stype = src.get('priority', 0), src.get('type', 'ad')
            
            # 统计更新
            stats_key = stype if stype in stats else "ad"
            stats[stats_key] += len(d_set) + len(r_set)
            
            # 规则路由表更新
            for d in d_set:
                if d not in routing or prio > routing[d]['priority']:
                    routing[d] = {
                        "type": "allow" if stype == "allow" else "block", 
                        "priority": prio, 
                        "tier": src.get('tier', 'global')
                    }
            
            # 非白名单的原始规则按层级归档
            if stype != "allow":
                target_tiers = {
                    'lite': ['lite', 'full', 'extreme'], 
                    'full': ['full', 'extreme'], 
                    'extreme': ['extreme']
                }
                for t in target_tiers.get(src.get('tier', 'lite'), ['lite']): 
                    tier_raws[t].update(r_set)

    # 输出目录创建
    os.makedirs('rules', exist_ok=True)
    
    # 构建白名单字典树，提前过滤白名单域名的子域名，减少无效规则
    whitelist_trie = DomainTrie()
    for d, v in routing.items():
        if v['type'] == 'allow':
            whitelist_trie.insert_and_check(d)
    
    # 分层级生成规则文件
    for t in ['lite', 'full', 'extreme']:
        allowed_tiers = ['lite']
        if t == 'full': 
            allowed_tiers = ['lite', 'full']
        if t == 'extreme': 
            allowed_tiers = ['lite', 'full', 'extreme']
        
        # 筛选当前层级的拦截域名
        tier_domains = [d for d, v in routing.items() if v['type'] == 'block' and v['tier'] in allowed_tiers]
        # 子域名去重 + 白名单过滤
        trie = DomainTrie()
        compressed = sorted([
            d for d in sorted(tier_domains, key=lambda x: x.count('.')) 
            if trie.insert_and_check(d) and not whitelist_trie.insert_and_check(d)
        ])
        
        # 写入规则文件
        with open(f'rules/{t}.txt', 'w', encoding='utf-8') as f:
            # 写入拦截域名规则
            for d in compressed: 
                f.write(f"||{d}^\n")
            # 写入原始复杂规则
            for r in sorted(tier_raws[t]): 
                f.write(f"{r}\n")
            # 写入全局白名单规则
            for d, v in routing.items(): 
                if v['type'] == 'allow': 
                    f.write(f"@@||{d}^\n")
        
        # 层级统计更新
        stats[f"{t}_total"] = len(compressed) + len(tier_raws[t]) + sum(1 for v in routing.values() if v['type'] == 'allow')

    # 写入统计文件
    with open('rules/stats.json', 'w', encoding='utf-8') as f: 
        json.dump(stats, f, indent=2)
    
    # 输出结果
    print("✅ 规则构建完成")
    print(f"📊 构建统计: {json.dumps(stats, indent=2, ensure_ascii=False)}")

if __name__ == '__main__': 
    main()
