import json
import urllib.request
import re
import os
import time
import concurrent.futures
import ipaddress
import sys
import gzip
from io import BytesIO
from publicsuffixlist import PublicSuffixList

# --- 全局初始化 ---
# 公共后缀列表初始化，仅使用官方原生API
psl = PublicSuffixList()

# 规则格式匹配正则
hosts_pattern = re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::1)\s+([a-zA-Z0-9.-]+)$')
strict_domain_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^?$')
pure_domain_pattern = re.compile(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+$')
dnsmasq_pattern = re.compile(r'^(?:server|address)=/([a-zA-Z0-9.-]+)/')

# 域名去重字典树（子域名自动压缩）
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

# 带重试、支持gzip压缩的下载函数
def download_with_retry(url, source_name, retries=3):
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
                # 自动解压gzip压缩内容
                if content_encoding == 'gzip':
                    with gzip.GzipFile(fileobj=BytesIO(raw_data)) as f:
                        return f.read().decode('utf-8', errors='ignore')
                return raw_data.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"⚠️ 下载失败 {source_name} (尝试 {i+1}/{retries}): {e}")
            time.sleep(3)
    print(f"❌ 下载失败: {source_name}")
    return None

# 规则解析核心函数（全程无错误API调用）
def parse_rule(line, is_whitelist=False):
    line = line.strip()
    # 跳过空行和注释行
    if not line or line.startswith(('!', '#')): 
        return None, None
    
    domain = None
    # 白名单规则优先解析
    if is_whitelist:
        m = dnsmasq_pattern.match(line)
        if m: 
            domain = m.group(1)
        elif line.startswith('@@||') and line.endswith('^'): 
            domain = line[4:-1]
    
    # 普通拦截规则解析
    if not domain:
        for pattern in [hosts_pattern, strict_domain_pattern, pure_domain_pattern, dnsmasq_pattern]:
            m = pattern.match(line)
            if m: 
                domain = m.group(1)
                break
    
    # 域名合法性全量校验
    if domain:
        domain = domain.lower()
        # 过滤IP地址
        try: 
            ipaddress.ip_address(domain)
            return None, None
        except: 
            pass
        
        # 过滤本地保留域名
        if domain in ('localhost', 'local', 'localhost.localdomain', 'broadcasthost'): 
            return None, None
        
        # 公共后缀合法性校验（仅使用官方原生API，无任何错误调用）
        try:
            public_suffix = psl.publicsuffix(domain)
            # 过滤无效域名：1. 域名本身就是公共后缀 2. 无有效公共后缀
            if public_suffix == domain or not public_suffix:
                return None, None
        except Exception:
            return None, None
        
        return 'domain', domain
    
    # 非域名的原生规则直接保留
    return 'raw', line

# 单源下载解析工作函数
def fetch_worker(source, is_whitelist=False):
    if not source.get('enabled', True): 
        return None
    content = download_with_retry(source['url'], source['name'])
    if not content: 
        return None
    domains = set()
    raws = set()
    for line in content.splitlines():
        rtype, val = parse_rule(line, is_whitelist)
        if rtype == 'domain': 
            domains.add(val)
        elif rtype == 'raw': 
            raws.add(val)
    return {"domains": domains, "raws": raws, "source": source}

# 主程序入口
def main():
    # 读取配置文件
    try:
        with open('upstream.json', 'r', encoding='utf-8') as f: 
            config = json.load(f)
    except FileNotFoundError:
        print("❌ 错误：同目录下未找到 upstream.json 配置文件")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ 错误：upstream.json 格式无效：{e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 错误：读取配置文件失败：{e}")
        sys.exit(1)
    
    # 初始化变量
    routing = {}
    tier_raws = {'lite': set(), 'full': set(), 'extreme': set()}
    stats = {"ad": 0, "tracking": 0, "malicious": 0, "allow": 0, "failed": 0}

    # 汇总所有规则源
    all_sources = [(s, False) for s in config.get('upstream_rules', [])] + \
                  [(s, True) for s in config.get('whitelist', [])]
    
    # 并发下载与解析
    print("🔄 开始下载并解析规则...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch_worker, s, is_w) for s, is_w in all_sources]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if not res: 
                stats["failed"] += 1
                continue
            src = res['source']
            d_set = res['domains']
            r_set = res['raws']
            prio = src.get('priority', 0)
            stype = src.get('type', 'ad')
            
            # 更新统计数据
            stats_key = stype if stype in stats else "ad"
            stats[stats_key] += len(d_set) + len(r_set)
            
            # 更新规则路由表（高优先级覆盖低优先级）
            for d in d_set:
                if d not in routing or prio > routing[d]['priority']:
                    routing[d] = {
                        "type": "allow" if stype == "allow" else "block", 
                        "priority": prio, 
                        "tier": src.get('tier', 'lite')
                    }
            
            # 非白名单规则按层级归档
            if stype != "allow":
                tier_map = {
                    'lite': ['lite', 'full', 'extreme'],
                    'full': ['full', 'extreme'],
                    'extreme': ['extreme']
                }
                for target_tier in tier_map.get(src.get('tier', 'lite'), ['lite']):
                    tier_raws[target_tier].update(r_set)

    # 创建输出目录
    os.makedirs('rules', exist_ok=True)
    
    # 预构建白名单字典树，提前过滤白名单域名的子域名，减少无效规则
    whitelist_trie = DomainTrie()
    for d, v in routing.items():
        if v['type'] == 'allow':
            whitelist_trie.insert_and_check(d)
    
    # 分层级生成最终规则文件
    for tier in ['lite', 'full', 'extreme']:
        # 筛选当前层级的拦截域名
        allowed_tiers = {
            'lite': ['lite'],
            'full': ['lite', 'full'],
            'extreme': ['lite', 'full', 'extreme']
        }[tier]
        tier_domains = [
            d for d, v in routing.items() 
            if v['type'] == 'block' and v['tier'] in allowed_tiers
        ]
        
        # 子域名去重 + 白名单过滤
        trie = DomainTrie()
        compressed_domains = sorted([
            d for d in sorted(tier_domains, key=lambda x: x.count('.'))
            if trie.insert_and_check(d) and not whitelist_trie.insert_and_check(d)
        ])
        
        # 写入规则文件
        with open(f'rules/{tier}.txt', 'w', encoding='utf-8') as f:
            # 写入拦截域名规则
            for d in compressed_domains:
                f.write(f"||{d}^\n")
            # 写入原生复杂规则
            for r in sorted(tier_raws[tier]):
                f.write(f"{r}\n")
            # 写入全局白名单规则
            for d, v in routing.items():
                if v['type'] == 'allow':
                    f.write(f"@@||{d}^\n")
        
        # 更新层级统计
        stats[f"{tier}_total"] = len(compressed_domains) + len(tier_raws[tier]) + sum(1 for v in routing.values() if v['type'] == 'allow')

    # 写入统计文件
    with open('rules/stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    
    # 输出最终结果
    print("\n✅ 规则构建完成！")
    print(f"📊 构建统计：{json.dumps(stats, indent=2, ensure_ascii=False)}")

if __name__ == '__main__':
    main()
