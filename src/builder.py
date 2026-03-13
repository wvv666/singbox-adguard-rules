import json
import urllib.request
import urllib.error
import re
import os
import time

# --- 正则表达式预编译 ---
hosts_pattern = re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::1)\s+([a-zA-Z0-9.-]+)$')
ip_rule_pattern = re.compile(r'^\|\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\^?$')
domain_extract_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+)(?:\^.*)?$')

def download_with_retry(url, retries=3, delay=5):
    """带重试机制的下载函数"""
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"    [警告] 下载失败 ({attempt+1}/{retries}): {url} - {e}")
            if attempt < retries - 1:
                time.sleep(delay)
    print(f"❌ 致命错误: 无法下载 {url}")
    exit(1)

def process_line(line):
    """清洗单行规则，返回合规的规则或 None"""
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#') or line.startswith('@@'):
        return None
    if '##' in line or '#?#' in line or '$$' in line:
        return None
    if line in ('||^', '||', '^'):
        return None
    if ip_rule_pattern.match(line):
        return None
    
    # 提取域名并校验合法性
    domain_match = domain_extract_pattern.match(line)
    if domain_match:
        domain = domain_match.group(1)
        if '..' in domain or domain.startswith('.') or domain.startswith('-') or domain.endswith('-'):
            return None

    # 处理 Hosts 格式
    match = hosts_pattern.match(line)
    if match:
        domain = match.group(1)
        if domain in ('localhost', 'broadcasthost', 'local'):
            return None
        return f'0.0.0.0 {domain}'
        
    return line

def main():
    print("🚀 开始执行核心构建引擎...")
    
    # 读取配置
    with open('upstream.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 准备各级别的集合
    ruleset = {
        'lite': set(),
        'full': set(),
        'extreme': set()
    }
    
    # 统计数据载体
    stats = {"ad": 0, "tracking": 0, "malicious": 0, "allow": 0}

    # 1. 处理黑名单上游
    for source in config.get('upstream_rules', []):
        if not source.get('enabled', True):
            continue
            
        print(f"⬇️ 正在下载 [{source['tier'].upper()}] {source['name']}...")
        content = download_with_retry(source['url'])
        
        valid_rules_count = 0
        for line in content.splitlines():
            clean_rule = process_line(line)
            if clean_rule:
                # 按照等级分发 (Extreme 包含所有，Full 包含 Lite+Full，Lite 只含 Lite)
                if source['tier'] in ('lite', 'full', 'extreme'):
                    ruleset['extreme'].add(clean_rule)
                if source['tier'] in ('lite', 'full'):
                    ruleset['full'].add(clean_rule)
                if source['tier'] == 'lite':
                    ruleset['lite'].add(clean_rule)
                
                valid_rules_count += 1
                
        # 记录统计数据
        stats[source['type']] = stats.get(source['type'], 0) + valid_rules_count

    # 2. 处理白名单上游
    allow_set = set()
    for source in config.get('whitelist', []):
        if not source.get('enabled', True):
            continue
        print(f"🛡️ 正在下载白名单 {source['name']}...")
        content = download_with_retry(source['url'])
        for line in content.splitlines():
            # 这里可以针对 dnsmasq 格式做简单提取，目前为了通用先做基础清洗
            clean_rule = process_line(line)
            if clean_rule:
                allow_set.add(clean_rule)
                stats['allow'] += 1

    # 3. 冲突检测与解决 (从所有黑名单中剔除白名单规则)
    conflict_count = len(ruleset['extreme'].intersection(allow_set))
    for tier in ruleset:
        ruleset[tier] = ruleset[tier] - allow_set

    # 4. 创建输出目录并保存文件
    os.makedirs('rules', exist_ok=True)
    for tier, rules in ruleset.items():
        with open(f'rules/{tier}.txt', 'w', encoding='utf-8') as f:
            for rule in sorted(rules):
                f.write(rule + '\n')
                
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
