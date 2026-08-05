# singbox-adguard-rules

[![Sync Rules](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml/badge.svg)](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml)
[![Last Update](https://img.shields.io/github/last-commit/wvv666/singbox-adguard-rules?label=updated)](../../actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

sing-box 广告规则自动同步、合并去重与编译。每日通过 GitHub Actions 从 `sources.json` 声明的上游拉取规则，转换为 sing-box 无头规则后编译为 `.srs` 二进制格式。

## 规则来源

源清单见 [`sources.json`](sources.json)（新增/更换源 = 编辑该文件并推送，CI 自动全流程）。

| 名称 | 来源 | 类型 | 说明 |
|------|------|------|------|
| `217heidai-adblockdns` | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | AdGuard | 合并去广告规则（16+ 上游） |
| `GOODBYEADS-dns` | [GOODBYEADS](https://github.com/8680/GOODBYEADS) | AdGuard | DNS 级广告拦截 |
| `anti-ad-adguard` | [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | AdGuard | 国内广告拦截 |
| `qq5460168-dns` | [qq5460168/666](https://github.com/qq5460168/666) | AdGuard | 多格式去广告规则 |
| `10007-adb` | [10007](https://lingeringsound.github.io/10007/) | AdGuard | ADB 广告拦截 |
| `GOODBYEADS-allow` | [GOODBYEADS](https://github.com/8680/GOODBYEADS) | AdGuard | 白名单例外 |
| `10007-all` | [10007](https://lingeringsound.github.io/10007/) | hosts | hosts 格式拦截 |

## 编译产物

CI 产物位于 `work/out/`（sources 原始文件 / converted 单源 / merged 合并去重 / rule-sets 引用配置），全部入库可下载：

| 文件 | 说明 | 下载链接 |
|------|------|----------|
| `merged/combined/combined.srs` | **合并去重版（AdGuard + hosts，推荐）** | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/combined/combined.srs) |
| `merged/adguard/adguard.srs` | AdGuard 语法合并去重 | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.srs) |
| `merged/hosts/hosts.srs` | hosts 语法合并去重 | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/hosts/hosts.srs) |
| `converted/adguard/<源名>.srs` | 单源转换 | 见 [work/out/converted](work/out/converted) |
| `rule-sets/*.json` | sing-box 引用条目（可直接粘贴） | 见 [work/out/rule-sets](work/out/rule-sets) |

每个产物同时保留**原始规则文件（.txt/.hosts）**与**无头规则 JSON 源**，便于检查与复用。

## 使用方法

在 sing-box 配置中添加规则集（`rule-sets/combined.json` 的内容可直接粘贴进 `route.rule_set`）：

```jsonc
{
  "route": {
    "rules": [
      {
        "rule_set": ["combined"],
        "outbound": "block"
      }
    ],
    "rule_set": [
      {
        "tag": "combined",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/combined/combined.srs",
        "download_detour": "direct"
      }
    ]
  }
}
```

## 工作流程

```
sources.json (源清单) → download-sources.py (下载 + WAF 污染检测)
                     → adguard2headless.py (AdGuard/hosts → 无头规则 JSON)
                     → sing-box rule-set compile → .srs
                     → merged 三类去重产物 + rule-sets 引用 → 提交
```

1. 从 `sources.json` 声明的源下载最新规则（含 HTML/WAF 拦截页污染检测，污染即失败）
2. 使用**最新版 sing-box**（GitHub API 解析 latest release，版本不符即失败）
3. `adguard2headless.py` 将 AdGuard/hosts 语法转换为 sing-box 无头规则 JSON（支持 `$dnstype`、`$client`、IP、端口等官方转换器丢弃的语法）
4. 合并去重分三类：adguard / hosts / combined（原始行去重 + 语义分桶 + 父域精简）
5. 编译全部 `.srs`，提交 `work/out/` 产物

## 自动更新

- **定时**：每天北京时间 10:00 自动运行
- **手动**：在 [Actions](../../actions) 页面触发
- **新增规则**：编辑 `sources.json` 添加条目 → 推送 → CI 自动下载/转换/编译/合并

## 项目结构

```
├── .github/workflows/
│   └── sync-and-compile.yml    # CI 工作流（latest sing-box + 源清单驱动）
├── sources.json                # 源清单（URL + 类型）
├── scripts/
│   ├── download-sources.py     # 按清单下载 + WAF 污染检测
│   ├── adguard2headless.py     # AdGuard/hosts → 无头规则 JSON 转换器
│   └── merge-rules.py          # （旧）去重合并脚本
├── tests/                      # 单元测试
├── work/out/                   # CI 产物（sources/converted/merged/rule-sets）
└── README.md
```

## 本地验证

转换器仅依赖 Python 3.10+ 标准库。运行测试：

```bash
python3 -m unittest discover -s tests -v
```

本地完整跑一遍（下载 → 转换 → 产物）：

```bash
python3 scripts/download-sources.py --sources sources.json --out work/sources
python3 scripts/adguard2headless.py \
  --adguard work/sources/adguard/*.txt \
  --hosts  work/sources/hosts/*.hosts \
  --base-url https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out \
  -o work/out
# 编译 .srs 需 sing-box 二进制（CI 自动完成）
```

## 许可证

[MIT](LICENSE)
