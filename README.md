# singbox-adguard-rules

[![Sync Rules](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml/badge.svg)](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml)
[![Last Update](https://img.shields.io/github/last-commit/wvv666/singbox-adguard-rules?label=updated)](../../actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

sing-box 广告规则自动同步、合并去重与编译。每日通过 GitHub Actions 从多个公开上游拉取规则，去重后使用 sing-box 官方转换器编译为 `.srs` 二进制格式。

## 规则来源

| # | 来源 | 格式 | 说明 |
|---|------|------|------|
| 1 | [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | sing-box JSON | 综合广告/追踪拦截 |
| 2 | [GOODBYEADS](https://github.com/8680/GOODBYEADS) | AdGuard TXT | DNS 级广告拦截 |
| 3 | [10007](https://lingeringsound.github.io/10007/) | AdGuard TXT | ADB 广告拦截 |
| 4 | [qq5460168/666](https://github.com/qq5460168/666) | sing-box JSON | 多格式去广告规则 |
| 5 | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | AdGuard TXT | 合并去广告规则（16+ 上游） |
| 6 | [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | AdGuard TXT | 国内广告拦截 |
| 7 | [REIJI007/AdBlock_Rule_For_Sing-box](https://github.com/REIJI007/AdBlock_Rule_For_Sing-box) | sing-box JSON | 综合广告拦截 |

## 编译产物

所有文件位于 `Filters/` 目录：

| 文件 | 说明 | 下载链接 |
|------|------|----------|
| `combined.srs` | **合并去重版（推荐）** | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/combined.srs) |
| `AWAvenue-Ads-Rule-Singbox.srs` | 单源：AWAvenue | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/AWAvenue-Ads-Rule-Singbox.srs) |
| `GOODBYEADS-dns.srs` | 单源：GOODBYEADS | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/GOODBYEADS-dns.srs) |
| `adb.srs` | 单源：10007 | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/adb.srs) |
| `qq5460168-666-Singbox.srs` | 单源：666 | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/qq5460168-666-Singbox.srs) |
| `217heidai-adblockdns.srs` | 单源：217heidai | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/217heidai-adblockdns.srs) |
| `anti-ad.srs` | 单源：anti-AD | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/anti-ad.srs) |
| `REIJI007-adblock_reject.srs` | 单源：REIJI007 | [下载](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/REIJI007-adblock_reject.srs) |

单源文件保留供需要精细控制的用户。

## 使用方法

在 sing-box 配置中添加规则集：

```jsonc
{
  "route": {
    "rules": [
      {
        "rule_set": ["geosite-category-ads-all"],
        "outbound": "block"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/combined.srs",
        "download_detour": "direct"
      }
    ]
  }
}
```

## 工作流程

```
上游源 (JSON/TXT) → 下载 → 等价转换与精确去重 → combined.txt → sing-box 官方转换 → combined.srs
                                                               ↘ 单源编译/转换 → 各 .srs 文件
```

1. 从 7 个上游源下载最新规则
2. 将 sing-box JSON 中可等价表示的域名、域名后缀、关键词和正则转换为 AdGuard 语法
3. 原样保留 TXT 中的例外、通配符、正则、hosts、逐行域名和 `$important` 等规则并精确去重
4. 使用官方 `sing-box rule-set convert --type adguard` 转换合并规则，单源 JSON 使用 `compile`
5. 提交并推送变更

AdGuard 转换行为和受支持语法以 [sing-box 官方兼容性文档](https://sing-box.sagernet.org/zh/configuration/rule-set/adguard/) 为准。JSON 的结构和字段语义遵循官方的[源文件格式](https://sing-box.sagernet.org/zh/configuration/rule-set/source-format/)与[无头规则](https://sing-box.sagernet.org/zh/configuration/rule-set/headless-rule/)文档。

不受官方转换器支持的路径规则和描述符会被跳过。无法等价表示为扁平 AdGuard DNS 规则的 JSON 内容，例如 `ip_cidr`、带端口或进程条件的 AND 规则、逻辑规则和 `invert`，会让合并任务明确失败，而不会被静默丢弃或扩大匹配范围。

## 自动更新

- **定时**：每天北京时间 10:00 自动运行
- **手动**：在 [Actions](../../actions) 页面触发

## 项目结构

```
├── .github/workflows/
│   └── sync-and-compile.yml    # CI 工作流
├── Filters/                    # 编译产物（.srs 文件）
├── scripts/
│   └── merge-rules.py          # 去重合并脚本
├── LICENSE
└── README.md
```

源文件由 CI 每次运行时从上游下载，不保留在仓库中。

## 本地验证

合并脚本仅依赖 Python 3.10+ 标准库。运行测试：

```bash
python3 -m unittest discover -s tests -v
```

如需使用已下载到 `Filters/` 的上游文件生成并转换合并规则：

```bash
python3 scripts/merge-rules.py
sing-box rule-set convert --type adguard --output Filters/combined.srs Filters/combined.txt
```

## 许可证

[MIT](LICENSE)
