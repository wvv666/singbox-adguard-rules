# singbox-adguard-rules

[![Sync Rules](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml/badge.svg)](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml)
[![Last Update](https://img.shields.io/github/last-commit/wvv666/singbox-adguard-rules?label=updated)](../../actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

sing-box 广告规则自动同步、合并去重与编译。每日通过 GitHub Actions 从多个可信源拉取规则，去重后编译为 `.srs` 二进制格式。

## 规则来源

| # | 来源 | 格式 | 说明 |
|---|------|------|------|
| 1 | [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | sing-box JSON | 综合广告/追踪拦截 |
| 2 | [GOODBYEADS](https://github.com/8680/GOODBYEADS) | AdGuard TXT | DNS 级广告拦截 |
| 3 | [10007](https://lingeringsound.github.io/10007/) | AdGuard TXT | ADB 广告拦截 |
| 4 | [qq5460168/666](https://github.com/qq5460168/666) | sing-box JSON | 多格式去广告规则 |
| 5 | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | AdGuard TXT | 合并去广告规则（16+ 上游） |
| 6 | [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | AdGuard TXT | 国内广告拦截 |

## 编译产物

所有文件位于 `Filters/` 目录：

| 文件 | 说明 |
|------|------|
| `combined.srs` | **合并去重版（推荐）** — 所有源合并去重，约 27 万条规则 |
| `AWAvenue-Ads-Rule-Singbox.srs` | 单源：AWAvenue |
| `GOODBYEADS-dns.srs` | 单源：GOODBYEADS |
| `adb.srs` | 单源：10007 |
| `qq5460168-666-Singbox.srs` | 单源：666 |
| `217heidai-adblockdns.srs` | 单源：217heidai |
| `anti-ad.srs` | 单源：anti-AD |

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
上游源 (JSON/TXT) → 下载 → 去重合并 → combined.json → sing-box 编译 → combined.srs
                                                    ↘ 单源编译 → 各 .srs 文件
```

1. 从 6 个上游源下载最新规则
2. 自动检测格式（sing-box JSON / AdGuard TXT）
3. 跨源去重，合并为 `combined.json`
4. 使用 `sing-box rule-set compile` 编译为 `.srs` 二进制格式
5. 提交并推送变更

## 自动更新

- **定时**：每天北京时间 10:00 自动运行
- **手动**：在 [Actions](../../actions) 页面触发

## 项目结构

```
├── .github/workflows/
│   └── sync-and-compile.yml    # CI 工作流
├── Filters/                    # 规则文件（源 + 编译产物）
├── scripts/
│   └── merge-rules.py          # 去重合并脚本
├── LICENSE
└── README.md
```

## 许可证

[MIT](LICENSE)
