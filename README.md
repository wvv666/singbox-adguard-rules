# singbox-adguard-rules

[![Sync Rules](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml/badge.svg)](https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

sing-box 广告规则自动同步与编译。每日通过 GitHub Actions 从多个可信源拉取规则并编译为 `.srs` 格式。

> Auto-synced and compiled ad-blocking rules for [sing-box](https://github.com/SagerNet/sing-box). Updated daily.

## 规则来源

| 来源 | 格式 | 说明 |
|------|------|------|
| [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | sing-box JSON | 综合广告/追踪拦截 |
| [GOODBYEADS](https://github.com/8680/GOODBYEADS) | AdGuard TXT | DNS 级广告拦截 |
| [10007](https://lingeringsound.github.io/10007/) | AdGuard TXT | ADB 广告拦截 |

## 编译产物

所有文件位于 `Filters/` 目录：

| 文件 | 格式 | 说明 |
|------|------|------|
| `combined.srs` | sing-box rule-set | **合并去重版**（推荐） |
| `AWAvenue-Ads-Rule-Singbox.srs` | sing-box rule-set | 单源：AWAvenue |
| `GOODBYEADS-dns.srs` | sing-box rule-set | 单源：GOODBYEADS |
| `adb.srs` | sing-box rule-set | 单源：10007 |

`combined.srs` 合并三个源并去重，排除白名单例外。单源文件保留供精细控制。

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

## 自动更新

GitHub Actions 工作流每天北京时间 10:00 自动运行：

1. 从各来源下载最新规则
2. 使用 `sing-box rule-set` 编译为 `.srs` 格式
3. 一次性提交并推送变更

也可在 [Actions](../../actions) 页面手动触发。

## 许可证

[MIT](LICENSE)
