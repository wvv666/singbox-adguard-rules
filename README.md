# singbox-adguard-rules

[English](#english) | [中文](#中文)

---

## English

Automatically synced and compiled ad-blocking rules for [sing-box](https://github.com/SagerNet/sing-box). Updated daily via GitHub Actions from multiple trusted sources.

### Features

- **Daily auto-sync** — Rules are fetched every day at 10:00 AM (UTC+8)
- **Auto-compile** — Raw rules are compiled into `.srs` format for sing-box
- **One-commit workflow** — Downloads, compiles, and pushes in a single CI run
- **Zero maintenance** — Just use the pre-built `.srs` files

### Rule Sources

| Source | File | Description |
|--------|------|-------------|
| [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | `AWAvenue-Ads-Rule-Singbox.json` | Comprehensive ad/tracker blocking rules (sing-box format) |
| [GOODBYEADS](https://github.com/8680/GOODBYEADS) | `GOODBYEADS-dns.txt` | DNS-level ad blocking rules (AdGuard format) |
| [10007](https://lingeringsound.github.io/10007/) | `adb.txt` | ADB-based ad blocking rules (AdGuard format) |

### Files

All compiled rules are in the `Filters/` directory:

| File | Format | Use Case |
|------|--------|----------|
| `AWAvenue-Ads-Rule-Singbox.srs` | sing-box rule-set | IP/domain blocking |
| `GOODBYEADS-dns.srs` | sing-box rule-set | DNS ad blocking |
| `adb.srs` | sing-box rule-set | DNS ad blocking |

### Usage

Add the rule-set to your `sing-box` configuration:

```jsonc
{
  "route": {
    "rules": [
      {
        "rule_set": [
          "geosite-category-ads-all"
        ],
        "outbound": "block"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/AWAvenue-Ads-Rule-Singbox.srs",
        "download_detour": "direct"
      }
    ]
  }
}
```

### Auto-Update

A single GitHub Actions workflow (`sync-and-compile.yml`) runs daily:

1. Downloads latest rules from all sources
2. Compiles to `.srs` format using `sing-box rule-set`
3. Commits and pushes everything in one go

You can also trigger it manually from the **Actions** tab.

### License

[MIT](LICENSE)

---

## 中文

[sing-box](https://github.com/SagerNet/sing-box) 广告规则自动同步与编译项目。每日通过 GitHub Actions 从多个可信源拉取规则并编译为 `.srs` 格式。

### 功能特性

- **每日自动同步** — 每天北京时间 10:00 自动拉取最新规则
- **自动编译** — 将原始规则编译为 sing-box 可用的 `.srs` 格式
- **单次提交** — 下载、编译、推送在同一 CI 流程中完成
- **零维护** — 直接使用预编译的 `.srs` 文件即可

### 规则来源

| 来源 | 文件 | 说明 |
|------|------|------|
| [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | `AWAvenue-Ads-Rule-Singbox.json` | 综合广告/追踪拦截规则（sing-box 格式） |
| [GOODBYEADS](https://github.com/8680/GOODBYEADS) | `GOODBYEADS-dns.txt` | DNS 级广告拦截规则（AdGuard 格式） |
| [10007](https://lingeringsound.github.io/10007/) | `adb.txt` | 基于 ADB 的广告拦截规则（AdGuard 格式） |

### 文件说明

所有编译后的规则位于 `Filters/` 目录：

| 文件 | 格式 | 用途 |
|------|------|------|
| `AWAvenue-Ads-Rule-Singbox.srs` | sing-box rule-set | IP/域名拦截 |
| `GOODBYEADS-dns.srs` | sing-box rule-set | DNS 广告拦截 |
| `adb.srs` | sing-box rule-set | DNS 广告拦截 |

### 使用方法

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
        "url": "https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/Filters/AWAvenue-Ads-Rule-Singbox.srs",
        "download_detour": "direct"
      }
    ]
  }
}
```

### 自动更新

GitHub Actions 工作流（`sync-and-compile.yml`）每日运行：

1. 从各来源下载最新规则
2. 使用 `sing-box rule-set` 编译为 `.srs` 格式
3. 一次性提交并推送所有变更

也可以在 **Actions** 页面手动触发。

### 许可证

[MIT](LICENSE)
