<div align="center">
<h1 align="center">singbox-adguard-rules</h1>
<h3 align="center">sing-box 广告拦截规则集（自动同步 · 合并去重 · 每日更新）</h3>

<p align="center">
  <a href="https://github.com/wvv666/singbox-adguard-rules">
    <img src="https://img.shields.io/github/last-commit/wvv666/singbox-adguard-rules?style=flat-square&color=blue" alt="last update" />
  </a>
  <a href="https://github.com/wvv666/singbox-adguard-rules/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/wvv666/singbox-adguard-rules?style=flat-square&color=9cf" alt="license" />
  </a>
  <a href="https://github.com/wvv666/singbox-adguard-rules/actions/workflows/sync-and-compile.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/wvv666/singbox-adguard-rules/sync-and-compile.yml?style=flat-square&color=brightgreen" alt="CI" />
  </a>
</p>

<p align="center">
  <b>🚫 广告拦截 | 🔄 每日更新 | 🧹 合并去重 | 🛡️ sing-box .srs</b>
</p>

<p align="center">
  <a href="#-项目统计">项目统计</a> •
  <a href="#-规则订阅">规则订阅</a> •
  <a href="#-上游列表">上游列表</a> •
  <a href="#-使用方法">使用方法</a>
</p>

---

</div>

## 📊 项目统计

```
🗓️ 每日更新（北京时间 10:00 自动同步并重新编译）

📈 合并规则集（去重后）:
   combined 258,312 条  （AdGuard + hosts 全量）
   adguard  241,131 条  （仅 AdGuard 语法）
   hosts     17,181 条  （仅 hosts 格式）

📦 单源规则集:
   217heidai  201,338 条   GOODBYEADS-dns  115,499 条
   anti-ad    102,187 条   qq5460168       15,188 条
   10007-adb   13,201 条   10007-all       17,181 条
   GOODBYEADS-allow      93 条（白名单例外）
```

## 📥 规则订阅

所有文件均为 sing-box 规则集（`.srs`），可直接填入 `route.rule_set[].url`。

<details open>
<summary><b>🚫 合并规则集（推荐）</b></summary>
<br>

| 规则集 | 说明 | 📥 GitHub 直链 | 🚀 国内加速 |
| :---- | :---- | :---- | :---- |
| `combined` | AdGuard + hosts 全量合并去重（最全） | [combined.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/combined/combined.srs) | [combined.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/combined/combined.srs) |
| `adguard` | 仅 AdGuard 语法源合并去重 | [adguard.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.srs) | [adguard.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.srs) |
| `hosts` | 仅 hosts 格式源合并去重 | [hosts.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/hosts/hosts.srs) | [hosts.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/hosts/hosts.srs) |

</details>

<details>
<summary><b>📦 单源规则集</b></summary>
<br>

| 规则集 | 说明 | 📥 GitHub 直链 | 🚀 国内加速 |
| :---- | :---- | :---- | :---- |
| `217heidai-adblockdns` | 汇总 16+ 上游的 AdGuard DNS 去广告规则 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/217heidai-adblockdns.srs) | [.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/217heidai-adblockdns.srs) |
| `GOODBYEADS-dns` | DNS 级广告拦截 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/GOODBYEADS-dns.srs) | [.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/GOODBYEADS-dns.srs) |
| `anti-ad-adguard` | 国内广告域名拦截 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/anti-ad-adguard.srs) | [.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/anti-ad-adguard.srs) |
| `qq5460168-dns` | 多格式去广告 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/qq5460168-dns.srs) | [.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/qq5460168-dns.srs) |
| `10007-adb` | ADB 广告拦截 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/10007-adb.srs) | [.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/10007-adb.srs) |
| `GOODBYEADS-allow` | 白名单例外（放行列表） | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/GOODBYEADS-allow.srs) | [.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/GOODBYEADS-allow.srs) |
| `10007-all` | hosts 格式全量拦截 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/hosts/10007-all.srs) | [.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/hosts/10007-all.srs) |

</details>

## 📚 上游列表

<details>
<summary><b>点击查看数据来源（sources.json）</b></summary>
<br>

- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) — 汇总 16+ 上游的 AdGuard DNS 规则
- [8680/GOODBYEADS](https://github.com/8680/GOODBYEADS) — DNS 级广告拦截 + 白名单例外
- [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) — 国内广告域名
- [qq5460168/666](https://github.com/qq5460168/666) — 多格式去广告
- [lingeringsound/10007](https://github.com/lingeringsound/10007) — ADB 拦截 + hosts 全量

</details>

## 🚀 使用方法

把订阅表中的链接填入 sing-box 配置（`type: "remote"`, `format: "binary"`），并在 `route.rules` 中引用：

```jsonc
{
  "route": {
    "rule_set": [
      {
        "tag": "combined",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/combined/combined.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      { "rule_set": ["combined"], "outbound": "block" }
    ]
  }
}
```

完整配置参考 [sing-box 官方文档](https://sing-box.sagernet.org/configuration/rule-set/)。

## 💬 完善项目

- **更换/新增广告源**：编辑 [`sources.json`](sources.json)（加/删/改 URL 与 type）→ push → CI 自动完成下载、转换、编译、提交
- **问题反馈**：欢迎提交 [Issue](https://github.com/wvv666/singbox-adguard-rules/issues)（误杀/漏拦截）

<div align="center">
  <b>如果觉得有用，请点个 ⭐ 支持一下！</b>
</div>
