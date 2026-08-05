# singbox-adguard-rules

sing-box 广告拦截规则集：自动同步上游规则、合并去重、编译为 `.srs`，每日更新。

![last update](https://img.shields.io/github/last-commit/wvv666/singbox-adguard-rules?style=flat-square&color=blue)
![license](https://img.shields.io/github/license/wvv666/singbox-adguard-rules?style=flat-square&color=9cf)
![CI](https://img.shields.io/github/actions/workflow/status/wvv666/singbox-adguard-rules/sync-and-compile.yml?style=flat-square&color=brightgreen)

[项目统计](#-项目统计) • [规则订阅](#-规则订阅) • [上游列表](#-上游列表) • [完善项目](#-完善项目)

---

## 📊 项目统计

每日更新（北京时间 10:00 自动同步并重新编译）。

```
📈 合并规则集（去重后）:
   combined 258,311 条  （AdGuard + hosts 全量）
   adguard  241,130 条  （仅 AdGuard 语法）
   hosts     17,181 条  （仅 hosts 格式）

📦 单源规则集:
   217heidai  201,338 条   GOODBYEADS-dns  115,498 条
   anti-ad    102,187 条   qq5460168       15,188 条
   10007-adb   13,201 条   10007-all       17,181 条
   GOODBYEADS-allow      92 条（白名单例外）
```

## 📥 规则订阅

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

## 💬 完善项目

- **更换/新增广告源**：编辑 [`sources.json`](sources.json)（加/删/改 URL 与 type）→ push → CI 自动完成下载、转换、编译、提交
- **问题反馈**：欢迎提交 [Issue](https://github.com/wvv666/singbox-adguard-rules/issues)（误杀/漏拦截）

如果觉得有用，请点个 ⭐ 支持一下！
