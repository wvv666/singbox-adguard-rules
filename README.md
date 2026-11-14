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
   adguard  288,113 条  （全部上游源合并去重）

📦 各规则源（规则数）:
   217heidai-adblockdns  241,897 条
   GOODBYEADS-dns        116,951 条
   anti-ad-adguard       96,518 条
   qq5460168-dns         15,275 条
   GOODBYEADS-allow      93 条
```

## 📥 规则订阅

<details open>
<summary><b>🚫 合并规则集（推荐）</b></summary>
<br>

| 格式 | 说明 | 📥 GitHub 直链 | 🚀 国内加速 |
| :---- | :---- | :---- | :---- |
| `adguard.srs` | sing-box 编译订阅（推荐） | [adguard.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.srs) | [adguard.srs](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.srs) |
| `adguard.txt` | AdGuard 原生文本（合并去重） | [adguard.txt](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.txt) | [adguard.txt](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.txt) |
| `adguard.json` | sing-box 源格式 JSON | [adguard.json](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.json) | [adguard.json](https://ghfast.top/raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.json) |

</details>

## 📚 上游列表

<details>
<summary><b>点击查看数据来源（sources.json）</b></summary>
<br>

- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) — 汇总 16+ 上游的 AdGuard DNS 规则
- [8680/GOODBYEADS](https://github.com/8680/GOODBYEADS) — DNS 级广告拦截 + 白名单例外
- [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) — 国内广告域名
- [qq5460168/666](https://github.com/qq5460168/666) — 多格式去广告

</details>

## 💬 完善项目

- **更换/新增广告源**：编辑 [`sources.json`](sources.json)（加/删/改 URL 与 type）→ push → CI 自动完成下载、转换、编译、提交
- **问题反馈**：欢迎提交 [Issue](https://github.com/wvv666/singbox-adguard-rules/issues)（误杀/漏拦截）

### 维护说明

- **仓库体积策略**：提交 `merged/adguard/` 下的 `.srs`、原生 `.txt` 与源格式 `.json`；仅上游原件副本不入库。
- **冗余剪枝**：合并时会删掉「已被同条件 `domain_suffix` 覆盖」的精确域名（如 `a.example.com` 已被 `example.com` 覆盖），拦截范围不变但产物更小。
- **自动防退化**：CI 校验 sing-box 二进制 SHA-256（读取 Release 资产 digest）；若合并规则数骤降超过 20%，判定上游源异常并拒绝提交。

如果觉得有用，请点个 ⭐ 支持一下！
