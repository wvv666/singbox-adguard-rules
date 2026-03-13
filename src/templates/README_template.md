# 🛡️ Sing-box Pro Ruleset | 企业级去广告规则库

![Rules Extreme](https://img.shields.io/badge/Extreme_Rules-{extreme_total}-red?style=for-the-badge)
![Last Update](https://img.shields.io/badge/Update-{update_time}-blue?style=for-the-badge)

本项目提供完全遵循 [sing-box](https://sing-box.sagernet.org/) 1.10.0+ 官方规范构建的顶级去广告 `.srs` 二进制规则集。

每天自动从全球顶尖的开源规则源拉取最新数据，并通过**高性能 Python 引擎**进行清洗、去重、压缩与编译，为你提供极致清爽的网络体验。
---

## ⚡ 核心构建引擎特性

本规则库不仅是简单的列表合并，我们在构建阶段引入了工业级的网络防护算法：

- **🌲 Trie-Tree 极致压缩**：基于字典树的 DNS 层级算法，精准剔除冗余子域名，极大降低设备内存占用。
- **🛡️ PSL 边界防护**：集成 Mozilla Public Suffix List，绝对禁止误杀顶级公共后缀（如 `.com.cn`, `github.io`）。
- **⚖️ 智能权重仲裁**：摒弃粗暴的集合运算，引入 `Priority` 优先级权重，完美处理白名单与黑名单的交叉冲突。
- **🚫 严格异形数据过滤**：自动清洗 Hosts 文件中的 IPv4/IPv6 残留与大小写混编等脏数据，保障底层网络栈稳定。

---

## 📦 规则分级与获取

为了适应不同用户的需求，本规则库提供三个梯度的构建产物。你可以直接点击下载，或复制链接作为远程规则导入：

### 🟢 Lite 版 (基础防误杀)
- **规则数量**：`{lite_total}` 条
- **适用场景**：家庭网络、长辈设备、对网络连通性要求极高的办公环境。
- **文件获取**：[📥 点击获取 lite.srs](rules/lite.srs) / [📄 纯文本规则](rules/lite.txt)

### 🔵 Full 版 (主力推荐)
- **规则数量**：`{full_total}` 条
- **适用场景**：日常主力使用，在保障绝大多数网站正常访问的前提下，强力拦截广告、隐私追踪与恶意软件。
- **文件获取**：[📥 点击获取 full.srs](rules/full.srs) / [📄 纯文本规则](rules/full.txt)

### 🔴 Extreme 版 (极限洁癖)
- **规则数量**：`{extreme_total}` 条
- **适用场景**：极客玩家专用，引入了最激进的过滤规则，可能会导致部分冷门网站样式错乱，但能提供绝对纯净的冲浪体验。
- **文件获取**：[📥 点击获取 extreme.srs](rules/extreme.srs) / [📄 纯文本规则](rules/extreme.txt)
---

## 📊 自动化构建数据大盘

得益于 GitHub Actions 的自动化流水线，本规则库保持每日高频更新。以下是最近一次构建的详细数据统计：

| 数据维度 | 数量统计 | 拦截维度说明 |
| :--- | :--- | :--- |
| **广告拦截 (Ads)** | `{ad_count}` 条 | 针对主流网页横幅、弹窗及视频广告 |
| **隐私追踪 (Tracking)** | `{tracking_count}` 条 | 拦截各类数据收集器、遥测与分析探针 |
| **恶意软件 (Malicious)** | `{malicious_count}` 条 | 屏蔽钓鱼网站、挖矿脚本与已知恶意节点 |
| **官方防误杀白名单** | `{allow_count}` 条 | 核心业务强行放行，保障支付与基础服务 |
| **智能冲突化解** | `{conflicts_resolved}` 次 | 利用权重仲裁成功纠正的规则冲突数 |
| **失效上游源** | `{failed_sources}` 个 | 本次构建因网络异常或停更被自动剔除的源 |

> **最后构建时间**: `{update_time}` (基于 GitHub Actions 自动化触发)

---

## 📖 Sing-box 客户端配置示例

你可以直接复制以下内容，将其集成到你本地设备或路由器的 `sing-box` 配置文件 (`config.json`) 中。

> 💡 **提示**：建议使用 `full.srs` 作为主力，如果遇到经常性断网，可降级为 `lite.srs`。将下面的 `你的GitHub用户名/你的仓库名` 替换为你 Fork 后的真实地址即可通过 GitHub Raw 直连更新。

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "adblock-pro",
        "type": "remote",
        "format": "binary",
        "url": "[https://raw.githubusercontent.com/你的GitHub用户名/你的仓库名/main/rules/full.srs](https://raw.githubusercontent.com/你的GitHub用户名/你的仓库名/main/rules/full.srs)",
        "download_detour": "direct",
        "update_interval": "1d"
      }
    ],
    "rules": [
      {
        "rule_set": "adblock-pro",
        "action": "reject"
      }
    ]
  }
}
