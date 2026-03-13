# 🛡️ Sing-box 终极全能去广告规则库

本项目由 GitHub Actions 引擎全自动驱动，每日聚合 **19+** 个顶级开源规则源，经过极速去重、冲突检测与深度清洗，专为 **sing-box** 网络层代理编译优化。

> ⏱️ **最后数据更新**: {{ UPDATE_TIME }}

## 📊 实时数据看板

基于最新的上游数据源，本次构建成功生成了以下三个等级的规则集：

| 规则分级 | 适用场景 | 构建说明 | 最终有效规则数 |
| :--- | :--- | :--- | :---: |
| 🟢 **Lite (轻量版)** | 基础去广告，几乎无误杀 | 适合路由/网关全局拦截，含 EasyList 等基础源 | **{{ LITE_COUNT }}** |
| 🔵 **Full (推荐版)** | 日常主力，强力净化 | 包含 Lite + 隐私防追踪 + 恶意/钓鱼域名拦截 | **{{ FULL_COUNT }}** |
| 🔴 **Extreme (极限版)** | 零容忍拦截，可能有误杀 | 包含 Full + 实验性规则 + 激进拦截规则 | **{{ EXTREME_COUNT }}** |

*⚡ 智能引擎启动：本次构建自动应用全局白名单，成功化解了 **{{ CONFLICTS_RESOLVED }}** 处规则冲突，保障网络畅通。*

## 🚀 订阅与使用方法 (Sing-box)

请在你的 Sing-box 客户端配置文件 `config.json` 的 `route.rule_set` 部分，添加以下配置（以 Full 推荐版为例）：

```json
{
  "tag": "ad-block",
  "type": "remote",
  "format": "binary",
  "url": "[https://github.com/你的GitHub用户名/你的仓库名/releases/latest/download/full.srs](https://github.com/你的GitHub用户名/你的仓库名/releases/latest/download/full.srs)",
  "download_detour": "direct"
}
(注意：请将 url 中的用户名和仓库名替换为你自己的)
