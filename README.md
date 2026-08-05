# singbox-adguard-rules

每日自动同步上游广告规则，合并去重后编译为 sing-box 规则集（`.srs`），直接订阅即可拦截广告。

## 使用

把下面的 `rule_set` 加进 sing-box 配置，并在 `rules` 中引用它：

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

可选规则集：

| tag | URL 后缀 | 内容 |
|---|---|---|
| `combined` | `merged/combined/combined.srs` | AdGuard + hosts 合并去重（推荐） |
| `adguard` | `merged/adguard/adguard.srs` | 仅 AdGuard 语法 |
| `hosts` | `merged/hosts/hosts.srs` | 仅 hosts 语法 |

URL 前缀统一为 `https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/`。单源规则集在 `converted/adguard/<源名>.srs`（源名见 `sources.json`）。

## 自动更新

- 每天北京时间 10:00 自动同步并重新编译
- 手动触发：仓库 Actions 页面 → 运行 workflow
- **更换广告源**：编辑 `sources.json`（加/删/改 URL 与类型）→ push → 自动完成下载、转换、编译、提交

## 本地验证

```bash
python3 -m unittest discover -s tests
```
