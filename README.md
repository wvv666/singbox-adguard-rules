# singbox-adguard-rules

每日自动同步上游广告规则，合并去重后编译为 sing-box 规则集（`.srs`）。

所有链接前缀：`https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/`

## 合并规则集

| 规则集 | 说明 | 引用链接 |
|---|---|---|
| `combined` | AdGuard 语法 + hosts 语法全部合并去重（最全，推荐） | [combined.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/combined/combined.srs) |
| `adguard` | 仅 AdGuard 语法源，合并去重 | [adguard.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/adguard/adguard.srs) |
| `hosts` | 仅 hosts 格式源，合并去重 | [hosts.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/merged/hosts/hosts.srs) |

## 单源规则集

源清单见 [`sources.json`](sources.json)，每个源独立编译，可单独订阅：

| 规则集 | 来源 | 说明 | 引用链接 |
|---|---|---|---|
| `217heidai-adblockdns` | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | 汇总 16+ 上游的 AdGuard DNS 去广告规则 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/217heidai-adblockdns.srs) |
| `GOODBYEADS-dns` | [8680/GOODBYEADS](https://github.com/8680/GOODBYEADS) | DNS 级广告拦截 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/GOODBYEADS-dns.srs) |
| `anti-ad-adguard` | [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) | 国内广告域名拦截（AdGuard 格式） | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/anti-ad-adguard.srs) |
| `qq5460168-dns` | [qq5460168/666](https://github.com/qq5460168/666) | 多格式去广告（AdGuard DNS 格式） | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/qq5460168-dns.srs) |
| `10007-adb` | [lingeringsound/10007](https://github.com/lingeringsound/10007) | ADB 广告拦截（AdGuard 格式） | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/10007-adb.srs) |
| `GOODBYEADS-allow` | [8680/GOODBYEADS](https://github.com/8680/GOODBYEADS) | 白名单例外（放行列表，配合拦截规则使用） | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/adguard/GOODBYEADS-allow.srs) |
| `10007-all` | [lingeringsound/10007](https://github.com/lingeringsound/10007) | hosts 格式全量拦截 | [.srs](https://raw.githubusercontent.com/wvv666/singbox-adguard-rules/main/work/out/converted/hosts/10007-all.srs) |

## 使用

把上表任一链接填入 sing-box `route.rule_set[].url`（`type: "remote"`, `format: "binary"`），在 `route.rules` 里用对应 tag 引用即可。完整示例见 [sing-box 官方文档](https://sing-box.sagernet.org/configuration/rule-set/)。

## 更新

- 每天北京时间 10:00 自动同步并重新编译
- 更换广告源：编辑 `sources.json`（加/删/改 URL 与 type）→ push → 自动完成下载、转换、编译、提交
