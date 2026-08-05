#!/usr/bin/env python3
"""按 sources.json 源清单下载上游广告规则，带 HTML/WAF 污染检测。

用法: python3 scripts/download-sources.py [--sources sources.json] [--out work/sources]

污染检测：下载内容若含 HTML/WAF 拦截页签名（DOCTYPE/CloudWAF 等），
视为下载失败并报错退出，防止垃圾规则混入产物。
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# WAF/HTML 拦截页签名（部分命中即判污染）
POLLUTION_SIGNATURES = [
    r"<!DOCTYPE\s+html",
    r"<html[^>]*>",
    r"CloudWAF",
    r"访问被拦截",
    r"您的请求疑似攻击行为",
]


def is_polluted(text: str) -> bool:
    """下载内容是否像 WAF/HTML 拦截页。"""
    head = text[:8192].lower()  # 只看头部，规则正文不会以 HTML 开头
    return any(re.search(sig, head, re.IGNORECASE) for sig in POLLUTION_SIGNATURES)


MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024  # 64MB 响应大小上限

# 允许的源主机白名单（防 file:// 等非 https 或任意主机拉取）。
# 注意：禁重定向 + HTML 污染检测，仅 raw.githubusercontent.com 与
# lingeringsound.github.io 这类纯文本直链可用（github.com 网页会触发污染检测）。
ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "lingeringsound.github.io",
}


def _check_url(url: str) -> str:
    """校验下载 URL：强制 https + 主机白名单，返回规范化 URL。"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"非 https URL 拒绝下载: {url}")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"主机不在白名单（{sorted(ALLOWED_HOSTS)}）: {url}")
    if parsed.port is not None:
        raise ValueError(f"不允许非标准端口: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"不允许 URL 内嵌用户信息: {url}")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止跟随重定向：3xx 直接抛 HTTPError（防 302 到白名单外主机）。"""

    def redirect_request(self, *args, **kwargs):
        return None


def download(url: str, dest: Path, timeout: int = 60, retries: int = 3) -> None:
    """下载源文件，带重试与 HTML/WAF 污染检测。"""
    opener = urllib.request.build_opener(_NoRedirect)
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(_check_url(url),
                                         headers={"User-Agent": "singbox-adguard-rules/1.0"})
            with opener.open(req, timeout=timeout) as resp:
                final = resp.geturl()
                _check_url(final)  # 302/3xx 后校验最终 URL（若被跟随）
                body = resp.read(MAX_DOWNLOAD_BYTES + 1)
            if len(body) > MAX_DOWNLOAD_BYTES:
                raise RuntimeError(f"响应超过大小上限 {MAX_DOWNLOAD_BYTES / 1024 / 1024:.0f}MB")
            text = body.decode("utf-8", errors="replace")
            if is_polluted(text):
                raise RuntimeError(
                    f"下载内容疑似 WAF/HTML 拦截页: {url}\n"
                    f"头部预览: {text[:120]!r}\n"
                    "请检查源 URL 是否被防火墙拦截（可尝试换 raw 路径/镜像）")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            print(f"[OK]  {dest.name:32s} ({len(body) / 1024:.0f} KB)")
            return
        except (urllib.error.URLError, OSError, http.client.IncompleteRead) as e:
            # 网络类错误可重试
            last_err = e
            if attempt < retries - 1:
                delay = 2 * (attempt + 1)
                print(f"[WARN] 第 {attempt + 1} 次失败（{e}），{delay}s 后重试...", file=sys.stderr)
                time.sleep(delay)
        except RuntimeError as e:
            # 污染/超限等不可自愈错误：直接失败，不重试
            raise e
    raise last_err if last_err else RuntimeError("unknown download error")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sources", type=Path, default=Path("sources.json"))
    ap.add_argument("--out", type=Path, default=Path("work/sources"))
    args = ap.parse_args(argv)

    sources = json.loads(args.sources.read_text(encoding="utf-8"))
    if not isinstance(sources, list) or not sources:
        ap.error(f"{args.sources} 应为非空 JSON 数组")
    seen = set()
    for s in sources:
        name = s.get("name")
        url = s.get("url")
        kind = s.get("type", "adguard")
        if not name or not url or kind not in ("adguard", "hosts"):
            ap.error(f"无效的源条目: {s!r}（需要 name/url/type∈adguard|hosts）")
        if name in seen:
            ap.error(f"重复的源名: {name}")
        seen.add(name)

    failed = 0
    dests: dict[Path, str] = {}
    for s in sources:
        dest = args.out / s["type"] / f"{Path(str(s['name'])).name}.{'hosts' if s['type'] == 'hosts' else 'txt'}"
        prev = dests.setdefault(dest, s["name"])
        if prev != s["name"]:
            ap.error(
                f"源名 {prev!r} 与 {s['name']!r} 解析到同一目标 {dest}，"
                f"会互相覆盖，请改用不同的 name")
        try:
            download(s["url"], dest)
        except (urllib.error.URLError, RuntimeError, OSError,
                http.client.HTTPException, ValueError) as e:
            print(f"[ERR]  {s['name']}: {e}", file=sys.stderr)
            failed += 1
    if failed:
        print(f"::error::{failed} 个源下载失败", file=sys.stderr)
        sys.exit(1)
    print(f"All done: 全部 {len(sources)} 个源下载完成")


if __name__ == "__main__":
    main()
