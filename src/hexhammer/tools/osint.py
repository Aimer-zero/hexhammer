"""OSINT 多源工具:被动情报,零目标接触。

来源:2026-09-21 真机 engagement——8443 域名狩猎只配了 crt.sh 单源,
死路即终点。本工具把免费无 Key 源合成一条命令:

- HackerTarget reverse IP(IP→同 IP 主机名,免 Key 限量);
- RapidDNS sameip(IP→同 IP 主机名,HTML);
- crt.sh(证书透明:域名的子域枚举;按 IP 查通常为空——实测);
- Wayback CDX(历史 URL:域名的历史抓取)。

按输入自动选源(IP→反查系;域名→证书/历史系),单源失败不拖垮整体,
输出合并去重 + 每条溯源。查询对象是情报服务,**不是目标本身**——
封禁退避判据不适用于本工具(这正是退避指路的"被动路线")。
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from collections.abc import Callable
from typing import ClassVar

import httpx

from .attack import _request
from .base import ToolContext, ToolError

# 服务自身域名 + 结果页常见的第三方样板(CDN/统计/社交):含其子域剔除。
# 清单来源:2026-09-21 实弹验证的污染观察。
_BOILERPLATE = {
    "hackertarget.com", "rapiddns.io", "crt.sh", "web.archive.org", "archive.org",
    "fonts.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "google.com", "schema.org", "w3.org", "www.w3.org", "twitter.com",
    "googlesyndication.com", "hackerone.com", "unpkg.com",
}
# 常用 TLD 白名单:防把 jquery-2.2.4.min.js / document.getElementById 这类
# 页面资源名误判为主机名(2026-09-21 实弹验证抓到的污染)。刻意不含 .js。
_TLDS = {
    "com", "net", "org", "cn", "com.cn", "net.cn", "org.cn", "gov", "edu",
    "io", "ai", "dev", "app", "co", "me", "sh", "top", "xyz", "site", "online",
    "shop", "cloud", "info", "biz", "name", "pro", "tech", "cc", "tv", "fm",
    "in", "us", "uk", "de", "jp", "kr", "ru", "hk", "tw", "sg", "vn", "th",
    "au", "ca", "br", "fr", "it", "es", "nl", "se", "ch", "vip", "club",
}
_HOST_RE = re.compile(r"(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,24}")
_RAPIDDNS_SUBDOMAIN_HREF = re.compile(r'href="/subdomain/([^"]+)"')


def _is_host(candidate: str, exclude: str) -> bool:
    low = candidate.lower()
    tld = low.rsplit(".", 1)[-1]
    if tld not in _TLDS:
        return False
    if low == exclude.lower():
        return False
    # 样板域名本体或其子域(blog.rapiddns.io)都剔除
    for boiler in _BOILERPLATE:
        if low == boiler or low.endswith("." + boiler):
            return False
    return True


def _looks_like_ip(query: str) -> bool:
    try:
        ipaddress.ip_address(query)
        return True
    except ValueError:
        return False


def _hosts_from_text(text: str, exclude: str) -> list[str]:
    found = {h for h in _HOST_RE.findall(text) if _is_host(h, exclude)}
    return sorted(found)


def _parse_hackertarget(body: str, exclude: str) -> list[str]:
    lowered = body.lower()
    if "error" in lowered or "no record" in lowered or "invalid" in lowered:
        return []
    return _hosts_from_text(body, exclude)


def _parse_rapiddns(body: str, exclude: str) -> list[str]:
    """优先解析表格列(/subdomain/ 链接);空表退回通用正则(已被 TLD 白名单净化)。"""
    precise = {
        h for h in _RAPIDDNS_SUBDOMAIN_HREF.findall(body)
        if _is_host(h, exclude)
    }
    if precise:
        return sorted(precise)
    return _hosts_from_text(body, exclude)


def _parse_crtsh_json(body: str, exclude: str) -> list[str]:
    try:
        rows = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []  # crt.sh 偶发 502/HTML 错误页,由外层记录 HTTP 状态
    names: set[str] = set()
    for row in rows:
        value = row.get("name_value", "") if isinstance(row, dict) else ""
        for name in str(value).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name and _is_host(name, exclude):
                names.add(name)
    return sorted(names)


def _parse_cdx_json(body: str, exclude: str) -> list[str]:
    try:
        rows = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    names: set[str] = set()
    for row in rows[1:]:  # 首行是表头
        if len(row) >= 3:
            host = urllib.parse.urlsplit(str(row[2])).hostname
            if host and _is_host(host, exclude):
                names.add(host.lower())
    return sorted(names)


class OsintTool:
    name = "osint"
    description = (
        "Passive multi-source OSINT (queries intel services, never the target). "
        "Input an IP (reverse-IP hostnames via HackerTarget/RapidDNS + Wayback) "
        "or a domain (subdomains via crt.sh + Wayback history). Returns merged "
        "candidate hostnames with source attribution. Use for vhost/SNI hunting."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "IP or domain"},
            "sources": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["hackertarget", "rapiddns", "crtsh", "wayback"],
                },
                "description": "subset of sources (default: auto by query type)",
            },
        },
        "required": ["query"],
    }

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def _plan(self, query: str) -> list[tuple[str, str, Callable[[str, str], list[str]]]]:
        if _looks_like_ip(query):
            return [
                ("hackertarget",
                 f"https://api.hackertarget.com/reverseiplookup/?q={query}",
                 _parse_hackertarget),
                ("rapiddns",
                 f"https://rapiddns.io/sameip/{query}?full=1",
                 _parse_rapiddns),
                ("crtsh",
                 f"https://crt.sh/?q={query}&output=json",
                 _parse_crtsh_json),
                ("wayback",
                 (f"http://web.archive.org/cdx/search/cdx"
                  f"?url={query}/*&output=json&limit=100&collapse=urlkey"),
                 _parse_cdx_json),
            ]
        return [
            ("crtsh",
             f"https://crt.sh/?q=%.{query}&output=json",
             _parse_crtsh_json),
            ("wayback",
             (f"http://web.archive.org/cdx/search/cdx"
              f"?url=*.{query}/*&output=json&limit=200&collapse=urlkey"),
             _parse_cdx_json),
        ]

    def execute(self, args: dict, ctx: ToolContext) -> str:
        query = str(args["query"]).strip()
        if not query:
            raise ToolError("query 为空")
        wanted = set(args.get("sources") or [])
        merged: dict[str, set[str]] = {}
        errors: list[str] = []
        for source, url, parser in self._plan(query):
            if wanted and source not in wanted:
                continue
            try:
                status, _, body = _request(
                    "GET", url, timeout=25.0, verify=False,
                    transport=self._transport,
                )
            except ToolError as exc:
                errors.append(f"{source}: {str(exc)[:60]}")
                continue
            if status != 200:
                errors.append(f"{source}: HTTP {status}")
                continue
            names = parser(body, query)
            if names:
                merged.setdefault(source, set()).update(names)

        lines = [f"# OSINT 候选(query={query},被动查询,未触碰目标)"]
        all_names: set[str] = set()
        for source, names in merged.items():
            lines.append(f"## {source}({len(names)})")
            lines.extend(f"- {n}" for n in sorted(names))
            all_names.update(names)
        if errors:
            lines.append("## 失败源")
            lines.extend(f"[!] {e}" for e in errors)
        if all_names:
            lines.append(
                f"## 合并去重({len(all_names)}):{', '.join(sorted(all_names))}\n"
                "提示:候选域名可用于 SNI 探测(openssl s_client -servername <域名> "
                "直连目标 TLS 口),或作为后续主动侦察的范围。"
            )
        else:
            lines.append("## 无候选。换源(需账号的 FOFA/ZoomEye 属于更强路线)或接受阴性格局。")
        return "\n".join(lines)
