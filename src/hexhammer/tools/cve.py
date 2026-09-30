"""CVE 情报聚合工具:被动查询,零目标接触——漏洞复现流水线的第一环。

源(免费无 Key):
- NVD API 2.0:描述 / CVSS / 受影响版本(CPE)/ 参考链接;
- PoC-in-GitHub(nomi-sec,按年份目录的 raw JSON):公开 PoC 仓库清单。

单源失败不拖垮整体。复现方法论在 resources/skills/cve-repro(挂载技能)。
"""

from __future__ import annotations

import json
import re
from typing import ClassVar

import httpx

from .attack import _request
from .base import ToolContext, ToolError

_CVE_RE = re.compile(r"^(?:cve-)?(\d{4})-(\d{4,})$", re.IGNORECASE)


def _normalize_cve(query: str) -> str:
    match = _CVE_RE.match(query.strip())
    if not match:
        raise ToolError(
            f"CVE 编号形状不对:{query!r}(期望 CVE-2021-44228 或 2021-44228)"
        )
    return f"CVE-{match.group(1)}-{match.group(2)}"


def _parse_nvd(body: str) -> list[str]:
    """NVD 2.0 响应 → 紧凑行(描述/CVSS/受影响/参考)。"""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ["[NVD 响应非 JSON]"]
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return ["[NVD 无记录]"]
    cve = vulns[0].get("cve", {})

    lines: list[str] = []
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    if desc:
        lines.append(f"描述:{desc[:600]}")

    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            score = metrics[key][0].get("cvssData", {})
            lines.append(
                f"CVSS:{score.get('baseScore', '?')} {score.get('severity', '?')} "
                f"({score.get('vectorString', '?')})"
            )
            break

    affected: list[str] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                criteria = cpe.get("criteria", "")
                parts = criteria.split(":")
                label = ":".join(parts[2:6]) if len(parts) >= 6 else criteria
                rng = " ".join(
                    f"{k}={cpe[k]}"
                    for k in ("versionStartIncluding", "versionEndExcluding",
                              "versionEndIncluding")
                    if k in cpe
                )
                affected.append(label + (f" ({rng})" if rng else ""))
    if affected:
        lines.append("受影响(截前 8):")
        lines.extend(f"  - {a}" for a in affected[:8])

    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
    if refs:
        lines.append(f"参考({len(refs)} 条,截前 10):")
        lines.extend(f"  - {r}" for r in refs[:10])
    return lines


def _parse_poc_list(body: str) -> list[str]:
    """PoC-in-GitHub JSON → 仓库行(星标排序,截前 8)。"""
    try:
        rows = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ["[PoC 索引响应非 JSON]"]
    if not isinstance(rows, list) or not rows:
        return []
    repos = sorted(
        rows, key=lambda r: r.get("stargazers_count", 0), reverse=True
    )[:8]
    lines = [f"共 {len(rows)} 个 PoC 仓库(按星标,截前 8):"]
    for r in repos:
        lines.append(
            f"- {r.get('full_name', '?')} ★{r.get('stargazers_count', 0)} "
            f"pushed {str(r.get('pushed_at', '?'))[:10]} → {r.get('html_url', '')}"
        )
    return lines


class CveTool:
    name = "cve"
    description = (
        "CVE intelligence aggregator (passive; queries NVD + PoC-in-GitHub, never "
        "the target). Input a CVE id (e.g. CVE-2021-44228) → description, CVSS, "
        "affected versions, references, public PoC repos. First step of "
        "vulnerability reproduction; follow with the cve-repro skill."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "CVE id"},
            "sources": {
                "type": "array",
                "items": {"type": "string", "enum": ["nvd", "poc"]},
                "description": "subset (default: both)",
            },
        },
        "required": ["query"],
    }

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def execute(self, args: dict, ctx: ToolContext) -> str:
        cve = _normalize_cve(str(args["query"]))
        wanted = set(args.get("sources") or ())
        year = cve.split("-")[1]

        sections: list[tuple[str, str, object]] = []
        if not wanted or "nvd" in wanted:
            sections.append(
                ("nvd",
                 f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
                 _parse_nvd),
            )
        if not wanted or "poc" in wanted:
            poc_url = (
                f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub"
                f"/master/{year}/{cve}.json"
            )
            sections.append(("poc", poc_url, _parse_poc_list))

        lines = [f"# {cve} 情报(被动查询,未触碰目标)"]
        errors: list[str] = []
        for source, url, parser in sections:
            try:
                status, _, body = _request(
                    "GET", url, timeout=25.0, verify=False,
                    transport=self._transport,
                )
            except ToolError as exc:
                errors.append(f"{source}: {str(exc)[:60]}")
                continue
            if status == 404:
                if source == "poc":
                    lines.append("## PoC-in-GitHub:无收录")
                else:
                    lines.append("## NVD:无记录(HTTP 404)")
                continue
            if status != 200:
                errors.append(f"{source}: HTTP {status}")
                continue
            parsed = parser(body)
            if parsed:
                lines.append(f"## {'NVD' if source == 'nvd' else 'PoC-in-GitHub'}")
                lines.extend(parsed)
        if errors:
            lines.append("## 失败源")
            lines.extend(f"[!] {e}" for e in errors)
        lines.append(
            "## 复现建议\n"
            "优先 PoC 仓库自带靶(docker-compose);无则按受影响组件+版本找 vulhub;"
            "靶只起 127.0.0.1,PoC 代码先读再跑;复现证据(请求+响应)用 finding 落账,"
            "完成即 docker compose down。方法论见 cve-repro 技能。"
        )
        return "\n".join(lines)
