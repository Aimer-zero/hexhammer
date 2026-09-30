"""武器研发工具:补丁差分研究链的机械部分(模型做研究,工具保证正确)。

通路(2026-09-29 实测,热点网络):api.github.com 直连可用(60 req/h 无 token),
raw.githubusercontent 可用;github 主站与 ghfast 代理的 .patch 不可用。

动作:
- gh_search:GitHub 仓库搜索(PoC/武器仓定位,星标排序);
- readme:读仓库 README(PoC 仓库 README 常含上游修复 commit 链接触发细节);
- patch:给定 github commit URL,经 API 拉统一 diff(Accept:/vnd.github.diff);
- save:武器条目入库 resources/weapon/library.jsonl(按 CVE 幂等;
  verified 状态强制:unverified / local-verified,后者必须带证据)。

武器 vs 经验库:经验条目=打法知识(LOCK/CONFIRMED);武器条目=具体漏洞的
可执行利用件(root_cause/trigger/poc),是 CVE 复现闭环的沉淀侧。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import ClassVar

import httpx

from .base import ToolContext, ToolError

_API = "https://api.github.com"
_MAX_DIFF_CHARS = 12000
_COMMIT_URL = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")

_WEAPON_DIR = Path(__file__).resolve().parents[2] / "resources" / "weapon"
_WEAPON_FILE = "library.jsonl"

_VERIFIED_STATES = ("unverified", "local-verified")


def weapon_library_path() -> Path:
    return _WEAPON_DIR / _WEAPON_FILE


def _api_get(path: str, accept: str, transport) -> tuple[int, str]:
    try:
        client = httpx.Client(timeout=20.0, transport=transport, follow_redirects=True)
        try:
            response = client.get(
                _API + path, headers={"Accept": accept, "User-Agent": "sapper-weapon"}
            )
        finally:
            client.close()
    except httpx.HTTPError as exc:
        raise ToolError(f"github api: {type(exc).__name__}: {exc}") from exc
    return response.status_code, response.text


class WeaponTool:
    name = "weapon"
    description = (
        "Vulnerability weapon-research toolkit (GitHub API based, passive). "
        "gh_search: find PoC/exploit repos for a CVE (star sorted). readme: read a "
        "repo README (often contains upstream fix commit URL + trigger details). "
        "patch: fetch the unified diff of an upstream fix commit "
        "(github.com/o/r/commit/<sha> URL in, diff out) — the core of patch-diff "
        "root-cause research. save: record a weapon entry (cve/root_cause/trigger/"
        "poc/verified) into the weapon library; local-verified requires evidence."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["gh_search", "readme", "patch", "save"],
            },
            "query": {"type": "string", "description": "gh_search: search query"},
            "repo": {"type": "string", "description": "readme: owner/name"},
            "commit_url": {
                "type": "string",
                "description": "patch: full github commit URL",
            },
            "cve": {"type": "string", "description": "save: CVE id"},
            "root_cause": {"type": "string", "description": "save: 根因(来自补丁差分)"},
            "trigger": {"type": "string", "description": "save: 触发条件"},
            "poc": {"type": "string", "description": "save: 可执行 PoC(请求/命令)"},
            "verified": {
                "type": "string",
                "enum": ["unverified", "local-verified"],
                "description": "save: 验证状态;local-verified 必须 evidence 非空",
            },
            "evidence": {"type": "string", "description": "save: 验证证据(靶输出摘录)"},
        },
        "required": ["action"],
    }

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def execute(self, args: dict, ctx: ToolContext) -> str:
        action = args["action"]
        if action == "gh_search":
            return self._search(str(args.get("query") or ""))
        if action == "readme":
            return self._readme(str(args.get("repo") or ""))
        if action == "patch":
            return self._patch(str(args.get("commit_url") or ""))
        if action == "save":
            return self._save(args)
        raise ToolError(f"unknown action {action!r}")

    # ---- GitHub API 动作

    def _search(self, query: str) -> str:
        if not query:
            raise ToolError("gh_search 需要 query")
        from urllib.parse import quote

        status, body = _api_get(
            f"/search/repositories?q={quote(query)}&sort=stars&per_page=8",
            "application/vnd.github+json",
            self._transport,
        )
        if status == 403:
            return "GitHub API 限流(60/h 无 token):稍后再试或直接用已知仓库名 readme"
        if status != 200:
            return f"HTTP {status}: {body[:200]}"
        rows = json.loads(body).get("items", [])
        if not rows:
            return "无结果仓库"
        lines = [f"共命中 {len(rows)} 个仓库(星标排序):"]
        for r in rows[:8]:
            lines.append(
                f"- {r['full_name']} ★{r['stargazers_count']} "
                f"pushed {str(r.get('pushed_at', ''))[:10]} {(r.get('description') or '')[:70]}"
            )
        return "\n".join(lines)

    def _readme(self, repo: str) -> str:
        if "/" not in repo:
            raise ToolError(f"repo 形如 owner/name,得到 {repo!r}")
        status, body = _api_get(
            f"/repos/{repo}/readme", "application/vnd.github.raw", self._transport
        )
        if status != 200:
            return f"HTTP {status}: {body[:200]}"
        import base64

        try:  # raw accept 直接给文本;兜底 json(base64)形态
            payload = json.loads(body)
            text = base64.b64decode(payload.get("content", "")).decode(
                "utf-8", errors="replace"
            )
        except (json.JSONDecodeError, ValueError):
            text = body
        return text[:8000]

    def _patch(self, commit_url: str) -> str:
        match = _COMMIT_URL.search(commit_url)
        if not match:
            raise ToolError(
                f"commit_url 形如 https://github.com/owner/repo/commit/<sha>,得到 {commit_url!r}"
            )
        owner, repo, sha = match.groups()
        status, body = _api_get(
            f"/repos/{owner}/{repo}/commits/{sha}",
            "application/vnd.github.diff",
            self._transport,
        )
        if status != 200:
            return f"HTTP {status}: {body[:200]}"
        head, _, tail = body.partition("\ndiff --git")
        head_txt = head[:400]
        diff = ("diff --git" + tail) if tail else body
        if len(diff) > _MAX_DIFF_CHARS:
            diff = diff[:_MAX_DIFF_CHARS] + f"\n...(截断,全量 {len(body)} 字符)"
        return f"# commit\n{head_txt}\n\n# diff\n{diff}"

    # ---- 武器入库

    def _save(self, args: dict) -> str:
        cve = str(args.get("cve") or "").strip()
        root_cause = str(args.get("root_cause") or "").strip()
        trigger = str(args.get("trigger") or "").strip()
        poc = str(args.get("poc") or "").strip()
        verified = str(args.get("verified") or "unverified")
        evidence = str(args.get("evidence") or "").strip()
        if not (cve and root_cause and trigger and poc):
            raise ToolError("save 需要 cve/root_cause/trigger/poc(缺一不可——半成品不入库)")
        if verified not in _VERIFIED_STATES:
            raise ToolError(f"verified 必须是 {'/'.join(_VERIFIED_STATES)}")
        if verified == "local-verified" and not evidence:
            raise ToolError("local-verified 必须带 evidence(靶验证输出摘录)")

        path = weapon_library_path()
        entries: list[dict] = []
        if path.is_file():
            entries = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        if any(e.get("cve", "").upper() == cve.upper() for e in entries):
            return f"武器库已有 {cve} 条目(幂等跳过);当前共 {len(entries)} 条"

        entry = {
            "cve": cve.upper(),
            "root_cause": root_cause[:1500],
            "trigger": trigger[:600],
            "poc": poc[:3000],
            "verified": verified,
            "evidence": evidence[:1500],
            "ts": round(time.time(), 3),
        }
        entries.append(entry)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".jsonl.tmp")
        tmp.write_text(
            "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries),
            encoding="utf-8",
        )
        tmp.replace(path)
        return (
            f"武器入库成功:{cve}({verified})。库内共 {len(entries)} 条;"
            "研究闭环完成:根因(补丁差分)→触发→PoC→"
            + ("靶验证 ✓" if verified == "local-verified" else "未验证(建议本地靶验)")
        )
