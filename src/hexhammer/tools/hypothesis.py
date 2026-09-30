"""假设-验证循环工具:引擎的"创造性突破"框架。

面对未知目标/架构/防御时,"创造力"的工程化等价物 = **系统化假设-验证循环**:
观察 → 生成 N 个假设(类比已知/协议矩阵/边界行为)→ 按信息量/成本排序
→ 最小验证 → 证据更新 → 迭代直到破局或穷尽。

动作:
- add:记录假设(text/verify/cost),落盘 workspace/hypotheses.jsonl;
- resolve:标记 confirmed/refuted/inconclusive + 证据;
- list:当前假设树(open/confirmed/refuted 分组)。

这不是"灵感替代品",是"让每个猜想都被记录、验证、淘汰的纪律"——
灵感仍然来自模型,但不会丢失在上下文膨胀中。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import ClassVar

from .base import ToolContext, ToolError, resolve_in_workspace

STATE_FILE = "hypotheses.jsonl"
_STATUSES = ("open", "confirmed", "refuted", "inconclusive")
_COSTS = ("low", "medium", "high")


def _load(ws: Path) -> list[dict]:
    path = ws / STATE_FILE
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows


def _save(ws: Path, rows: list[dict]) -> None:
    path = ws / STATE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
    )


class HypothesisTool:
    name = "hypothesis"
    description = (
        "Hypothesis-driven exploration tracker. When facing an unknown service/"
        "architecture/defense, record testable hypotheses (add), verify them "
        "(resolve with evidence), and review the tree (list). This is the "
        "'creative breakthrough' framework: observation → N hypotheses → "
        "rank by information/cost → minimal test → update → iterate."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["add", "resolve", "list"],
            },
            "text": {"type": "string", "description": "add: 假设描述(可测试的一句)"},
            "verify": {"type": "string", "description": "add: 验证方式(一发探测/一条命令)"},
            "cost": {
                "type": "string",
                "enum": ["low", "medium", "high"],
                "description": "add: 验证成本(默认 low)",
            },
            "id": {"type": "integer", "description": "resolve: 假设序号"},
            "status": {
                "type": "string",
                "enum": ["confirmed", "refuted", "inconclusive"],
            },
            "evidence": {"type": "string", "description": "resolve: 证据摘录"},
        },
        "required": ["action"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        action = args["action"]
        if action == "add":
            return self._add(args, ctx)
        if action == "resolve":
            return self._resolve(args, ctx)
        if action == "list":
            return self._list(ctx)
        raise ToolError(f"unknown action {action!r}")

    def _add(self, args: dict, ctx: ToolContext) -> str:
        text = str(args.get("text") or "").strip()
        verify = str(args.get("verify") or "").strip()
        cost = str(args.get("cost") or "low")
        if not text or not verify:
            raise ToolError("add 需要 text(假设描述)+ verify(验证方式)")
        if cost not in _COSTS:
            raise ToolError(f"cost 必须是 {'/'.join(_COSTS)}")

        rows = _load(ctx.workspace)
        entry = {
            "id": len(rows) + 1,
            "text": text[:500],
            "verify": verify[:500],
            "cost": cost,
            "status": "open",
            "evidence": "",
            "ts": round(time.time(), 3),
        }
        rows.append(entry)
        _save(ctx.workspace, rows)
        return (
            f"假设 #{entry['id']} 已记录:{text[:80]}\n"
            f"验证:{verify[:80]}(成本:{cost})\n"
            f"提示:接下来立即执行 verify 所述的最小验证,然后 resolve 带证据。"
        )

    def _resolve(self, args: dict, ctx: ToolContext) -> str:
        hid = int(args.get("id") or 0)
        status = str(args.get("status") or "")
        evidence = str(args.get("evidence") or "").strip()
        if not hid:
            raise ToolError("resolve 需要 id(假设序号)")
        if status not in ("confirmed", "refuted", "inconclusive"):
            raise ToolError("status 必须是 confirmed/refuted/inconclusive")
        if not evidence:
            raise ToolError("resolve 需要 evidence(探测/命令的输出摘录)")

        rows = _load(ctx.workspace)
        for row in rows:
            if row.get("id") == hid:
                row["status"] = status
                row["evidence"] = evidence[:800]
                _save(ctx.workspace, rows)
                mark = {"confirmed": "✓", "refuted": "✗", "inconclusive": "?"}[status]
                return f"假设 #{hid} {mark} {status}:{row['text'][:60]}\n证据:{evidence[:120]}"
        raise ToolError(f"假设 #{hid} 不存在(共 {len(rows)} 条)")

    def _list(self, ctx: ToolContext) -> str:
        rows = _load(ctx.workspace)
        if not rows:
            return "无假设记录。面对未知目标时,先 add 至少 3 个(类比已知/协议矩阵/边界行为)"
        groups: dict[str, list[dict]] = {"open": [], "confirmed": [], "refuted": [], "inconclusive": []}
        for row in rows:
            groups.get(row.get("status", "open"), groups["open"]).append(row)

        lines: list[str] = []
        for status in ("open", "confirmed", "refuted", "inconclusive"):
            group = groups[status]
            if not group:
                continue
            mark = {"open": "○", "confirmed": "✓", "refuted": "✗", "inconclusive": "?"}[status]
            lines.append(f"## {mark} {status}({len(group)})")
            for row in group:
                cost_tag = f" [{row.get('cost', '?')}]" if row.get("cost") else ""
                lines.append(f"  #{row['id']}{cost_tag} {row['text'][:80]}")
                if row.get("evidence"):
                    lines.append(f"    证据:{row['evidence'][:100]}")
        # 探索度统计
        total = len(rows)
        resolved = total - len(groups["open"])
        lines.append(
            f"\n探索度:{resolved}/{total} 已验证"
            + (f"({len(groups['confirmed'])} 确认/{len(groups['refuted'])} 排除)"
               if resolved else "(全部 open——先验证 cost=low 的)")
        )
        return "\n".join(lines)
