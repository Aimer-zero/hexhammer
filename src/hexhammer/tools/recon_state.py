"""目标状态跟踪:端口状态转移检测 + 封禁退避判据。

来源:2026-09-21 真机 engagement 三次现场证明——引擎对"端口被动态黑洞化"
毫无感知,继续对黑洞扫描,烧 token 烧时间且加固封锁。判据:

- 端口状态转移:某端口先记录过 open,随后 error/filtered(带时间戳)→ 1 分;
- 连续错误:该主机存在过 open 的前提下,连续 error ≥ streak_limit → 触发。

触发后,Http/Nmap 工具在执行前直接拒绝并给出退避指引(exit-75 语义):
停止主动探测、把"防护存在"记为发现、转被动 OSINT 或等待窗口。状态档案
recon-state.jsonl 落在工作区,天然满足"侦察结论时效性"(改进 #3)。
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .base import ToolError

STATE_FILE = "recon-state.jsonl"

# 超过该年龄的侦察结论视为过期:引用前必须复核(改进 #2 复核纪律的读取侧)。
STALE_AFTER_S = 3600.0

BLOCK_GUIDANCE = (
    "检测到目标 {host} 疑似对源 IP 启动了动态封禁(证据:{evidence})。"
    "继续主动探测只会加固封锁。按纪律执行:1) 停止对该主机的主动扫描;"
    "2) 『防护存在/端口黑洞化』已自动记为 finding(这本身是有价值的情报);"
    "3) 转被动路线(OSINT/换视界点)或收尾报告,不要原样重试。"
)


def _age_str(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 48 * 3600:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


class ReconState:
    """每工作区一份;线程内串行使用(solver 单线程驱动工具)。"""

    def __init__(self, workspace: Path) -> None:
        self.path = Path(workspace) / STATE_FILE
        self._records: list[dict] = []
        self._load()

    def _load(self) -> None:
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    self._records.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue

    def record(self, host: str, port: int | None, state: str) -> None:
        entry = {
            "ts": round(time.time(), 3),
            "host": host,
            "port": port,
            "state": state,
        }
        self._records.append(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def records_for(self, host: str) -> list[dict]:
        return [r for r in self._records if r["host"] == host]

    def transitions(self, host: str) -> list[str]:
        """open 之后同端口出现 error/filtered = 一次转移。"""
        by_port: dict[int, list[str]] = {}
        for r in self.records_for(host):
            if r["port"] is None:
                continue
            by_port.setdefault(r["port"], []).append(r["state"])
        hits = []
        for port, states in by_port.items():
            seen_open = False
            for s in states:
                if s == "open":
                    seen_open = True
                elif seen_open and s in ("error", "filtered"):
                    hits.append(f"{port}/tcp open→{s}")
                    break
        return hits

    def error_streak(self, host: str) -> int:
        """尾部连续 error/filtered 计数(主机须曾有过 open)。"""
        records = self.records_for(host)
        had_open = any(r["state"] == "open" for r in records)
        if not had_open:
            return 0
        streak = 0
        for r in reversed(records):
            if r["state"] in ("error", "filtered"):
                streak += 1
            else:
                break
        return streak

    def verdict(self, host: str) -> str:
        """空串=放行;非空=退避指引(工具层在执行前拒绝)。"""
        parts = self._evidence(host)
        if not parts:
            return ""
        return BLOCK_GUIDANCE.format(host=host, evidence=", ".join(parts))

    def _evidence(self, host: str) -> list[str]:
        """命中退避判据时返回证据行;未命中返回空。"""
        hits = self.transitions(host)
        streak = self.error_streak(host)
        if len(hits) < 2 and streak < 3:
            return []
        return hits + ([f"连续错误 ×{streak}"] if streak >= 3 else [])

    def snapshot(self, host: str, now: float | None = None) -> str:
        """该主机每端口最后状态 + 年龄(时效性读取侧);过期打复核标记。"""
        now = time.time() if now is None else now
        latest: dict[int, dict] = {}
        for r in self.records_for(host):
            if r.get("port") is not None:
                latest[r["port"]] = r  # 后写覆盖:每端口只留最后状态
        if not latest:
            return ""
        parts = []
        for port in sorted(latest):
            r = latest[port]
            age = now - r["ts"]
            mark = " ⚠过期,引用前复核" if age > STALE_AFTER_S else ""
            parts.append(f"{port}/tcp {r['state']}({_age_str(age)}前{mark})")
        return " · ".join(parts)

    def enforce(self, host: str) -> None:
        """工具层统一入口:判据命中 → 自动落 finding + 抛退避指引。

        finding 自动化(不依赖模型自觉执行指引);按 title 幂等,重复
        拦截不重复落账。清白时零开销,不触碰 flags.json。
        """
        parts = self._evidence(host)
        if not parts:
            return
        from ..inbox import FindingsInbox

        inbox = FindingsInbox(self.path.parent / "flags.json")
        inbox.add_finding(
            f"目标 {host} 存在动态封禁/反扫描防护(端口黑洞化)",
            evidence=f"状态转移证据:{', '.join(parts)}(全量见 recon-state.jsonl)",
            severity="medium",
            kind="info",
        )
        raise ToolError(BLOCK_GUIDANCE.format(host=host, evidence=", ".join(parts)))
