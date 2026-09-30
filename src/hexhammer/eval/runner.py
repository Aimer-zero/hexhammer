"""A/B 运行器:同题集 × 工具变体(full / basic)对照,工具价值由数字证明。

变体:
- full:默认工具面(基础七件套 + 攻击工具包);
- basic:仅基础七件套(隔离攻击工具的边际贡献)。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from ..inbox import FindingsInbox
from ..llm.types import LLMClientProtocol, TokenLedger
from ..solver import SolverLoop
from ..tools import BashTool, Registry, default_registry
from ..tools.fs import default_fs_tools
from .golden import Challenge

EVAL_SYSTEM = (
    "你是 hexhammer 解题 agent,在授权测试工作区内完成任务。优先用可用工具,"
    "不要问问题。发现形如 flag{...} 的旗标时,让它出现在命令输出里即可。"
)


def basic_registry() -> Registry:
    registry = Registry()
    for tool in default_fs_tools():
        registry.register(tool)
    registry.register(BashTool())
    return registry


@dataclass
class SuiteResult:
    challenge: str
    variant: str
    solved: bool
    stop_reason: str
    turns: int
    redrives: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    wall_s: float


def run_suite(
    client_factory: Callable[[], tuple[LLMClientProtocol, TokenLedger]],
    challenges: list[Challenge],
    *,
    variant: str,
    root: Path,
    max_turns: int = 16,
    budget_s: float = 240.0,
    system_prompt: str | None = None,
) -> list[SuiteResult]:
    registry = default_registry() if variant == "full" else basic_registry()
    prompt = system_prompt or EVAL_SYSTEM
    results: list[SuiteResult] = []
    for challenge in challenges:
        ws = root / variant / challenge.id
        ws.mkdir(parents=True, exist_ok=True)
        ctx = challenge.setup(ws)
        try:
            goal = challenge.template.replace("__URL__", str(ctx.get("url", "")))
            client, ledger = client_factory()
            inbox = FindingsInbox(ws / "flags.json")
            loop = SolverLoop(
                client,
                registry,
                prompt,
                inbox=inbox,
                acceptance=lambda ch=challenge, w=ws, ib=inbox: ch.verify(w, ib),
                acceptance_status=lambda: "验收未通过",
                max_turns=max_turns,
                redrive_max=2,
            )
            t0 = time.monotonic()
            outcome = loop.run(goal, ws, deadline=time.monotonic() + budget_s)
            snapshot = ledger.snapshot()
            results.append(
                SuiteResult(
                    challenge=challenge.id,
                    variant=variant,
                    solved=challenge.verify(ws, inbox),  # 终局复核,不止依赖 stop_reason
                    stop_reason=outcome.stop_reason,
                    turns=outcome.turns,
                    redrives=outcome.redrives,
                    input_tokens=snapshot["input_tokens"],
                    output_tokens=snapshot["output_tokens"],
                    cache_read_tokens=snapshot["cache_read_tokens"],
                    wall_s=round(time.monotonic() - t0, 1),
                )
            )
        finally:
            challenge.teardown(ctx)
    return results


def format_report(results: list[SuiteResult]) -> str:
    header = (
        f"{'challenge':14} {'variant':7} {'solved':6} {'stop':10} "
        f"{'turns':5} {'rd':3} {'in_tok':8} {'out_tok':8} {'cache':8} {'wall_s':7}"
    )
    lines = [header, "-" * len(header)]
    for r in results:
        lines.append(
            f"{r.challenge:14} {r.variant:7} {r.solved!s:6} {r.stop_reason:10.10} "
            f"{r.turns:<5} {r.redrives:<3} {r.input_tokens:<8} {r.output_tokens:<8} "
            f"{r.cache_read_tokens:<8} {r.wall_s:<7}"
        )
    for variant in sorted({r.variant for r in results}):
        group = [r for r in results if r.variant == variant]
        solved = sum(1 for r in group if r.solved)
        lines.append(
            f"[{variant}] solved {solved}/{len(group)} | "
            f"turns {sum(r.turns for r in group)} | "
            f"in {sum(r.input_tokens for r in group)} out {sum(r.output_tokens for r in group)} | "
            f"wall {sum(r.wall_s for r in group):.0f}s"
        )
    return "\n".join(lines)


def results_as_dicts(results: list[SuiteResult]) -> list[dict]:
    return [asdict(r) for r in results]
