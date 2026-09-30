"""solver 循环:引擎的心跳。

职责边界(架构 §1):solver 只做工作记忆内的推理与工具调用;长程记忆在
文件系统(收件箱/覆盖图),平台交互在 adapter。循环自带三条保命机制:

1. **flag 刮取钩子**:每轮工具输出与模型文本都过一遍 flag 正则,发现即
   入收件箱——提交成功率与模型"记得写"解耦(铁律 2);
2. **until-acceptance 再驱动**:模型停了但验收未满足时,注入
   "Acceptance status: not met" 继续同会话(Heimdall until-flag 模式),
   指数退避,有次数上限;
3. **压缩**:ContextOverflowError 触发确定性压缩(保尾),M2 换 observer
   摘要式压缩。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..inbox.flags import FindingsInbox, extract_flags
from ..llm.types import (
    AssistantTurn,
    ContextOverflowError,
    Conversation,
    LLMClientProtocol,
    ToolResult,
)
from ..observer import Observer, evidence_window
from ..tools import Registry, ToolContext

# 压缩后的任务化保留清单(Heimdall 压缩指令同款):不是"总结一下",
# 而是点名必须幸存的信息与恢复动作。
COMPACT_NOTICE = (
    "(前文已压缩以适配窗口。保留清单——若下列任一不在当前会话,先从工作区文件"
    "恢复再行动:①任务目标与验收条件;②存活地址/有效凭证(见覆盖图 CONFIRMED/LOCK);"
    "③已证死路及其失败原因(勿重复);④下一步动作。"
    "关键证据在 notes.md / flags.json / tmp/ 下,重新读取后再继续。)"
)


@dataclass
class SolverOutcome:
    stop_reason: str  # acceptance / model_stop / max_turns / deadline
    turns: int = 0
    redrives: int = 0
    compactions: int = 0
    flags_found: list[str] = field(default_factory=list)
    error: str = ""
    conversation: Conversation | None = None  # 会话句柄:编排器持久化用


class SolverLoop:
    def __init__(
        self,
        client: LLMClientProtocol,
        registry: Registry,
        system_prompt: str,
        *,
        inbox: FindingsInbox | None = None,
        max_turns: int = 64,
        acceptance: Callable[[], bool] | None = None,
        acceptance_status: Callable[[], str] | None = None,
        redrive_max: int = 3,
        compact_keep_tail: int = 8,
        sleep: Callable[[float], None] = time.sleep,
        observer: Observer | None = None,
        observe_every: int = 0,
    ) -> None:
        self._client = client
        self._registry = registry
        self._system_prompt = system_prompt
        self._inbox = inbox
        self._max_turns = max_turns
        self._acceptance = acceptance
        self._acceptance_status = acceptance_status or (lambda: "not met")
        self._redrive_max = redrive_max
        self._compact_keep_tail = compact_keep_tail
        self._sleep = sleep
        # observer 外圈:observe_every>0 时,每 N 个工具轮注入一次覆盖图
        self._observer = observer
        self._observe_every = observe_every
        self._turns_since_observe = observe_every  # 首个工具轮即触发
        self._evidence_from = 0
        self._last_map: str | None = None

    def run(
        self,
        goal: str,
        workspace: Path,
        conversation: Conversation | None = None,
        deadline: float | None = None,
    ) -> SolverOutcome:
        """跑一轮求解。deadline 为 time.monotonic() 绝对时刻,到点止损。

        止损由编排层(Orchestrator)的 Pass Clock 决定;循环只认时刻,
        保证长扫描/慢模型都不会吃穿预算。
        """
        conversation = conversation or Conversation()
        if not conversation.items():
            conversation.add_user(goal)
        ctx = ToolContext(workspace=workspace)
        outcome = SolverOutcome(stop_reason="max_turns")

        while outcome.turns < self._max_turns:
            if deadline is not None and time.monotonic() > deadline:
                outcome.stop_reason = "deadline"
                outcome.conversation = conversation
                return outcome
            outcome.turns += 1
            try:
                response = self._client.chat(
                    self._system_prompt, conversation, self._registry.specs()
                )
            except ContextOverflowError:
                self._compact(conversation)
                outcome.compactions += 1
                continue

            conversation.add_assistant(response.turn)

            if response.turn.tool_calls:
                self._run_tools(response.turn, conversation, ctx, outcome)
                if self._acceptance is not None and self._acceptance():
                    outcome.stop_reason = "acceptance"
                    outcome.conversation = conversation
                    return outcome
                if self._observer is not None and self._observe_every > 0:
                    self._turns_since_observe += 1
                    if self._turns_since_observe >= self._observe_every:
                        self._maybe_observe(conversation, goal)
                continue

            # 模型停了(纯文本,无工具调用)
            self._scrape(response.turn.text, "assistant_text", outcome)
            if self._acceptance is not None:
                if self._acceptance():
                    outcome.stop_reason = "acceptance"
                    outcome.conversation = conversation
                    return outcome
                if outcome.redrives < self._redrive_max:
                    outcome.redrives += 1
                    self._sleep(min(30.0, 2.0**outcome.redrives))
                    conversation.add_user(
                        f"Acceptance status: {self._acceptance_status()}. "
                        "Continue from the current session's evidence; do not restart."
                    )
                    continue
            outcome.stop_reason = "model_stop"
            outcome.conversation = conversation
            return outcome

        outcome.conversation = conversation
        return outcome

    def _run_tools(
        self,
        turn: AssistantTurn,
        conversation: Conversation,
        ctx: ToolContext,
        outcome: SolverOutcome,
    ) -> None:
        for call in turn.tool_calls:
            content, is_error = self._registry.dispatch(call.name, call.arguments, ctx)
            conversation.add_tool(
                ToolResult(tool_call_id=call.id, content=content, is_error=is_error)
            )
            self._scrape(content, f"tool:{call.name}", outcome)

    def _scrape(self, text: str, source: str, outcome: SolverOutcome) -> None:
        if not text:
            return
        fresh = [f for f in extract_flags(text) if f not in outcome.flags_found]
        outcome.flags_found.extend(fresh)
        if self._inbox is not None:
            self._inbox.add_many(fresh, source=source)

    def _compact(self, conversation: Conversation) -> None:
        """确定性压缩:保 system 外的前几条(目标)+ 尾部最近交互。

        M2 升级为 observer 摘要(LOCK/CONFIRMED/ANGLES 简报)后此函数
        退役为兜底。
        """
        items = list(conversation.items())
        head = items[:1]  # 初始目标
        tail = items[-self._compact_keep_tail :]
        kept = head + tail if len(head) < self._compact_keep_tail else tail
        rebuilt = Conversation()
        for role, payload in kept:
            if role == "user":
                rebuilt.add_user(payload)
            elif role == "assistant":
                rebuilt.add_assistant(payload)
            else:
                rebuilt.add_tool(payload)
        rebuilt.add_user(COMPACT_NOTICE)
        if self._last_map:  # 覆盖图是长程记忆,压缩必须幸存(原位,不重复)
            rebuilt.upsert_user("<hexhammer-map>", self._last_map)
        conversation.replace_with(rebuilt)

    def _maybe_observe(self, conversation: Conversation, goal: str) -> None:
        """蒸馏证据窗 → 覆盖图注入。失败 fail-open,不阻塞求解。

        注入用 upsert 原位替换:旧图在历史中段被新图覆盖,长会话不膨胀
        (Heimdall injectMapIntoMessages 同款,2026-09-24 对齐)。
        """
        evidence = evidence_window(conversation, self._evidence_from)
        observer_map = self._observer.observe(goal, evidence)
        if observer_map is not None:
            self._last_map = observer_map.render()
            conversation.upsert_user("<hexhammer-map>", self._last_map)
            self._evidence_from = len(conversation.items())
        self._turns_since_observe = 0
