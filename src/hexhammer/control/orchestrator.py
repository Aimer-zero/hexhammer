"""编排核心:Pass Clock × 槽位调度 × 两阶段升级 × 时限止损。

设计铁律(见 docs/design.md §1-2):
- 调度纪律全部长在 harness 里,不进提示词(CyberPenda ADR 0034 事故反面);
- 预算元数据数据化(CyberPenda Pass Clock):elapsed/budget/attempt 注入目标,
  不靠模型记性;
- 两阶段(Heimdall):regular 快跑多次尝试 → loop 深挖一次,复用方法不复用会话;
- 时限止损:solver 循环认 deadline,长扫描/慢模型都吃不穿预算。
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from ..inbox import FindingsInbox
from ..llm.types import Conversation, LLMClientProtocol
from ..session import SessionStore
from ..solver import SolverLoop
from ..tools import Registry, default_registry
from .timeline import Timeline, null_timeline


@dataclass
class MissionHooks:
    """adapter 生命周期钩子:平台操作(启容器/交 flag/关容器)从这里进编排。

    - start:任务开跑前调用,返回追加进 goal 的附言(如容器地址);
    - attempt_end:每次尝试结束调用(冲洗收件箱→提交 flag);
    - task_end:任务收尾调用(最终冲洗+释放容器),任何退出路径都会走到。
    """

    start: Callable[[TaskRecord], str] = lambda record: ""
    attempt_end: Callable[[TaskRecord], object] = lambda record: None
    task_end: Callable[[TaskRecord], object] = lambda record: None


@dataclass
class TaskSpec:
    """一个编排单元:目标 + 域 + 工作区 + 预算。context 由 adapter 填。"""

    task_id: str
    goal: str
    domain: str
    workspace: Path
    priority: int = 0  # 大者先跑
    accept_flags: int = 1  # 收件箱累计 flag 数达到即验收(默认验收)
    acceptance_fn: Callable[[Path, FindingsInbox], bool] | None = None  # 自定义验收(报告型任务用)
    budget_regular_s: float = 1800.0
    budget_loop_s: float = 3600.0
    max_attempts: int = 2  # phase 1 尝试次数
    max_turns: int = 40
    redrive_max: int = 1
    context: dict = field(default_factory=dict)


@dataclass
class TaskRecord:
    spec: TaskSpec
    status: str = "pending"  # pending/running/accepted/failed
    phase: int = 0
    attempts: int = 0
    flags: list[str] = field(default_factory=list)
    stop_reasons: list[str] = field(default_factory=list)
    error: str = ""
    elapsed_s: float = 0.0

    def summary(self) -> str:
        return (
            f"{self.spec.task_id}: {self.status} phase={self.phase} "
            f"attempts={self.attempts} flags={len(self.flags)} "
            f"elapsed={self.elapsed_s:.0f}s stops={self.stop_reasons or ['-']}"
        )


class PassClock:
    """每题预算时钟:首启时间 + 累计耗时 + 注入行。"""

    def __init__(self, spec: TaskSpec) -> None:
        self.spec = spec
        self.total_elapsed = 0.0
        self._t0: float | None = None
        self._lock = threading.Lock()

    def open(self) -> None:
        with self._lock:
            self._t0 = time.monotonic()

    def close(self) -> None:
        with self._lock:
            if self._t0 is not None:
                self.total_elapsed += time.monotonic() - self._t0
                self._t0 = None

    def budget_for(self, phase: int) -> float:
        return self.spec.budget_regular_s if phase == 1 else self.spec.budget_loop_s

    def remaining_for(self, phase: int) -> float:
        return max(0.0, self.budget_for(phase) - self.total_elapsed)

    def render(self, phase: int, attempt: int) -> str:
        budget = self.budget_for(phase)
        over = "yes" if self.total_elapsed > budget else "no"
        return (
            f"[clock] pass={phase} attempt={attempt} "
            f"elapsed_min={self.total_elapsed / 60:.1f} "
            f"budget_min={budget / 60:.0f} over_budget={over}"
        )


class Orchestrator:
    """编排器:槽位并行跑任务,每任务两阶段推进,全程时间线留痕。"""

    def __init__(
        self,
        client_factory: Callable[[TaskSpec], LLMClientProtocol],
        system_prompt_for: Callable[[str], str],
        *,
        slots: int = 3,
        registry: Registry | None = None,
        timeline: Timeline | None = None,
        hooks: MissionHooks | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._system_prompt_for = system_prompt_for
        self._slots = max(1, slots)
        self._registry = registry or default_registry()
        self._emit = timeline.emit if timeline is not None else null_timeline()
        self._hooks = hooks or MissionHooks()

    def run(self, specs: list[TaskSpec]) -> list[TaskRecord]:
        records = [
            TaskRecord(spec=s)
            for s in sorted(specs, key=lambda s: (-s.priority, s.task_id))
        ]
        self._emit(
            "mission_start",
            tasks=len(records),
            slots=self._slots,
            domains=sorted({s.domain for s in specs}),
        )
        with ThreadPoolExecutor(max_workers=self._slots) as pool:
            futures = {
                pool.submit(self._run_task, record): record for record in records
            }
            for future in as_completed(futures):
                future.result()
        accepted = sum(1 for r in records if r.status == "accepted")
        self._emit(
            "mission_end",
            total=len(records),
            accepted=accepted,
            failed=len(records) - accepted,
            flags=sum(len(r.flags) for r in records),
        )
        return records

    # ---------------------------------------------------------------- 单任务

    def _run_task(self, record: TaskRecord) -> TaskRecord:
        spec = record.spec
        record.status = "running"
        self._emit("task_start", task_id=spec.task_id, domain=spec.domain)
        # 防呆:调用方忘建目录会让 bash 的 cwd 直接死(mission2 实测事故:
        # 三任务全灭的根因)。引擎侧永远兜底。
        spec.workspace.mkdir(parents=True, exist_ok=True)
        inbox = FindingsInbox(spec.workspace / "flags.json")
        clock = PassClock(spec)
        client = self._client_factory(spec)
        system_prompt = self._system_prompt_for(spec.domain)
        if spec.acceptance_fn is not None:
            acceptance = lambda: spec.acceptance_fn(spec.workspace, inbox)
        else:
            acceptance = self._make_acceptance(inbox, spec)
        addon = ""
        store = SessionStore(spec.workspace)

        # ---- 断点恢复:进程死后从上次会话与计数继续,不归零 ----
        session = store.load()
        pending_resume: Conversation | None = None
        if session is not None:
            clock.total_elapsed = session.elapsed_s
            record.attempts = session.attempts
            record.phase = session.phase
            for flag in session.flags:
                if flag not in record.flags:
                    record.flags.append(flag)
            record.stop_reasons = list(session.stop_reasons)
            pending_resume = session.conversation
            self._emit(
                "session_resume",
                task_id=spec.task_id,
                attempts=session.attempts,
                elapsed_s=round(session.elapsed_s, 1),
                resumed=pending_resume is not None,
            )
        last_conv = pending_resume

        try:
            addon = self._hooks.start(record) or ""
            # ---- 阶段 1:regular,可多次尝试(恢复时从上次计数续) ----
            for attempt in range(record.attempts + 1, spec.max_attempts + 1):
                record.attempts = attempt
                record.phase = 1
                self._emit(
                    "task_attempt",
                    task_id=spec.task_id,
                    phase=1,
                    attempt=attempt,
                    remaining_s=round(clock.remaining_for(1), 1),
                )
                conv = pending_resume or Conversation()
                pending_resume = None  # 恢复只消费一次,之后各次尝试全新会话
                last_conv = conv
                outcome = self._attempt(
                    client,
                    system_prompt,
                    spec,
                    inbox,
                    acceptance,
                    clock,
                    1,
                    attempt,
                    addon=addon,
                    conversation=conv,
                )
                record.stop_reasons.append(outcome.stop_reason)
                self._absorb_flags(record, inbox)
                # 持久化用 loop 返回的会话句柄:_attempt 对空会话自建新对象,
                # 外部 conv 变量不跟踪它——#14(conversation.json 从未落盘)根因
                if outcome.conversation is not None:
                    last_conv = outcome.conversation
                store.save(
                    attempts=record.attempts,
                    phase=1,
                    elapsed_s=clock.total_elapsed,
                    flags=record.flags,
                    stop_reasons=record.stop_reasons,
                    conversation=last_conv,
                )
                if outcome.stop_reason == "acceptance":
                    record.status = "accepted"
                    break
                self._hooks.attempt_end(record)

            else:
                if clock.remaining_for(2) < 60:
                    # loop 预算已被 regular 吃光:尸体阶段无意义,直接记败
                    record.stop_reasons.append("loop_budget_exhausted")
                    record.status = "failed"
                else:
                    # ---- 阶段 2:loop 深挖,单次,复用方法不复用会话 ----
                    record.phase = 2
                    brief = (
                        f"先前 {record.attempts} 次 regular 未果;"
                        f"止损={record.stop_reasons};已获 flags={record.flags or '无'}。"
                        "复用方法不复用会话:先读 notes.md 里已确认的路径与死路,别重复侦察。"
                    )
                    self._emit(
                        "task_attempt",
                        task_id=spec.task_id,
                        phase=2,
                        attempt=1,
                        remaining_s=round(clock.remaining_for(2), 1),
                    )
                    conv = pending_resume or Conversation()
                    last_conv = conv
                    outcome = self._attempt(
                        client,
                        system_prompt,
                        spec,
                        inbox,
                        acceptance,
                        clock,
                        2,
                        1,
                        brief=brief,
                        addon=addon,
                        conversation=conv,
                    )
                    record.stop_reasons.append(outcome.stop_reason)
                    self._absorb_flags(record, inbox)
                    record.status = (
                        "accepted" if outcome.stop_reason == "acceptance" else "failed"
                    )
                    if outcome.conversation is not None:
                        last_conv = outcome.conversation
                    store.save(
                        attempts=record.attempts,
                        phase=2,
                        elapsed_s=clock.total_elapsed,
                        flags=record.flags,
                        stop_reasons=record.stop_reasons,
                        conversation=last_conv,
                    )
        except Exception as exc:  # noqa: BLE001 - 线程内兜底,失败入档不炸池
            record.status = "failed"
            record.error = f"{type(exc).__name__}: {exc}"
            self._emit("task_error", task_id=spec.task_id, error=record.error)

        finally:
            # 单出口收尾:最终冲洗 + 容器释放 + 存档 + 计时,任何路径都不跳过。
            for hook_name, hook in (
                ("attempt_end", self._hooks.attempt_end),
                ("task_end", self._hooks.task_end),
            ):
                try:
                    hook(record)
                except Exception as exc:  # noqa: BLE001 - 钩子失败入档不吞任务结果
                    record.error += f" | {hook_name} failed: {exc}"
                    self._emit(
                        "hook_error", task_id=spec.task_id, hook=hook_name, error=str(exc)
                    )
            record.elapsed_s = clock.total_elapsed
            # 崩溃路径(except)跳过了常规吸收:收尾时无条件与收件箱对账,
            # 保证 record/session 元数据不落后于已持久化的 flag。
            self._absorb_flags(record, inbox)
            if record.status == "accepted":
                store.clear()  # 通关清档:同题下次从零
            else:
                try:
                    store.save(
                        attempts=record.attempts,
                        phase=record.phase,
                        elapsed_s=clock.total_elapsed,
                        flags=record.flags,
                        stop_reasons=record.stop_reasons,
                        conversation=last_conv,
                    )
                except Exception as exc:  # noqa: BLE001 - 存档失败不吞结果
                    self._emit(
                        "session_save_failed", task_id=spec.task_id, error=str(exc)
                    )
            self._emit(
                "task_end",
                task_id=spec.task_id,
                status=record.status,
                flags=record.flags,
                elapsed_s=round(record.elapsed_s, 1),
            )
        return record

    def _attempt(
        self,
        client: LLMClientProtocol,
        system_prompt: str,
        spec: TaskSpec,
        inbox: FindingsInbox,
        acceptance: Callable[[], bool],
        clock: PassClock,
        phase: int,
        attempt: int,
        brief: str = "",
        addon: str = "",
        conversation: Conversation | None = None,
    ) -> object:
        goal = spec.goal
        if addon:
            goal = f"{goal}\n\n{addon}"
        goal = f"{goal}\n\n{clock.render(phase, attempt)}"
        if brief:
            goal = f"{goal}\n\n{brief}"
        # 会话注入:全新尝试从头构建;断点恢复则在旧会话上追恢复指令。
        conv = (
            conversation
            if conversation is not None and conversation.items()
            else Conversation()
        )
        if not conv.items():
            conv.add_user(goal)
        else:
            conv.add_user(
                f"[恢复] 会话自持久化断点继续。{clock.render(phase, attempt)}\n"
                f"目标重申:{spec.goal}\n"
                "先读 notes.md 与最近的覆盖图恢复状态,不要重复已完成的侦察。"
            )
        clock.open()
        try:
            loop = SolverLoop(
                client,
                self._registry,
                system_prompt,
                inbox=inbox,
                acceptance=acceptance,
                acceptance_status=lambda: (
                    f"flags {len(inbox.all_entries())}/{spec.accept_flags}"
                ),
                max_turns=spec.max_turns,
                redrive_max=spec.redrive_max,
            )
            return loop.run(
                goal,
                spec.workspace,
                conversation=conv,
                deadline=time.monotonic() + clock.remaining_for(phase),
            )
        finally:
            clock.close()

    @staticmethod
    def _make_acceptance(inbox: FindingsInbox, spec: TaskSpec) -> Callable[[], bool]:
        # 默认验收只数 flag(靶场语义);漏洞类 finding 走 acceptance_fn/报告验收
        return lambda: len(inbox.flags_only()) >= spec.accept_flags

    @staticmethod
    def _absorb_flags(record: TaskRecord, inbox: FindingsInbox) -> None:
        for entry in inbox.all_entries():
            flag = entry["flag"]
            # finding 条目 flag 字段为空串:不是旗标,不吸收(实测 host80 混入 "")
            if flag and flag not in record.flags:
                record.flags.append(flag)
