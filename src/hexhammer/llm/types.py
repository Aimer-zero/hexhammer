"""LLM 协议层公共类型:会话模型、工具规格、用量记账、错误四分类、重试策略。

错误分类对齐 Heimdall 的四分类经验(capacity/transient/fatal/session-dead):
长任务稳定性的一半在错误处置,基础设施失败不烧尝试次数是控制面的前提。
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Protocol

# ---------------------------------------------------------------- 会话模型


@dataclass(frozen=True)
class ToolSpec:
    """暴露给模型的工具定义。"""

    name: str
    description: str
    parameters: dict  # JSON Schema


@dataclass(frozen=True)
class ToolCall:
    """模型发起的一次工具调用。arguments 保持 JSON 字符串原样。"""

    id: str
    name: str
    arguments: str


@dataclass
class AssistantTurn:
    """一轮模型输出:文本与工具调用。"""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class ToolResult:
    """工具执行结果,回灌给模型。"""

    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class LLMResponse:
    turn: AssistantTurn
    usage: Usage
    stop_reason: str = ""


class Conversation:
    """会话条目序列:user / assistant / tool 三种角色,保持插入序。

    长程记忆不在这里——外圈状态走文件系统(覆盖图/facts),会话只是工作
    记忆(架构铁律 3)。
    """

    def __init__(self) -> None:
        self._items: list[tuple[str, object]] = []

    def add_user(self, text: str) -> None:
        self._items.append(("user", text))

    def upsert_user(self, marker: str, text: str) -> None:
        """原位替换首条以 marker 开头的 user 消息;不存在则追加。

        覆盖图等周期注入必须用它:追加式注入会让长会话线性膨胀
        (Heimdall injectMapIntoMessages 的原位替换同款,2026-09-24 对齐)。
        """
        for index, (role, payload) in enumerate(self._items):
            if role == "user" and isinstance(payload, str) and payload.startswith(marker):
                self._items[index] = ("user", text)
                return
        self.add_user(text)

    def add_assistant(self, turn: AssistantTurn) -> None:
        self._items.append(("assistant", turn))

    def add_tool(self, result: ToolResult) -> None:
        self._items.append(("tool", result))

    def items(self) -> tuple[tuple[str, object], ...]:
        return tuple(self._items)

    def replace_with(self, other: Conversation) -> None:
        """整体替换为另一会话的内容(压缩时用)。"""
        self._items = list(other.items())

    def approx_tokens(self) -> int:
        """粗略 token 估算(chars/4),只用于压缩阈值预判;记账以 API usage 为准。"""
        total_chars = 0
        for role, payload in self._items:
            if role == "user":
                total_chars += len(payload)
            elif role == "assistant":
                total_chars += len(payload.text) + sum(
                    len(c.name) + len(c.arguments) for c in payload.tool_calls
                )
            else:
                total_chars += len(payload.content)
        return total_chars // 4


# ---------------------------------------------------------------- 客户端协议


class LLMClientProtocol(Protocol):
    """solver 循环依赖的最小客户端接口;真实客户端与测试伪实现都满足它。"""

    def chat(
        self,
        system: str,
        conversation: Conversation,
        tools: list[ToolSpec] | None = None,
    ) -> LLMResponse: ...


# ---------------------------------------------------------------- 错误分类


class LLMError(Exception):
    """LLM 调用错误基类。"""

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        self.reason = reason


class LLMTransientError(LLMError):
    """瞬态:429/5xx/超时/连接失败。可按退避重试。"""


class LLMFatalError(LLMError):
    """致命:鉴权失败/模型不存在/请求非法。停止并报告,不重试。"""


class ContextOverflowError(LLMFatalError):
    """上下文超窗。solver 循环应触发压缩后重试一次,而非放弃。"""


class LLMSessionDeadError(LLMError):
    """会话死亡:响应体截断/解析失败等传输层特征。清会话重建,不计尝试。"""


# ---------------------------------------------------------------- 用量记账


class TokenLedger:
    """线程安全的 token 记账。预算纪律(章程)依赖它。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.input_tokens = 0
        self.output_tokens = 0
        self.cache_read_tokens = 0
        self.cache_write_tokens = 0
        self.calls = 0

    def add(self, usage: Usage) -> None:
        with self._lock:
            self.calls += 1
            self.input_tokens += usage.input_tokens
            self.output_tokens += usage.output_tokens
            self.cache_read_tokens += usage.cache_read_tokens
            self.cache_write_tokens += usage.cache_write_tokens

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "calls": self.calls,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cache_read_tokens": self.cache_read_tokens,
                "cache_write_tokens": self.cache_write_tokens,
                "total_tokens": self.input_tokens + self.output_tokens,
            }


# ---------------------------------------------------------------- 重试策略


@dataclass
class RetryPolicy:
    """指数退避:base * 2^(n-1),封顶 max_delay。只重试 Transient。"""

    max_attempts: int = 5
    base_delay: float = 2.0
    max_delay: float = 30.0

    def delay_for(self, attempt: int) -> float:
        return min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))


def sleep_backoff(policy: RetryPolicy, attempt: int) -> None:
    time.sleep(policy.delay_for(attempt))


def safe_json_loads(raw: str) -> dict:
    """解析模型工具参数/响应体;失败抛 LLMSessionDeadError(截断特征)。"""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise LLMSessionDeadError("bad_json", f"JSON decode failed: {exc}") from exc
