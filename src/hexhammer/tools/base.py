"""工具接口与注册表。

工具面纪律(架构 §4.2):极简七件套、零 MCP、平台交互 CLI 化。所有工具
输出统一截断(保头保尾——flag 与证据常在尾部),防单条工具结果撑爆上下文。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..llm.types import ToolSpec, safe_json_loads
from .policy import CommandPolicy

MAX_OUTPUT_CHARS = 8000


def truncate(text: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """保头保尾截断:中间用省略标记连接。"""
    if len(text) <= max_chars:
        return text
    keep = max_chars // 2
    return (
        text[:keep]
        + f"\n... [truncated {len(text) - 2 * keep} chars] ...\n"
        + text[-keep:]
    )


class ToolError(Exception):
    """工具执行失败:转成 is_error 的 ToolResult 回灌,不炸循环。"""


class Tool(Protocol):
    name: str
    description: str
    parameters: dict

    def execute(self, args: dict, ctx: ToolContext) -> str: ...


@dataclass
class ToolContext:
    """一次求解会话的执行环境:工作区根 + 资源上限 + 命令策略。

    policy 默认开启(物理纪律默认在位,不是可选配置)。
    """

    workspace: Path
    bash_timeout: float = 120.0
    max_output_chars: int = MAX_OUTPUT_CHARS
    policy: CommandPolicy = field(default_factory=CommandPolicy)


@dataclass
class Registry:
    """工具注册表:暴露 ToolSpec 列表,按名分发。"""

    _tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool: {tool.name}")
        self._tools[tool.name] = tool

    def specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name=t.name, description=t.description, parameters=t.parameters
            )
            for t in self._tools.values()
        ]

    def dispatch(self, name: str, arguments_json: str, ctx: ToolContext) -> tuple[str, bool]:
        """执行工具调用,返回 (content, is_error)。永不抛异常给调用方。"""
        tool = self._tools.get(name)
        if tool is None:
            return f"error: unknown tool {name!r}", True
        try:
            args = safe_json_loads(arguments_json or "{}")
            if not isinstance(args, dict):
                raise ToolError(f"arguments must be a JSON object, got {type(args).__name__}")
            content = tool.execute(args, ctx)
        except ToolError as exc:
            return f"error: {exc}", True
        except Exception as exc:  # noqa: BLE001 - 工具层兜底,错误回灌模型
            return f"error: {type(exc).__name__}: {exc}", True
        return truncate(content, ctx.max_output_chars), False


def resolve_in_workspace(ctx: ToolContext, path: str) -> Path:
    """把模型给的路径钉死在工作区内;越界即 ToolError(防误伤宿主)。"""
    target = Path(path)
    if not target.is_absolute():
        target = ctx.workspace / target
    resolved = target.resolve()
    root = ctx.workspace.resolve()
    if resolved != root and root not in resolved.parents:
        raise ToolError(f"path escapes workspace: {path}")
    return resolved
