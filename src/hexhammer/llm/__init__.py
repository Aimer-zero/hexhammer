"""LLM 协议层:openai_compat / anthropic_compat 双形态客户端。"""

from ..config import ModelConfig
from .anthropic_compat import AnthropicCompatClient
from .openai_compat import OpenAICompatClient
from .types import (
    AssistantTurn,
    ContextOverflowError,
    Conversation,
    LLMError,
    LLMFatalError,
    LLMResponse,
    LLMSessionDeadError,
    LLMTransientError,
    RetryPolicy,
    TokenLedger,
    ToolCall,
    ToolResult,
    ToolSpec,
    Usage,
)

__all__ = [
    "AnthropicCompatClient",
    "AssistantTurn",
    "ContextOverflowError",
    "Conversation",
    "LLMError",
    "LLMFatalError",
    "LLMResponse",
    "LLMSessionDeadError",
    "LLMTransientError",
    "ModelConfig",
    "OpenAICompatClient",
    "RetryPolicy",
    "TokenLedger",
    "ToolCall",
    "ToolResult",
    "ToolSpec",
    "Usage",
]


def build_client(
    config: ModelConfig,
    *,
    ledger: TokenLedger | None = None,
    **kwargs,
):
    """按 config.protocol 构造对应客户端。"""
    if config.protocol == "anthropic":
        return AnthropicCompatClient(config, ledger=ledger, **kwargs)
    if config.protocol == "openai":
        return OpenAICompatClient(config, ledger=ledger, **kwargs)
    raise ValueError(f"unknown protocol: {config.protocol!r}")
