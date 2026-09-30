"""Anthropic 兼容协议客户端(/v1/messages)。

与 OpenAI 形态的关键差异:
- system 是顶层字段,不在 messages 里;
- 工具结果作为 user 消息内的 tool_result 内容块回灌,必须紧跟带 tool_use
  的 assistant 消息;
- max_tokens 必填(取 ModelConfig.max_output_tokens,显式守卫)。
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable

import httpx

from ..config import ModelConfig
from .http import request_with_retry
from .types import (
    AssistantTurn,
    ContextOverflowError,
    Conversation,
    LLMError,
    LLMFatalError,
    LLMResponse,
    LLMTransientError,
    RetryPolicy,
    TokenLedger,
    ToolCall,
    ToolResult,
    ToolSpec,
    Usage,
    safe_json_loads,
)


def _classify_error(status_code: int, body: str) -> LLMError:
    lowered = body.lower()
    if status_code == 400:
        if "prompt is too long" in lowered or "maximum context" in lowered:
            return ContextOverflowError("context_overflow", body)
        return LLMFatalError("bad_request", body)
    if status_code in (401, 403, 404):
        return LLMFatalError("auth", body)
    if status_code in (408, 429, 529) or status_code >= 500:
        return LLMTransientError(f"http_{status_code}", body)
    return LLMFatalError(f"http_{status_code}", body)


class AnthropicCompatClient:
    def __init__(
        self,
        config: ModelConfig,
        *,
        ledger: TokenLedger | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 600.0,
        retry: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._ledger = ledger or TokenLedger()
        self._retry = retry or RetryPolicy()
        self._sleep = sleep
        self._client = httpx.Client(timeout=timeout, transport=transport)

    def close(self) -> None:
        self._client.close()

    def _messages_url(self) -> str:
        base = self._config.base_url.rstrip("/")
        if base.endswith("/v1"):
            return base + "/messages"
        return base + "/v1/messages"

    def chat(
        self,
        system: str,
        conversation: Conversation,
        tools: list[ToolSpec] | None = None,
    ) -> LLMResponse:
        messages = self._map_messages(conversation)
        body: dict = {
            "model": self._config.model,
            "system": system,
            "messages": messages,
            "max_tokens": self._config.max_output_tokens,
        }
        if tools:
            body["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                }
                for t in tools
            ]
        if self._config.temperature is not None:
            body["temperature"] = self._config.temperature

        headers = {
            "x-api-key": self._config.api_key,
            "anthropic-version": "2023-06-01",
        }
        headers.update(self._config.extra_headers)

        response = request_with_retry(
            self._client,
            "POST",
            self._messages_url(),
            headers=headers,
            json_payload=body,
            classify=_classify_error,
            retry=self._retry,
            sleep=self._sleep,
        )
        return self._parse_response(response.text)

    @staticmethod
    def _map_messages(conversation: Conversation) -> list[dict]:
        """映射为 anthropic 消息数组。

        anthropic 要求角色严格交替:user 文本与 tool_result 连续出现时
        合并为同一条 user 消息的内容块;tool_result 必须紧跟带 tool_use
        的 assistant 消息。
        """
        messages: list[dict] = []

        def append_user_block(block: dict) -> None:
            if messages and messages[-1]["role"] == "user":
                messages[-1]["content"].append(block)
            else:
                messages.append({"role": "user", "content": [block]})

        for role, payload in conversation.items():
            if role == "user":
                append_user_block({"type": "text", "text": payload})
            elif role == "assistant":
                turn: AssistantTurn = payload
                blocks: list[dict] = []
                if turn.text:
                    blocks.append({"type": "text", "text": turn.text})
                for call in turn.tool_calls:
                    try:
                        arguments = json.loads(call.arguments)
                    except (json.JSONDecodeError, ValueError):
                        arguments = {"_raw": call.arguments}
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": call.id,
                            "name": call.name,
                            "input": arguments,
                        }
                    )
                messages.append({"role": "assistant", "content": blocks})
            else:
                result: ToolResult = payload
                block = {
                    "type": "tool_result",
                    "tool_use_id": result.tool_call_id,
                    "content": result.content,
                }
                if result.is_error:
                    block["is_error"] = True
                append_user_block(block)
        return messages

    def _parse_response(self, raw: str) -> LLMResponse:
        payload = safe_json_loads(raw)
        blocks = payload.get("content") or []
        texts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in blocks:
            if block.get("type") == "text":
                texts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.get("id", ""),
                        name=block.get("name", ""),
                        arguments=json.dumps(block.get("input") or {}),
                    )
                )
        usage_raw = payload.get("usage") or {}
        usage = Usage(
            input_tokens=int(usage_raw.get("input_tokens", 0)),
            output_tokens=int(usage_raw.get("output_tokens", 0)),
            cache_read_tokens=int(usage_raw.get("cache_read_input_tokens", 0)),
            cache_write_tokens=int(usage_raw.get("cache_creation_input_tokens", 0)),
        )
        self._ledger.add(usage)
        return LLMResponse(
            turn=AssistantTurn(text="\n".join(texts), tool_calls=tool_calls),
            usage=usage,
            stop_reason=payload.get("stop_reason", ""),
        )
