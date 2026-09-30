"""OpenAI 兼容协议客户端(chat/completions)。deepseek 系网关的默认形态。"""

from __future__ import annotations

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

_CONTEXT_OVERFLOW_MARKERS = ("context length", "maximum context", "too long")


def _classify_error(status_code: int, body: str) -> LLMError:
    lowered = body.lower()
    if status_code == 400:
        for marker in _CONTEXT_OVERFLOW_MARKERS:
            if marker in lowered:
                return ContextOverflowError("context_overflow", body)
        return LLMFatalError("bad_request", body)
    if status_code in (401, 403, 404):
        return LLMFatalError("auth", body)
    if status_code == 408 or status_code == 429 or status_code >= 500:
        return LLMTransientError(f"http_{status_code}", body)
    return LLMFatalError(f"http_{status_code}", body)


class OpenAICompatClient:
    """一个实例 = 一个网关 + 一个模型。线程安全性依赖每次调用独立请求。

    streaming=True 声明支持流式回调(chat 的 stream_cb=...,协议兼容:
    不传回调行为与旧版完全一致;某些网关不支持流式时自动回退整请求)。
    """

    streaming = True

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

    def chat(
        self,
        system: str,
        conversation: Conversation,
        tools: list[ToolSpec] | None = None,
        *,
        stream_cb: Callable[[str], None] | None = None,
    ) -> LLMResponse:
        body = self._build_body(system, conversation, tools)
        url = self._config.base_url.rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {self._config.api_key}"}
        headers.update(self._config.extra_headers)

        if stream_cb is not None:
            try:
                return self._chat_stream(url, headers, body, stream_cb)
            except LLMFatalError as exc:
                # 仅"网关不支持流式"才回退整请求;其余致命错(context 溢出等)
                # 直接抛——回退重放只会浪费一次大请求。
                if "stream" not in str(exc).lower():
                    raise

        response = request_with_retry(
            self._client,
            "POST",
            url,
            headers=headers,
            json_payload=body,
            classify=_classify_error,
            retry=self._retry,
            sleep=self._sleep,
        )
        return self._parse_response(response.text)

    def _build_body(
        self,
        system: str,
        conversation: Conversation,
        tools: list[ToolSpec] | None,
    ) -> dict:
        tools = tools or []
        messages: list[dict] = [{"role": "system", "content": system}]
        for role, payload in conversation.items():
            if role == "user":
                messages.append({"role": "user", "content": payload})
            elif role == "assistant":
                turn: AssistantTurn = payload
                message: dict = {"role": "assistant"}
                if turn.text:
                    message["content"] = turn.text
                if turn.tool_calls:
                    message["tool_calls"] = [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {
                                "name": call.name,
                                "arguments": call.arguments,
                            },
                        }
                        for call in turn.tool_calls
                    ]
                if "content" not in message:
                    message["content"] = None
                messages.append(message)
            else:
                result: ToolResult = payload
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": result.tool_call_id,
                        "content": result.content,
                    }
                )

        body: dict = {
            "model": self._config.model,
            "messages": messages,
            "max_tokens": self._config.max_output_tokens,
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]
            body["tool_choice"] = "auto"
        if self._config.temperature is not None:
            body["temperature"] = self._config.temperature
        return body

    def _chat_stream(
        self, url: str, headers: dict, body: dict, stream_cb: Callable[[str], None]
    ) -> LLMResponse:
        """SSE 流式:文本 delta 实时回调,最终聚合为与非流式同构的响应。"""
        import json as _json

        body = {**body, "stream": True, "stream_options": {"include_usage": True}}
        text_parts: list[str] = []
        calls: dict[int, dict] = {}
        usage_raw: dict = {}
        finish = ""
        with self._client.stream(
            "POST", url, headers=headers, json=body
        ) as response:
            if response.status_code >= 400:
                raw = response.read().decode("utf-8", errors="replace")
                raise _classify_error(response.status_code, raw)
            for line in response.iter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = _json.loads(data)
                except ValueError:
                    continue
                if chunk.get("usage"):
                    usage_raw = chunk["usage"]
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                piece = delta.get("content")
                if piece:
                    text_parts.append(piece)
                    stream_cb(piece)
                for call in delta.get("tool_calls") or []:
                    index = call.get("index", 0)
                    slot = calls.setdefault(index, {"id": "", "name": "", "args": ""})
                    if call.get("id"):
                        slot["id"] = call["id"]
                    fn = call.get("function") or {}
                    slot["name"] += fn.get("name") or ""
                    slot["args"] += fn.get("arguments") or ""
                finish = choices[0].get("finish_reason") or finish

        tool_calls = [
            ToolCall(id=slot["id"], name=slot["name"], arguments=slot["args"] or "{}")
            for _, slot in sorted(calls.items())
        ]
        usage = Usage(
            input_tokens=int(usage_raw.get("prompt_tokens", 0)),
            output_tokens=int(usage_raw.get("completion_tokens", 0)),
            cache_read_tokens=int(
                usage_raw.get("prompt_cache_hit_tokens", 0)
                or (usage_raw.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
            ),
        )
        self._ledger.add(usage)
        return LLMResponse(
            turn=AssistantTurn(text="".join(text_parts), tool_calls=tool_calls),
            usage=usage,
            stop_reason=finish,
        )

    def _parse_response(self, raw: str) -> LLMResponse:
        payload = safe_json_loads(raw)
        choices = payload.get("choices") or []
        if not choices:
            raise LLMFatalError("empty_choices", raw)
        message = choices[0].get("message") or {}
        tool_calls = [
            ToolCall(
                id=call.get("id", ""),
                name=(call.get("function") or {}).get("name", ""),
                arguments=(call.get("function") or {}).get("arguments", "{}"),
            )
            for call in message.get("tool_calls") or []
        ]
        turn = AssistantTurn(text=message.get("content") or "", tool_calls=tool_calls)
        usage_raw = payload.get("usage") or {}
        usage = Usage(
            input_tokens=int(usage_raw.get("prompt_tokens", 0)),
            output_tokens=int(usage_raw.get("completion_tokens", 0)),
            # deepseek 网关用 prompt_cache_hit_tokens,OpenAI 新版用
            # prompt_tokens_details.cached_tokens,两者都认。
            cache_read_tokens=int(
                usage_raw.get("prompt_cache_hit_tokens", 0)
                or (usage_raw.get("prompt_tokens_details") or {}).get(
                    "cached_tokens", 0
                )
            ),
        )
        self._ledger.add(usage)
        return LLMResponse(
            turn=turn, usage=usage, stop_reason=choices[0].get("finish_reason", "")
        )
