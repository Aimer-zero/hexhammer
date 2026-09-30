"""LLM 协议层测试:成功解析、重试、错误分类、记账、anthropic 消息映射。"""

import json

import httpx
import pytest

from hexhammer.config import ModelConfig
from hexhammer.llm import (
    AnthropicCompatClient,
    ContextOverflowError,
    Conversation,
    LLMFatalError,
    OpenAICompatClient,
    RetryPolicy,
    TokenLedger,
    ToolResult,
)


def _config(**overrides) -> ModelConfig:
    values = {
        "protocol": "openai",
        "base_url": "https://gw.example.com/v1",
        "api_key": "test-key",
        "model": "deepseek-flash-test",
    }
    values.update(overrides)
    return ModelConfig(**values)


def _json_response(request: httpx.Request) -> httpx.Response:
    """从测试用 handler 里取请求体。"""
    return json.loads(request.content.decode("utf-8"))


def _completion(body_overrides: dict | None = None) -> dict:
    message = {
        "role": "assistant",
        "content": "thinking out loud",
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "bash",
                    "arguments": '{"command": "id"}',
                },
            }
        ],
    }
    usage = {
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "prompt_cache_hit_tokens": 40,
    }
    payload = {
        "choices": [{"message": message, "finish_reason": "tool_calls"}],
        "usage": usage,
    }
    if body_overrides:
        payload.update(body_overrides)
    return payload


class TestOpenAICompat:
    def test_chat_success_and_request_shape(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = _json_response(request)
            return httpx.Response(200, json=_completion())

        client = OpenAICompatClient(
            _config(), transport=httpx.MockTransport(handler)
        )
        conv = Conversation()
        conv.add_user("solve it")
        response = client.chat("you are a solver", conv, tools=[])

        assert response.turn.text == "thinking out loud"
        assert response.turn.tool_calls[0].name == "bash"
        assert response.stop_reason == "tool_calls"
        # 守卫:max_tokens 显式下发,不留给网关默认
        assert captured["body"]["max_tokens"] == 131_072
        assert captured["body"]["model"] == "deepseek-flash-test"
        assert captured["body"]["messages"][0] == {
            "role": "system",
            "content": "you are a solver",
        }

    def test_transient_500_retries_then_succeeds(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(500, text="boom")
            return httpx.Response(200, json=_completion())

        client = OpenAICompatClient(
            _config(),
            transport=httpx.MockTransport(handler),
            retry=RetryPolicy(max_attempts=3, base_delay=1.0),
            sleep=sleeps.append,
        )
        response = client.chat("sys", Conversation())
        assert calls["n"] == 2
        assert sleeps == [1.0]  # 指数退避第 1 次 = base
        assert response.usage.input_tokens == 100

    def test_fatal_401_no_retry(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(401, text="bad key")

        client = OpenAICompatClient(
            _config(), transport=httpx.MockTransport(handler), sleep=lambda s: None
        )
        with pytest.raises(LLMFatalError) as excinfo:
            client.chat("sys", Conversation())
        assert excinfo.value.reason == "auth"
        assert calls["n"] == 1

    def test_context_overflow_400(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                400, text="This model's maximum context length is 65536 tokens"
            )

        client = OpenAICompatClient(
            _config(), transport=httpx.MockTransport(handler), sleep=lambda s: None
        )
        with pytest.raises(ContextOverflowError):
            client.chat("sys", Conversation())

    def test_ledger_records_usage(self):
        ledger = TokenLedger()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_completion())

        client = OpenAICompatClient(
            _config(), transport=httpx.MockTransport(handler), ledger=ledger
        )
        client.chat("sys", Conversation())
        snapshot = ledger.snapshot()
        assert snapshot["calls"] == 1
        assert snapshot["input_tokens"] == 100
        assert snapshot["output_tokens"] == 20
        assert snapshot["cache_read_tokens"] == 40


class TestAnthropicCompat:
    def test_chat_success_and_tool_result_mapping(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["body"] = _json_response(request)
            return httpx.Response(
                200,
                json={
                    "content": [
                        {"type": "text", "text": "plan"},
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "bash",
                            "input": {"command": "id"},
                        },
                    ],
                    "stop_reason": "tool_use",
                    "usage": {
                        "input_tokens": 50,
                        "output_tokens": 10,
                        "cache_read_input_tokens": 30,
                        "cache_creation_input_tokens": 5,
                    },
                },
            )

        client = AnthropicCompatClient(
            _config(protocol="anthropic"),
            transport=httpx.MockTransport(handler),
        )
        conv = Conversation()
        conv.add_user("solve")
        from hexhammer.llm import AssistantTurn, ToolCall

        conv.add_assistant(
            AssistantTurn(tool_calls=[ToolCall(id="tu_0", name="bash", arguments="{}")])
        )
        conv.add_tool(ToolResult(tool_call_id="tu_0", content="uid=0(root)"))
        conv.add_user("continue")

        response = client.chat("sys prompt", conv)

        assert captured["url"].endswith("/v1/messages")
        body = captured["body"]
        assert body["system"] == "sys prompt"
        assert body["max_tokens"] == 131_072
        # 映射:user / assistant(tool_use) / user(tool_result + text 合并)
        assert body["messages"][0] == {
            "role": "user",
            "content": [{"type": "text", "text": "solve"}],
        }
        assert body["messages"][1]["content"][0]["type"] == "tool_use"
        merged = body["messages"][2]["content"]
        assert merged[0] == {
            "type": "tool_result",
            "tool_use_id": "tu_0",
            "content": "uid=0(root)",
        }
        assert merged[1] == {"type": "text", "text": "continue"}
        # 响应解析
        assert response.turn.tool_calls[0].id == "tu_1"
        assert json.loads(response.turn.tool_calls[0].arguments) == {"command": "id"}
        assert response.usage.cache_read_tokens == 30
        assert response.usage.cache_write_tokens == 5

    def test_base_url_with_trailing_v1_not_duplicated(self):
        client = AnthropicCompatClient(
            _config(protocol="anthropic", base_url="https://gw/v1"),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"content": [], "usage": {}})
            ),
        )
        assert client._messages_url() == "https://gw/v1/messages"


class TestUpsertUser:
    def test_replace_in_place_no_growth(self):
        conv = Conversation()
        conv.add_user("goal")
        conv.add_user("<hexhammer-map>v1</hexhammer-map>")
        conv.upsert_user("<hexhammer-map>", "<hexhammer-map>v2</hexhammer-map>")
        items = conv.items()
        assert len(items) == 2  # 原位替换,不追加
        assert items[1] == ("user", "<hexhammer-map>v2</hexhammer-map>")

    def test_append_when_missing(self):
        conv = Conversation()
        conv.add_user("goal")
        conv.upsert_user("<hexhammer-map>", "<hexhammer-map>v1</hexhammer-map>")
        assert len(conv.items()) == 2

    def test_only_first_occurrence_replaced(self):
        conv = Conversation()
        conv.add_user("<hexhammer-map>a</hexhammer-map>")
        conv.add_user("<hexhammer-map>b</hexhammer-map>")  # 压缩路径可能造成的历史重复
        conv.upsert_user("<hexhammer-map>", "<hexhammer-map>c</hexhammer-map>")
        items = conv.items()
        assert items[0] == ("user", "<hexhammer-map>c</hexhammer-map>")
        assert items[1] == ("user", "<hexhammer-map>b</hexhammer-map>")

    def test_non_user_payloads_untouched(self):
        from hexhammer.llm.types import AssistantTurn, ToolResult
        conv = Conversation()
        conv.add_user("<hexhammer-map>old</hexhammer-map>")
        conv.add_tool(ToolResult(tool_call_id="t", content="<hexhammer-map>x"))
        conv.add_assistant(AssistantTurn(text="<hexhammer-map>y"))
        conv.upsert_user("<hexhammer-map>", "<hexhammer-map>new</hexhammer-map>")
        assert conv.items()[0] == ("user", "<hexhammer-map>new</hexhammer-map>")
        assert len(conv.items()) == 3


class TestStreaming:
    def test_sse_stream_aggregates_and_calls_back(self):
        """流式:delta 实时回调、聚合响应与非流式同构、usage/ledger 记账。"""
        from hexhammer.config import ModelConfig
        from hexhammer.llm import OpenAICompatClient
        from hexhammer.llm.types import Conversation, TokenLedger

        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert '"stream":true' in request.read().decode()
            sse = "\n".join([
                'data: {"choices":[{"delta":{"content":"He"}}]}',
                'data: {"choices":[{"delta":{"content":"llo"}}]}',
                'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"bash","arguments":"{\\"cmd\\""}}]}}]}',
                'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":\\"id\\"}"}}]}}]}',
                'data: {"choices":[{"finish_reason":"tool_calls"}]}',
                'data: {"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_hit_tokens":8}}',
                'data: [DONE]',
            ])
            return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})

        cfg = ModelConfig(base_url="https://gw.example/v1", api_key="k", model="m")
        ledger = TokenLedger()
        client = OpenAICompatClient(cfg, ledger=ledger, transport=httpx.MockTransport(handler))
        conv = Conversation()
        conv.add_user("hi")
        response = client.chat("sys", conv, stream_cb=seen.append)

        assert seen == ["He", "llo"]                     # delta 逐段回调
        assert response.turn.text == "Hello"
        assert len(response.turn.tool_calls) == 1
        call = response.turn.tool_calls[0]
        assert call.id == "c1" and call.name == "bash"
        assert __import__("json").loads(call.arguments) == {"cmd": "id"}  # 分片拼接完整
        assert response.stop_reason == "tool_calls"
        assert ledger.snapshot()["input_tokens"] == 10   # 记账不丢
        assert ledger.snapshot()["cache_read_tokens"] == 8

    def test_stream_fallback_on_unsupported(self):
        """网关拒流式(400 提到 stream):回退整请求,结果一致。"""
        from hexhammer.config import ModelConfig
        from hexhammer.llm import OpenAICompatClient
        from hexhammer.llm.types import Conversation

        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            body = request.read().decode()
            if '"stream":true' in body:
                return httpx.Response(400, text='{"error":"stream not supported"}')
            return httpx.Response(200, text=__import__("json").dumps({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            }))

        cfg = ModelConfig(base_url="https://gw.example/v1", api_key="k", model="m")
        client = OpenAICompatClient(cfg, transport=httpx.MockTransport(handler))
        conv = Conversation()
        conv.add_user("hi")
        response = client.chat("sys", conv, stream_cb=lambda s: None)
        assert response.turn.text == "ok"
        assert calls["n"] == 2  # 流式被拒 → 整请求重放
