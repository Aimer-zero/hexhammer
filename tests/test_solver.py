"""solver 循环测试:mock e2e、flag 刮取、再驱动、压缩。"""

import json
from pathlib import Path

from hexhammer.inbox import FindingsInbox, extract_flags
from hexhammer.llm.types import (
    AssistantTurn,
    ContextOverflowError,
    Conversation,
    LLMResponse,
    ToolCall,
    ToolResult,
    Usage,
)
from hexhammer.solver import SolverLoop
from hexhammer.tools import default_registry


class FakeClient:
    """脚本化伪客户端:按序吐出预设响应;记录每次请求的会话引用。"""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.calls: list[Conversation] = []

    def chat(self, system, conversation, tools=None):
        self.calls.append(conversation)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _usage() -> Usage:
    return Usage(input_tokens=1, output_tokens=1)


def _tool_turn(call_id: str, name: str, arguments: dict) -> LLMResponse:
    return LLMResponse(
        turn=AssistantTurn(
            tool_calls=[
                ToolCall(id=call_id, name=name, arguments=json.dumps(arguments))
            ]
        ),
        usage=_usage(),
    )


def _text_turn(text: str) -> LLMResponse:
    return LLMResponse(
        turn=AssistantTurn(text=text),
        usage=type("U", (), {"input_tokens": 1, "output_tokens": 1})(),
    )


def test_extract_flags_dedup_ordered():
    text = "got flag{a} then ctf{b} and flag{a} again hack{c}"
    assert extract_flags(text) == ["flag{a}", "ctf{b}", "hack{c}"]


class TestInbox:
    def test_add_pending_mark_persistence(self, tmp_path: Path):
        inbox = FindingsInbox(tmp_path / "flags.json")
        assert inbox.add("flag{1}") is True
        assert inbox.add("flag{1}") is False  # 幂等
        assert inbox.add("flag{2}") is True
        assert len(inbox.pending()) == 2
        inbox.mark("flag{1}", "submitted", "awarded=50")
        reloaded = FindingsInbox(tmp_path / "flags.json")
        assert reloaded.pending() == [
            e for e in reloaded.all_entries() if e["flag"] == "flag{2}"
        ]
        assert reloaded.known_flags() == {"flag{1}", "flag{2}"}


class TestSolverLoop:
    def _workspace(self, tmp_path: Path) -> Path:
        ws = tmp_path / "ws"
        ws.mkdir()
        return ws

    def test_e2e_tool_flag_scraped_into_inbox(self, tmp_path: Path):
        client = FakeClient(
            [_tool_turn("c1", "bash", {"command": "echo 'found flag{e2e_ok}'"})]
        )
        inbox = FindingsInbox(tmp_path / "ws" / "flags.json")
        loop = SolverLoop(
            client,
            default_registry(),
            "system",
            inbox=inbox,
            acceptance=lambda: bool(inbox.pending()),
        )
        outcome = loop.run("get the flag", self._workspace(tmp_path))
        assert outcome.stop_reason == "acceptance"
        assert outcome.flags_found == ["flag{e2e_ok}"]
        assert inbox.pending()[0]["flag"] == "flag{e2e_ok}"
        assert inbox.pending()[0]["source"] == "tool:bash"
        # 会话里确实有工具结果回灌(user → assistant → tool)
        roles = [role for role, _ in client.calls[-1].items()]
        assert roles == ["user", "assistant", "tool"]

    def test_redrive_on_unmet_acceptance(self, tmp_path: Path):
        client = FakeClient(
            [
                _text_turn("I believe we are done."),  # 无 flag → 未验收
                _tool_turn("c1", "bash", {"command": "echo flag{r2}"}),
            ]
        )
        inbox = FindingsInbox(tmp_path / "ws" / "flags.json")
        sleeps: list[float] = []
        loop = SolverLoop(
            client,
            default_registry(),
            "system",
            inbox=inbox,
            acceptance=lambda: bool(inbox.pending()),
            acceptance_status=lambda: "0 flags in inbox",
            redrive_max=3,
            sleep=sleeps.append,
        )
        outcome = loop.run("goal", self._workspace(tmp_path))
        assert outcome.stop_reason == "acceptance"
        assert outcome.redrives == 1
        assert sleeps == [2.0]  # 2^1 退避
        assert outcome.flags_found == ["flag{r2}"]

    def test_model_stop_without_acceptance(self, tmp_path: Path):
        client = FakeClient([_text_turn("final answer: nothing found")])
        loop = SolverLoop(client, default_registry(), "system")
        outcome = loop.run("goal", self._workspace(tmp_path))
        assert outcome.stop_reason == "model_stop"
        assert outcome.turns == 1
        assert outcome.redrives == 0  # 未配验收:模型停即结束,不空转

    def test_context_overflow_triggers_compaction(self, tmp_path: Path):
        # 预置 20 条工具结果,触发一次溢出后正常收尾
        conversation = Conversation()
        conversation.add_user("goal")
        for i in range(20):
            conversation.add_tool(ToolResult(tool_call_id=f"t{i}", content=f"out {i}"))
        client = FakeClient(
            [ContextOverflowError("context_overflow", "too long"), _text_turn("done")]
        )
        loop = SolverLoop(client, default_registry(), "system")
        outcome = loop.run("goal", self._workspace(tmp_path), conversation=conversation)
        assert outcome.compactions == 1
        assert outcome.stop_reason == "model_stop"
        # 压缩后:头部目标 + 尾部 8 条 + 压缩说明 + 本轮 assistant 文本
        items = client.calls[-1].items()
        assert len(items) <= 13
        assert items[0][0] == "user"  # 原目标保留
        # 压缩说明 = 任务化保留清单(目标/凭证/死路/下一步),不是泛泛"已压缩"
        notice = next(
            str(payload) for role, payload in items
            if role == "user" and "已压缩" in str(payload)
        )
        assert "保留清单" in notice and "下一步" in notice
