"""会话持久化测试:编解码、存档、崩溃恢复 e2e(进程死≠任务死)。"""

import json
from pathlib import Path

from hexhammer.control import Orchestrator, TaskSpec
from hexhammer.inbox import FindingsInbox
from hexhammer.llm.types import (
    AssistantTurn,
    Conversation,
    LLMResponse,
    ToolCall,
    ToolResult,
    Usage,
)
from hexhammer.session import (
    SessionStore,
    conversation_from_json,
    conversation_to_json,
)
from hexhammer.solver import SolverLoop
from hexhammer.tools import default_registry


def _text_turn(text: str) -> LLMResponse:
    return LLMResponse(
        turn=AssistantTurn(text=text), usage=Usage(input_tokens=1, output_tokens=1)
    )


def _flag_turn(flag: str) -> LLMResponse:
    return LLMResponse(
        turn=AssistantTurn(
            tool_calls=[
                ToolCall(
                    id="c1",
                    name="bash",
                    arguments=json.dumps({"command": f"echo '{flag}'"}),
                )
            ]
        ),
        usage=Usage(input_tokens=1, output_tokens=1),
    )


class ScriptedClient:
    def __init__(self, script: list) -> None:
        self.script = list(script)

    def chat(self, system, conversation, tools=None):
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestCodec:
    def test_round_trip_all_roles(self):
        conv = Conversation()
        conv.add_user("goal text")
        conv.add_assistant(
            AssistantTurn(
                text="plan",
                tool_calls=[ToolCall(id="t1", name="bash", arguments='{"command":"id"}')],
            )
        )
        conv.add_tool(ToolResult(tool_call_id="t1", content="uid=0", is_error=False))
        restored = conversation_from_json(conversation_to_json(conv))
        assert restored.items() == conv.items()


class TestStore:
    def test_save_load_round_trip(self, tmp_path: Path):
        store = SessionStore(tmp_path / "ws")
        conv = Conversation()
        conv.add_user("g")
        store.save(
            attempts=2,
            phase=1,
            elapsed_s=123.5,
            flags=["flag{a}"],
            stop_reasons=["model_stop", "deadline"],
            conversation=conv,
        )
        session = store.load()
        assert session is not None
        assert session.attempts == 2 and session.phase == 1
        assert session.elapsed_s == 123.5
        assert session.flags == ["flag{a}"]
        assert session.stop_reasons == ["model_stop", "deadline"]
        assert session.conversation is not None and session.conversation.items() == conv.items()

    def test_missing_and_corrupt(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        assert SessionStore(ws).load() is None  # 无档案
        (ws / "session.json").write_text("{broken", encoding="utf-8")
        assert SessionStore(ws).load() is None  # 元数据损坏 → 整档作废
        store = SessionStore(ws)
        store.save(
            attempts=1, phase=1, elapsed_s=1.0,
            flags=[], stop_reasons=[], conversation=None,
        )
        (ws / "conversation.json").write_text("not json", encoding="utf-8")
        session = store.load()
        assert session is not None and session.conversation is None  # 会话损坏丢会话保元数据

    def test_clear_removes_files(self, tmp_path: Path):
        ws = tmp_path / "ws"
        store = SessionStore(ws)
        conv = Conversation()
        conv.add_user("g")
        store.save(attempts=1, phase=1, elapsed_s=1, flags=[], stop_reasons=[], conversation=conv)
        store.clear()
        assert not (ws / "session.json").exists()
        assert not (ws / "conversation.json").exists()
        # 会话归档保复盘证据(0003 教训:accepted 清档删了行为评估证据)
        archived = ws / "tmp" / "conversation-final.json"
        assert archived.is_file() and "g" in archived.read_text(encoding="utf-8")


class TestCrashRecovery:
    def test_interrupted_then_resumed_mission(self, tmp_path: Path):
        ws = tmp_path / "task-r"
        ws.mkdir(parents=True)
        spec = TaskSpec(
            task_id="a1_r", goal="two flags", domain="web",
            workspace=ws, max_attempts=2, redrive_max=0, max_turns=10,
            accept_flags=2,
        )

        # ---- 第一次运行:拿到 flag{r1} 后网关炸了(进程等价死亡) ----
        crash_client = ScriptedClient(
            [_flag_turn("flag{r1}"), RuntimeError("gateway dead")]
        )
        records = Orchestrator(
            lambda s: crash_client, lambda d: f"sys-{d}", slots=1
        ).run([TaskSpec(**{**spec.__dict__, "workspace": ws})])
        rec1 = records[0]
        assert rec1.status == "failed" and "gateway dead" in rec1.error
        assert rec1.flags == ["flag{r1}"]  # 收件箱已持久化
        assert SessionStore(ws).load() is not None  # 断点档案在
        inbox = FindingsInbox(ws / "flags.json")
        assert [e["flag"] for e in inbox.all_entries()] == ["flag{r1}"]

        # ---- 第二次运行:断点续跑,补齐第二个 flag,通关 ----
        resume_client = ScriptedClient([_flag_turn("flag{r2}")])
        records = Orchestrator(
            lambda s: resume_client, lambda d: f"sys-{d}", slots=1
        ).run([TaskSpec(**{**spec.__dict__, "workspace": ws})])
        rec2 = records[0]
        assert rec2.status == "accepted"
        assert rec2.attempts == 2  # 尝试计数没归零:第 1 次是崩溃前那次
        assert set(rec2.flags) == {"flag{r1}", "flag{r2}"}  # 跨进程累积
        assert SessionStore(ws).load() is None  # 通关清档
        # 恢复会话带着断点上下文与 [恢复] 指令续跑(会话已通关清档,
        # 以收件箱与记录断言恢复语义)

    def test_solver_outcome_carries_conversation(self, tmp_path: Path):
        ws = tmp_path / "ws-outcome"
        ws.mkdir()
        loop = SolverLoop(
            ScriptedClient([_flag_turn("flag{oc}}")]),
            default_registry(),
            "sys",
            acceptance=lambda: True,
            max_turns=3,
        )
        outcome = loop.run("goal", ws)
        assert outcome.conversation is not None
        assert len(outcome.conversation.items()) >= 3  # goal+assistant+tool
