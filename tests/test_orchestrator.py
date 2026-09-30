"""编排器测试:并行槽位、两阶段升级、时限止损、时间线。"""

import json
import threading
import time
from pathlib import Path

from hexhammer.control import Orchestrator, TaskSpec, Timeline
from hexhammer.llm.types import AssistantTurn, LLMResponse, ToolCall, Usage


def _text_turn(text: str) -> LLMResponse:
    return LLMResponse(
        turn=AssistantTurn(text=text),
        usage=Usage(input_tokens=1, output_tokens=1),
    )


def _flag_turn(task_id: str) -> LLMResponse:
    return LLMResponse(
        turn=AssistantTurn(
            tool_calls=[
                ToolCall(
                    id="c1",
                    name="bash",
                    arguments=json.dumps({"command": f"echo 'flag{{orch-{task_id}}}'"}),
                )
            ]
        ),
        usage=Usage(input_tokens=1, output_tokens=1),
    )


class ScriptedClient:
    """按序吐脚本;耗尽再要就抛错(测试必须精确控制)。"""

    def __init__(self, script: list) -> None:
        self.script = list(script)

    def chat(self, system, conversation, tools=None):
        if not self.script:
            raise AssertionError("script exhausted")
        return self.script.pop(0)


def _spec(tmp_path: Path, task_id: str, **overrides) -> TaskSpec:
    ws = tmp_path / task_id
    ws.mkdir(parents=True)
    values = {
        "task_id": task_id,
        "goal": f"solve {task_id}",
        "domain": "web",
        "workspace": ws,
        "max_turns": 20,
        "redrive_max": 1,
    }
    values.update(overrides)
    return TaskSpec(**values)


def _prompt_for(domain: str) -> str:
    return f"system-for-{domain}"


class TestHappyPath:
    def test_parallel_slots_all_accepted(self, tmp_path):
        lock = threading.Lock()
        state = {"cur": 0, "max": 0}

        def factory(spec: TaskSpec) -> ScriptedClient:
            class SlowClient(ScriptedClient):
                def chat(self, system, conversation, tools=None):
                    with lock:
                        state["cur"] += 1
                        state["max"] = max(state["max"], state["cur"])
                    time.sleep(0.2)
                    try:
                        return super().chat(system, conversation, tools)
                    finally:
                        with lock:
                            state["cur"] -= 1

            return SlowClient([_flag_turn(spec.task_id)])

        specs = [_spec(tmp_path, f"t{i}") for i in range(4)]
        records = Orchestrator(factory, _prompt_for, slots=2).run(specs)

        assert all(r.status == "accepted" for r in records), [r.summary() for r in records]
        assert all(r.phase == 1 and r.attempts == 1 for r in records)
        assert sorted(r.flags[0] for r in records) == [
            "flag{orch-t0}", "flag{orch-t1}", "flag{orch-t2}", "flag{orch-t3}",
        ]
        # 槽位纪律:并发峰值被 slots 卡住,且确实并行过
        assert 2 <= state["max"] <= 2

    def test_priority_ordering(self, tmp_path):
        started: list[str] = []
        lock = threading.Lock()

        def factory(spec: TaskSpec) -> ScriptedClient:
            class OrderingClient(ScriptedClient):
                def chat(self, system, conversation, tools=None):
                    with lock:
                        started.append(spec.task_id)
                    return super().chat(system, conversation, tools)

            return OrderingClient([_flag_turn(spec.task_id)])

        specs = [
            _spec(tmp_path, "low", priority=0),
            _spec(tmp_path, "high", priority=10),
        ]
        records = Orchestrator(factory, _prompt_for, slots=1).run(specs)
        assert all(r.status == "accepted" for r in records)
        assert started[0] == "high"  # 单槽串行,高优先级先跑


class TestEscalation:
    def test_phase2_loop_rescues_stuck_task(self, tmp_path):
        script = [
            _text_turn("stuck"),   # attempt1: 文本 → redrive
            _text_turn("still stuck"),  # → model_stop
            _text_turn("stuck"),   # attempt2
            _text_turn("still stuck"),
            _flag_turn("esc"),     # phase2 loop: 一发命中
        ]
        spec = _spec(tmp_path, "esc", max_attempts=2)
        records = Orchestrator(
            lambda s: ScriptedClient(script), _prompt_for, slots=1
        ).run([spec])

        rec = records[0]
        assert rec.status == "accepted"
        assert rec.phase == 2 and rec.attempts == 2
        assert rec.stop_reasons == ["model_stop", "model_stop", "acceptance"]
        assert rec.flags == ["flag{orch-esc}"]


class TestDeadline:
    def test_budget_exhaustion_fails_with_deadline(self, tmp_path):
        class LoopForever(ScriptedClient):
            def chat(self, system, conversation, tools=None):
                time.sleep(0.02)
                return _flag_free_tool_turn()

        def _flag_free_tool_turn() -> LLMResponse:
            return LLMResponse(
                turn=AssistantTurn(
                    tool_calls=[
                        ToolCall(
                            id="c1", name="bash",
                            arguments=json.dumps({"command": "echo probing"}),
                        )
                    ]
                ),
                usage=Usage(input_tokens=1, output_tokens=1),
            )

        spec = _spec(
            tmp_path, "dead",
            budget_regular_s=0.15, budget_loop_s=0.15,
            max_attempts=2, max_turns=500, redrive_max=0,
        )
        records = Orchestrator(
            lambda s: LoopForever([]), _prompt_for, slots=1
        ).run([spec])
        rec = records[0]
        assert rec.status == "failed"
        assert "deadline" in rec.stop_reasons
        assert rec.flags == []  # 从未出 flag,验收从未满足


class TestTimeline:
    def test_jsonl_events_complete(self, tmp_path):
        tl = Timeline(tmp_path / "timeline.jsonl")
        specs = [_spec(tmp_path, f"tk{i}") for i in range(2)]
        Orchestrator(
            lambda s: ScriptedClient([_flag_turn(s.task_id)]), _prompt_for,
            slots=2, timeline=tl,
        ).run(specs)

        lines = [
            json.loads(line)
            for line in (tmp_path / "timeline.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        events = [ln["event"] for ln in lines]
        assert events[0] == "mission_start" and events[-1] == "mission_end"
        assert events.count("task_start") == 2
        assert events.count("task_end") == 2
        assert sum(1 for ln in lines if ln["event"] == "task_attempt") >= 2
        # 每行都有 ts 与 event 字段(章程:按行记录每步)
        assert all({"ts", "event"} <= ln.keys() for ln in lines)


class TestPassClock:
    def test_render_injects_metadata(self, tmp_path):
        from hexhammer.control import PassClock

        spec = _spec(tmp_path, "clk", budget_regular_s=60, budget_loop_s=120)
        clock = PassClock(spec)
        clock.open()
        time.sleep(0.05)
        clock.close()
        line = clock.render(1, 2)
        assert "pass=1" in line and "attempt=2" in line
        assert "budget_min=1" in line and "over_budget=no" in line
        assert clock.remaining_for(1) < 60


class TestMission2Fixes:
    """2026-09-21 mission2 三连灭的修复回归:目录防呆 / 自定义验收 / 尸体阶段跳过。"""

    def test_workspace_autocreated(self, tmp_path):
        ws = tmp_path / "never-created" / "t"
        spec = TaskSpec(task_id="t", goal="g", domain="web", workspace=ws)
        assert not ws.exists()
        records = Orchestrator(
            lambda s: ScriptedClient([_flag_turn("flag{mk}")]),
            _prompt_for, slots=1,
        ).run([spec])
        assert records[0].status == "accepted"
        assert ws.is_dir()  # 防呆:调用方忘建目录不再弄死 bash 的 cwd

    def test_acceptance_fn_override_report_based(self, tmp_path):
        def write_notes_client():
            return ScriptedClient(
                [
                    LLMResponse(
                        turn=AssistantTurn(
                            tool_calls=[
                                ToolCall(
                                    id="c1",
                                    name="write",
                                    arguments=json.dumps(
                                        {"path": "notes.md", "content": "结论:环境正常,可以干活。"}
                                    ),
                                )
                            ]
                        ),
                        usage=Usage(input_tokens=1, output_tokens=1),
                    )
                ]
            )

        def report_ok(ws, inbox):
            target = ws / "notes.md"
            return target.is_file() and len(target.read_text()) > 5

        spec = TaskSpec(
            task_id="rep", goal="g", domain="web",
            workspace=tmp_path / "rep", acceptance_fn=report_ok,
        )
        records = Orchestrator(
            lambda s: write_notes_client(), _prompt_for, slots=1
        ).run([spec])
        assert records[0].status == "accepted" and records[0].flags == []

    def test_loop_budget_exhausted_skips_phase2(self, tmp_path):
        import time as _t

        def burn_turn():
            return LLMResponse(
                turn=AssistantTurn(
                    tool_calls=[
                        ToolCall(
                            id="c1", name="bash",
                            arguments=json.dumps({"command": "echo probing"}),
                        )
                    ]
                ),
                usage=Usage(input_tokens=1, output_tokens=1),
            )

        class Burner(ScriptedClient):
            def chat(self, system, conversation, tools=None):
                _t.sleep(0.05)
                return burn_turn()

        spec = _spec(
            tmp_path, "burn",
            budget_regular_s=0.8, budget_loop_s=5.0,  # loop 剩余必 < 60s 阈值
            max_attempts=1, max_turns=500, redrive_max=0,
        )
        records = Orchestrator(lambda s: Burner([]), _prompt_for, slots=1).run([spec])
        rec = records[0]
        assert rec.stop_reasons == ["deadline", "loop_budget_exhausted"]
        assert rec.phase == 1  # phase2 从未开跑


class TestAbsorbFlags:
    def test_finding_empty_flag_not_absorbed(self, tmp_path):
        """finding 条目 flag 为空串:吸收进 record.flags 会污染旗标计数(实测 0003)。"""

        from hexhammer.control.orchestrator import TaskRecord
        from hexhammer.inbox import FindingsInbox

        inbox = FindingsInbox(tmp_path / "flags.json")
        inbox.add_finding("测试发现", "证据", kind="vuln")
        inbox.add("flag{real}", source="test")
        record = TaskRecord(spec=None)  # type: ignore[arg-type]
        Orchestrator._absorb_flags(record, inbox)
        assert record.flags == ["flag{real}"]


class TestConversationPersistence:
    def test_conversation_file_written_per_attempt(self, tmp_path):
        """#14 复现:真实 mission 里 conversation.json 从未落盘(0004/0005/0007)。
        线程池 + 两 attempt + acceptance 场景下断言每步落盘。"""
        from hexhammer.tools import default_registry

        ws = tmp_path / "t-conv"
        spec = _spec(
            ws, "conv",
            acceptance_fn=lambda w, inbox: (w / "notes.md").exists(),
            max_attempts=2, max_turns=4, redrive_max=0,
        )

        def write_notes_turn():
            from hexhammer.llm.types import ToolCall
            return LLMResponse(
                turn=AssistantTurn(tool_calls=[
                    ToolCall(id="c1", name="write",
                             arguments=json.dumps({"path": "notes.md", "content": "x" * 20})),
                ]),
                usage=Usage(input_tokens=1, output_tokens=1),
            )

        class ConvClient(ScriptedClient):
            def chat(self, system, conversation, tools=None):
                return write_notes_turn()

        records = Orchestrator(
            lambda s: ConvClient([]), _prompt_for, slots=1,
            registry=default_registry(),
        ).run([spec])
        assert records[0].status == "accepted"
        # accepted 后 clear 挪档:归档必须在(spec.workspace,非 _spec 的 tmp_path)
        assert (spec.workspace / "tmp" / "conversation-final.json").is_file(), (
            "accepted 清档后应有会话归档(#14)"
        )
        # 失败中间态也必须落过盘:归档内容含真实会话(非空 items)
        import json as _json
        archived = _json.loads(
            (spec.workspace / "tmp" / "conversation-final.json").read_text()
        )
        assert len(archived.get("items", [])) >= 3  # goal + assistant + tool
