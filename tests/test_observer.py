"""observer 外圈测试:覆盖图解析/封顶、fail-open、solver 注入、压缩幸存。"""

import json

import pytest

from hexhammer.llm.types import (
    AssistantTurn,
    Conversation,
    LLMResponse,
    ToolCall,
    ToolResult,
    Usage,
)
from hexhammer.observer import (
    Observer,
    ObserverMap,
    evidence_window,
    extract_json_object,
)
from hexhammer.solver import SolverLoop
from hexhammer.tools import default_registry


def _text_turn(text: str) -> LLMResponse:
    return LLMResponse(
        turn=AssistantTurn(text=text), usage=Usage(input_tokens=1, output_tokens=1)
    )


def _tool_turn(flag: str) -> LLMResponse:
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
        self.calls = 0
        self.last_conversation: Conversation | None = None

    def chat(self, system, conversation, tools=None):
        self.calls += 1
        self.last_conversation = conversation
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


MAP_JSON = json.dumps(
    {
        "confirmed": ["10.0.0.5:8080 alive"],
        "lock": ["443 refused"],
        "angles": ["grep nuclei templates for caddy"],
        "tension": [],
    }
)


class TestObserverMap:
    def test_from_json_caps(self):
        payload = {
            "confirmed": ["x" * 500] + [f"fact{i}" for i in range(8)],
            "lock": [],
            "angles": "not-a-list",  # 类型不对→空
            "tension": None,
        }
        omap = ObserverMap.from_json(payload)
        assert len(omap.confirmed) == 6  # 条数封顶
        assert len(omap.confirmed[0]) == 160  # 字数截断
        assert omap.angles == []

    def test_render_sections(self):
        omap = ObserverMap.from_json(json.loads(MAP_JSON))
        rendered = omap.render()
        assert rendered.startswith("<hexhammer-map>") and rendered.endswith("</hexhammer-map>")
        assert "CONFIRMED" in rendered and "10.0.0.5:8080" in rendered
        assert "LOCK" in rendered and "443 refused" in rendered
        assert "ANGLES" in rendered
        assert "(none)" in rendered  # tension 空 → 占位


class TestExtractJson:
    def test_plain_and_fenced_and_prose(self):
        assert extract_json_object(MAP_JSON)["lock"] == ["443 refused"]
        assert extract_json_object(f"```json\n{MAP_JSON}\n```")["confirmed"]
        assert extract_json_object(f"思路如下...\n{MAP_JSON}\n以上。")["angles"]

    def test_garbage_raises(self):
        with pytest.raises(ValueError, match="no JSON object"):
            extract_json_object("没有任何对象")


class TestObserverFailOpen:
    def test_valid_json_returns_map(self):
        observer = Observer(ScriptedClient([_text_turn(MAP_JSON)]))
        omap = observer.observe("goal", "evidence text")
        assert omap is not None and omap.lock == ["443 refused"]

    def test_retry_then_success(self):
        observer = Observer(ScriptedClient([_text_turn("not json"), _text_turn(MAP_JSON)]))
        assert observer.observe("goal", "ev") is not None

    def test_double_failure_returns_none(self):
        observer = Observer(ScriptedClient([_text_turn("bad"), _text_turn("worse")]))
        assert observer.observe("goal", "ev") is None  # fail-open


class TestEvidenceWindow:
    def test_builds_from_tools_skips_user_and_truncates(self):
        conv = Conversation()
        conv.add_user("goal text")
        conv.add_assistant(AssistantTurn(tool_calls=[
            ToolCall(id="1", name="bash", arguments='{"command":"nmap -sT"}')
        ]))
        conv.add_tool(ToolResult(tool_call_id="1", content="80/tcp open"))
        conv.add_user("<hexhammer-map>...</hexhammer-map>")
        text = evidence_window(conv, 0, max_chars=200)
        assert "nmap" in text and "80/tcp open" in text
        assert "goal text" not in text and "hexhammer-map" not in text

        big = Conversation()
        for i in range(30):
            big.add_tool(ToolResult(tool_call_id=str(i), content="A" * 100))
        assert len(evidence_window(big, 0, max_chars=500)) <= 520


class TestSolverIntegration:
    def test_map_injected_and_survives(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        from hexhammer.inbox import FindingsInbox

        inbox = FindingsInbox(ws / "flags.json")
        script = [
            _tool_turn("flag{m1}"),   # solver turn1 → flag1,验收未达(需 2)
            _text_turn(MAP_JSON),     # observer 调用(共享 client)
            _tool_turn("flag{m2}"),   # solver turn2 → flag2 → 验收
        ]
        client = ScriptedClient(script)
        loop = SolverLoop(
            client,
            default_registry(),
            "sys",
            inbox=inbox,
            acceptance=lambda: len(inbox.all_entries()) >= 2,
            observer=Observer(client),
            observe_every=1,
            max_turns=6,
        )
        outcome = loop.run("two flags", ws)
        assert outcome.stop_reason == "acceptance"
        assert outcome.flags_found == ["flag{m1}", "flag{m2}"]
        # 覆盖图以 user 消息注入会话
        assert client.last_conversation is not None
        items = client.last_conversation.items()
        assert any(
            role == "user"
            and isinstance(payload, str)
            and payload.startswith("<hexhammer-map>")
            for role, payload in items
        )

    def test_compaction_preserves_last_map(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        client = ScriptedClient([])
        loop = SolverLoop(client, default_registry(), "sys")
        loop._last_map = "<hexhammer-map>KEEP-ME</hexhammer-map>"
        conv = Conversation()
        conv.add_user("goal")
        for i in range(20):
            conv.add_tool(ToolResult(tool_call_id=f"t{i}", content=f"out {i}"))
        loop._compact(conv)
        payloads = [p for _, p in conv.items()]
        assert any(
            isinstance(p, str) and "KEEP-ME" in p for p in payloads
        )


class TestMapInPlaceUpsert:
    def test_repeated_observe_keeps_single_map_message(self, tmp_path):
        """原位替换:多次 observe 只留一条 map 消息,长会话不膨胀(A1)。"""
        ws = tmp_path / "ws"
        ws.mkdir()
        from hexhammer.inbox import FindingsInbox

        inbox = FindingsInbox(ws / "flags.json")
        script = [
            _tool_turn("flag{r1}"), _text_turn(MAP_JSON),
            _tool_turn("flag{r2}"), _text_turn(MAP_JSON),
            _tool_turn("flag{r3}"), _text_turn(MAP_JSON),
            _tool_turn("flag{r4}"),
        ]
        client = ScriptedClient(script)
        loop = SolverLoop(
            client, default_registry(), "sys",
            inbox=inbox,
            acceptance=lambda: len(inbox.all_entries()) >= 4,
            observer=Observer(client),
            observe_every=1,
            max_turns=10,
        )
        loop.run("maps", ws)
        items = client.last_conversation.items()
        maps = [
            (role, payload) for role, payload in items
            if role == "user" and str(payload).startswith("<hexhammer-map>")
        ]
        assert len(maps) == 1  # 三次 observe,一条 map(原位覆盖)

    def test_compact_does_not_duplicate_map(self, tmp_path):
        """压缩路径:tail 里已有 map 时,幸存注入不得造成两条。"""
        from hexhammer.llm.types import ToolResult
        ws = tmp_path / "ws"
        ws.mkdir()
        client = ScriptedClient([])
        loop = SolverLoop(client, default_registry(), "sys")
        loop._last_map = "<hexhammer-map>KEEP</hexhammer-map>"
        conv = Conversation()
        conv.add_user("goal")
        for i in range(6):
            conv.add_tool(ToolResult(tool_call_id=f"t{i}", content=f"o{i}"))
        conv.add_user("<hexhammer-map>STALE</hexhammer-map>")  # 落在 tail 8 条内
        loop._compact(conv)
        maps = [p for r, p in conv.items() if r == "user" and str(p).startswith("<hexhammer-map>")]
        assert maps == ["<hexhammer-map>KEEP</hexhammer-map>"]
