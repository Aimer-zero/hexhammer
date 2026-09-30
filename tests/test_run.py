"""hexhammer.run 入口测试:goal 装配、授权档位、spec 组装、验收函数。"""

import pytest

from hexhammer.inbox import FindingsInbox
from hexhammer.run import build_goal, build_specs


class TestBuildGoal:
    def test_mode_routing(self):
        for mode in ("recon", "webapp"):  # chain 由 build_specs 分解,无独立 goal
            goal = build_goal(mode, "1.2.3.4", "", rce_proof=False)
            assert "1.2.3.4" in goal
            assert "纪律" in goal
        assert "端口" in build_goal("recon", "t", "", False)
        assert "openapi" in build_goal("webapp", "t", "", False)

    def test_unknown_mode_rejected(self):
        with pytest.raises(ValueError):
            build_goal("pwn", "t", "", False)

    def test_default_auth_is_readonly(self):
        goal = build_goal("webapp", "t", "", rce_proof=False)
        assert "只读" in goal and "禁止任何改写" in goal
        assert "RCE 证明" not in goal.split("纪律")[0]

    def test_rce_proof_upgrades_auth(self):
        goal = build_goal("webapp", "t", "", rce_proof=True)
        assert "RCE 证明" in goal
        assert "禁止:落盘" in goal and "证完即撤" in goal

    def test_domain_hint(self):
        assert "(关联域名:example.com)" in build_goal("recon", "1.2.3.4", "example.com", False)


class TestBuildSpecs:
    def test_chain_makes_two_serial_specs(self, tmp_path):
        specs = build_specs("chain", "1.2.3.4", "", False, tmp_path, 30.0)
        assert [s.task_id for s in specs] == ["recon", "webapp"]
        assert specs[0].budget_regular_s == 1800.0  # min(30min, cap)
        assert specs[1].domain == "web" and specs[0].domain == "pentest"

    def test_single_modes(self, tmp_path):
        assert len(build_specs("recon", "t", "", False, tmp_path, 10)) == 1
        assert len(build_specs("webapp", "t", "", False, tmp_path, 10)) == 1

    def test_small_budget_not_capped(self, tmp_path):
        specs = build_specs("webapp", "t", "", False, tmp_path, 10)
        assert specs[0].budget_regular_s == 600.0


class TestAcceptance:
    def test_webapp_requires_finding(self, tmp_path):
        spec = build_specs("webapp", "t", "", False, tmp_path, 10)[0]
        accept = spec.acceptance_fn
        notes = tmp_path / "webapp" / "notes.md"
        notes.parent.mkdir(parents=True)
        notes.write_text("x" * 500 + " 结论", encoding="utf-8")
        inbox = FindingsInbox(tmp_path / "webapp" / "flags.json")
        assert not accept(notes.parent, inbox)  # 报告够格但无 finding
        inbox.add_finding("洞", "证据")
        assert accept(notes.parent, inbox)

    def test_recon_keywords(self, tmp_path):
        spec = build_specs("recon", "t", "", False, tmp_path, 10)[0]
        ws = tmp_path / "recon"
        ws.mkdir()
        (ws / "notes.md").write_text("y" * 500, encoding="utf-8")  # 缺"端口/结论"
        inbox = FindingsInbox(ws / "flags.json")
        assert not spec.acceptance_fn(ws, inbox)
        (ws / "notes.md").write_text("端口扫描…结论成立 " + "y" * 500, encoding="utf-8")
        assert spec.acceptance_fn(ws, inbox)


class TestDoctor:
    def test_reports_all_deps(self, capsys):
        from hexhammer.run import doctor
        found = doctor()
        assert "nmap" in found and "docker" in found
        out = capsys.readouterr().out
        assert "✓" in out or "✗" in out
        # 缺失项必须给安装指引
        for name, hit in found.items():
            if hit is None:
                assert "→" in out  # 安装命令提示存在


class TestChat:
    def test_one_round_trip_with_tools(self, tmp_path):
        """注入伪 client 与输入序列:一轮 user→工具调用→文本回复→退出。"""
        import json as _json

        from hexhammer.llm.types import AssistantTurn, LLMResponse, ToolCall, Usage
        from hexhammer.run import chat

        class FakeClient:
            def __init__(self):
                self.n = 0

            def chat(self, system, conversation, tools=None):
                self.n += 1
                if self.n == 1:
                    return LLMResponse(turn=AssistantTurn(tool_calls=[
                        ToolCall(id="c1", name="encode",
                                 arguments=_json.dumps({"op": "encode", "scheme": "base64", "text": "hi"})),
                    ]), usage=Usage())
                return LLMResponse(turn=AssistantTurn(text="完成:aGk="), usage=Usage())

        printed: list[str] = []
        convo = chat(
            target="1.2.3.4",
            workspace=tmp_path / "ws",
            client=FakeClient(),
            input_fn=iter(["curl 一下首页", "exit"]).__next__,
            print_fn=printed.append,
        )
        joined = "\n".join(printed)
        assert "[✓ encode]" in joined          # 工具调用逐轮显示
        assert "完成:aGk=" in joined            # 最终文本回复
        assert "1.2.3.4" in joined              # 目标注入对用户可见
        # 会话贯穿且首条含完整授权上下文
        items = convo.items()
        assert items[0][0] == "user"
        assert "1.2.3.4" in items[0][1] and "只在此目标" in items[0][1]
        assert len([r for r, _ in items if r == "assistant"]) == 2

    def test_clear_resets_conversation(self, tmp_path):
        from hexhammer.llm.types import AssistantTurn, LLMResponse, Usage
        from hexhammer.run import chat

        class FakeClient:
            def chat(self, system, conversation, tools=None):
                return LLMResponse(turn=AssistantTurn(text="ok"), usage=Usage())

        convo = chat(
            workspace=tmp_path / "ws",
            client=FakeClient(),
            input_fn=iter(["第一句", "clear", "第二句", "exit"]).__next__,
            print_fn=lambda *_: None,
        )
        # clear 后只剩"第二句"起的会话
        users = [p for r, p in convo.items() if r == "user"]
        assert users == ["第二句"]


class TestChatInterrupt:
    def test_keyboard_interrupt_mid_reply_keeps_repl_alive(self, tmp_path):
        """Ctrl+C 打断当前回复:REPL 不崩,继续收下一输入(用户实测崩溃)。"""
        import json as _json

        from hexhammer.llm.types import AssistantTurn, LLMResponse, ToolCall, Usage
        from hexhammer.run import chat

        class InterruptingClient:
            def __init__(self):
                self.n = 0

            def chat(self, system, conversation, tools=None):
                self.n += 1
                if self.n == 1:  # 第一轮:发起工具调用
                    return LLMResponse(turn=AssistantTurn(tool_calls=[
                        ToolCall(id="c1", name="encode",
                                 arguments=_json.dumps({"op": "encode", "scheme": "base64", "text": "x"})),
                    ]), usage=Usage())
                raise KeyboardInterrupt  # 第二轮(模拟用户在等待时 Ctrl+C)

        printed: list[str] = []
        convo = chat(
            workspace=tmp_path / "ws",
            client=InterruptingClient(),
            input_fn=iter(["干活", "exit"]).__next__,
            print_fn=printed.append,
        )
        joined = "\n".join(printed)
        assert "已中断本轮回复" in joined       # 中断被捕获并提示
        assert any(r == "assistant" for r, _ in convo.items())  # 会话保留(第一轮 assistant 在)
        # REPL 存活并处理了后续 exit

    def test_ctx_wording_no_autonomous_scan(self, tmp_path):
        """上下文注入必须包含『不要主动发起扫描』——修『你好也开扫』。"""
        from hexhammer.llm.types import AssistantTurn, LLMResponse, Usage
        from hexhammer.run import chat

        class Idle:
            def chat(self, system, conversation, tools=None):
                return LLMResponse(turn=AssistantTurn(text="你好!"), usage=Usage())

        convo = chat(
            target="1.2.3.4",
            workspace=tmp_path / "ws",
            client=Idle(),
            input_fn=iter(["你好", "exit"]).__next__,
            print_fn=lambda *_: None,
        )
        first_user = next(p for r, p in convo.items() if r == "user")
        assert "只在此目标范围内" in first_user
        assert "不要主动发起" in first_user


class TestTargetSwitch:
    def test_target_command_rescopes_and_reinjects(self, tmp_path):
        """/target 切换:旧目标解除,下一条消息携带新授权上下文。"""
        from hexhammer.llm.types import AssistantTurn, LLMResponse, Usage
        from hexhammer.run import chat

        captured: list[str] = []

        class Rec:
            def chat(self, system, conversation, tools=None):
                captured.append(conversation.items()[-1][1])
                return LLMResponse(turn=AssistantTurn(text="ok"), usage=Usage())

        convo = chat(
            workspace=tmp_path / "ws",
            client=Rec(),
            input_fn=iter([
                "/target 9.9.9.9",
                "curl 一下首页",
                "exit",
            ]).__next__,
            print_fn=lambda *_: None,
        )
        # 切换不发请求(无多余 LLM 调用);切换后的消息带新目标前缀,不含旧目标
        assert len(captured) == 1
        assert "9.9.9.9" in captured[0]
        users = [p for r, p in convo.items() if r == "user"]
        assert len(users) == 1 and "9.9.9.9" in users[0]
