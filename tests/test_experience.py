"""经验库测试:存储/校验/匹配/渲染、蒸馏(fail-open+pending 落盘)、人审入库。"""

import json

import pytest

from hexhammer.experience import (
    ExperienceEntry,
    ExperienceStore,
    distill,
    review,
)
from hexhammer.llm.types import AssistantTurn, LLMResponse, Usage


def _entry(**kw) -> ExperienceEntry:
    base = dict(
        kind="lock",
        domain="web",
        condition="云防护目标的高频探测",
        finding="单发间隔>=2s 全程不触发封禁",
        evidence="mission-001 notes §0 接入方式",
        origin="mission-001",
    )
    base.update(kw)
    return ExperienceEntry(**base)


class TestStore:
    def test_roundtrip_and_validate(self, tmp_path):
        store = ExperienceStore(tmp_path / "lib.jsonl")
        store.add(_entry())
        loaded = ExperienceStore(tmp_path / "lib.jsonl").load()
        assert len(loaded) == 1 and loaded[0].kind == "lock"

        with pytest.raises(ValueError):
            store.add(_entry(evidence=""))  # 证据缺失 = 非法

    def test_match_domain_and_boost(self, tmp_path):
        store = ExperienceStore(tmp_path / "lib.jsonl")
        store.add(_entry(kind="confirmed", domain="pentest", confidence=1))
        store.add(_entry(kind="lock", domain="web", confidence=2))
        store.add(_entry(kind="pattern", domain="general", confidence=5,
                         condition="任意网络服务的基础指纹"))
        hits = store.match("web", traits="8443 云防护目标")
        # web + general 命中;条件特征命中的 web 条目加权越过高 confidence 的 general
        assert {e.domain for e in hits} == {"web", "general"}
        assert hits[0].domain == "web"

    def test_render_budget(self, tmp_path):
        store = ExperienceStore(tmp_path / "lib.jsonl")
        for i in range(10):
            store.add(_entry(finding=f"手法 {i} " + "x" * 300))
        text = store.render(store.match("web"))
        assert text.startswith("[历史经验]")
        assert len(text) < 2600 and "预算截断" in text


class TestDistill:
    def _mission(self, tmp_path):
        ws = tmp_path / "val" / "000x-demo"
        ws.mkdir(parents=True)
        task = ws / "webapp"
        task.mkdir()
        (task / "notes.md").write_text(
            "# 演示\n## 结论\n" + "过程与证据 " * 60, encoding="utf-8"
        )
        (task / "flags.json").write_text(json.dumps([
            {"kind": "vuln", "severity": "high", "title": "全部端点未鉴权"},
        ]), encoding="utf-8")
        (ws / "timeline.jsonl").write_text(
            '{"event":"task_start","task_id":"t"}\n{"event":"task_end","task_id":"t","status":"accepted"}\n',
            encoding="utf-8",
        )
        return ws

    def test_distill_writes_pending(self, tmp_path):
        ws = self._mission(tmp_path)

        class FakeClient:
            def chat(self, system, conversation, tools=None):
                assert "复盘蒸馏官" in system
                return LLMResponse(turn=AssistantTurn(text=json.dumps([
                    {"kind": "lock", "domain": "web",
                     "condition": "云防护目标", "finding": "慢速单发",
                     "evidence": "mission-demo notes §结论", "origin": "mission-demo"},
                    {"kind": "bad-kind", "domain": "web",
                     "condition": "x", "finding": "y", "evidence": "z"},
                ])), usage=Usage())

        entries = distill(ws, FakeClient(), mission_id="000x-demo")
        assert len(entries) == 1  # 非法 kind 被校验拒绝
        assert (ws / "experience-pending.jsonl").is_file()

    def test_distill_failopen(self, tmp_path):
        ws = self._mission(tmp_path)

        class Broken:
            def chat(self, system, conversation, tools=None):
                raise RuntimeError("gateway down")

        assert distill(ws, Broken(), mission_id="x") == []
        assert not (ws / "experience-pending.jsonl").exists()


class TestReview:
    def test_pending_to_library_with_dedup(self, tmp_path, monkeypatch):
        from hexhammer import experience as exp

        ws = self._ws(tmp_path)
        pending = ExperienceStore(ws / "experience-pending.jsonl")
        e1 = _entry(origin="mission-001")
        e2 = _entry(finding="MCP 端点未认证可枚举工具面", origin="mission-002")
        pending.add_many([e1, e2])

        lib_path = tmp_path / "library.jsonl"
        monkeypatch.setattr(exp, "default_library_path", lambda: lib_path)

        printed: list[str] = []
        review(ws, approve_all=False, print_fn=printed.append)
        assert not lib_path.exists()  # 未批准不入库
        assert "待审" in "\n".join(printed)

        printed.clear()
        merged = review(ws, approve_all=True, print_fn=printed.append)
        assert len(merged) == 2 and lib_path.is_file()

        # 二次批准:去重,不重复入库
        merged_again = review(ws, approve_all=True, print_fn=printed.append)
        assert len(merged_again) == 0
        assert len(ExperienceStore(lib_path).load()) == 2

    @staticmethod
    def _ws(tmp_path):
        ws = tmp_path / "val" / "000y"
        ws.mkdir(parents=True)
        return ws
