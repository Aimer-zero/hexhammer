"""封禁感知测试:状态转移检测、退避判据、Http/Nmap 工具层接入。"""

import json

import httpx
import pytest

from hexhammer.tools import ToolContext, default_registry
from hexhammer.tools.recon_state import ReconState


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


class TestReconState:
    def test_two_transitions_trigger_backoff(self, tmp_path):
        state = ReconState(tmp_path)
        state.record("h", 80, "open")
        state.record("h", 80, "error")
        assert state.verdict("h") == ""  # 单口转移不触发
        state.record("h", 53, "open")
        state.record("h", 53, "filtered")
        verdict = state.verdict("h")
        assert "动态封禁" in verdict and "53/tcp open→filtered" in verdict
        assert "被动" in verdict  # 指路:转被动/收尾

    def test_streak_rule(self, tmp_path):
        state = ReconState(tmp_path)
        state.record("h", 80, "open")
        state.record("h", 80, "error")
        state.record("h", 80, "error")
        assert state.verdict("h") == ""  # 连错 2 不触发
        state.record("h", 80, "error")
        assert "连续错误 ×3" in state.verdict("h")

    def test_errors_without_prior_open_do_not_trigger(self, tmp_path):
        state = ReconState(tmp_path)
        for _ in range(5):
            state.record("h", 80, "error")
        assert state.verdict("h") == ""  # 从未 open 过:可能只是服务没起

    def test_persistence_across_instances(self, tmp_path):
        ReconState(tmp_path).record("h", 22, "open")
        assert len(ReconState(tmp_path).records_for("h")) == 1

    def test_host_isolation(self, tmp_path):
        state = ReconState(tmp_path)
        state.record("a", 80, "open")
        state.record("a", 80, "error")
        state.record("b", 80, "error")
        assert state.verdict("b") == ""


class TestHttpIntegration:
    def test_backoff_after_success_then_failures(self, tmp_path):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(200, content="ok")
            raise httpx.ConnectError("dropped")

        registry = default_registry(transport=httpx.MockTransport(handler))
        ctx = _ctx(tmp_path)
        url = "http://t.example/"

        content, is_error = registry.dispatch("http", json.dumps({"method": "GET", "url": url}), ctx)
        assert not is_error and "200" in content
        # 成功被记录为 open
        assert any(r["state"] == "open" for r in ReconState(tmp_path).records_for("t.example"))

        for _ in range(3):  # 三连失败 → 连错条纹到 3
            _, is_error = registry.dispatch("http", json.dumps({"method": "GET", "url": url}), ctx)
            assert is_error

        # 第四次:请求发出前就被退避判据拒绝,并给出指路
        content, is_error = registry.dispatch("http", json.dumps({"method": "GET", "url": url}), ctx)
        assert is_error and "动态封禁" in content and "被动" in content
        assert calls["n"] == 4  # 第 5 次调度没有真的发请求


class TestNmapIntegration:
    def test_verdict_blocks_before_scan(self, tmp_path):
        state = ReconState(tmp_path)
        state.record("10.9.9.9", 80, "open")
        for _ in range(3):
            state.record("10.9.9.9", 80, "error")

        registry = default_registry()
        content, is_error = registry.dispatch(
            "nmap", json.dumps({"target": "10.9.9.9", "top_ports": 10}), _ctx(tmp_path)
        )
        assert is_error and "动态封禁" in content


class TestSnapshot:
    """时效性:每端口最后状态 + 年龄;过期数据打复核标记。"""

    def test_snapshot_empty_without_records(self, tmp_path):
        assert ReconState(tmp_path).snapshot("h") == ""

    def test_snapshot_shows_age_and_stale_warning(self, tmp_path):
        import time as time_mod

        state = ReconState(tmp_path)
        state.record("h", 80, "open")
        fresh = state.snapshot("h", now=time_mod.time() + 60)
        assert "80/tcp open" in fresh and "复核" not in fresh
        stale = state.snapshot("h", now=time_mod.time() + 7200)
        assert "80/tcp open" in stale and "2.0h" in stale and "复核" in stale

    def test_snapshot_keeps_last_state_per_port(self, tmp_path):
        state = ReconState(tmp_path)
        state.record("h", 80, "open")
        state.record("h", 80, "error")
        snap = ReconState(tmp_path).snapshot("h")
        assert "80/tcp error" in snap and "80/tcp open" not in snap


class TestEnforceAutoFinding:
    """退避触发时自动把『防护存在』落 finding——不依赖模型自觉执行指引。"""

    def test_enforce_raises_and_records_finding(self, tmp_path):
        from hexhammer.inbox import FindingsInbox
        from hexhammer.tools.base import ToolError

        state = ReconState(tmp_path)
        for port in (80, 53):
            state.record("h", port, "open")
            state.record("h", port, "filtered")
        with pytest.raises(ToolError, match="动态封禁"):
            state.enforce("h")
        entries = FindingsInbox(tmp_path / "flags.json").findings()
        assert len(entries) == 1 and "动态封禁" in entries[0]["title"]

    def test_enforce_finding_idempotent(self, tmp_path):
        from hexhammer.inbox import FindingsInbox
        from hexhammer.tools.base import ToolError

        state = ReconState(tmp_path)
        for port in (80, 53):
            state.record("h", port, "open")
            state.record("h", port, "filtered")
        with pytest.raises(ToolError):
            state.enforce("h")
        with pytest.raises(ToolError):
            state.enforce("h")  # 第二次拦截不再重复落 finding
        assert len(FindingsInbox(tmp_path / "flags.json").findings()) == 1

    def test_enforce_noop_when_clear(self, tmp_path):
        state = ReconState(tmp_path)
        state.enforce("h")  # 无判据:静默放行
        assert not (tmp_path / "flags.json").exists()


class TestBypass403Integration:
    def test_bypass403_blocked_before_firing(self, tmp_path):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(403, content="denied")

        state = ReconState(tmp_path)
        for port in (80, 443):
            state.record("t.example", port, "open")
            state.record("t.example", port, "filtered")

        registry = default_registry(transport=httpx.MockTransport(handler))
        content, is_error = registry.dispatch(
            "bypass403", json.dumps({"url": "http://t.example/admin"}), _ctx(tmp_path)
        )
        assert is_error and "动态封禁" in content
        assert calls["n"] == 0  # 一发未出:拦截在请求前

    def test_bypass403_errors_feed_state(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dropped")

        registry = default_registry(transport=httpx.MockTransport(handler))
        content, is_error = registry.dispatch(
            "bypass403", json.dumps({"url": "http://t.example/admin"}), _ctx(tmp_path)
        )
        assert not is_error  # 工具自身不因单源失败报错
        states = [r["state"] for r in ReconState(tmp_path).records_for("t.example")]
        assert states.count("error") >= 10  # 变体失败全部入账

    def test_bypass403_blocked_after_prior_open_then_blackout(self, tmp_path):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            raise httpx.ConnectError("dropped")

        state = ReconState(tmp_path)
        state.record("t.example", 80, "open")  # 曾探通(真实场景:先 open 后黑洞)

        registry = default_registry(transport=httpx.MockTransport(handler))
        registry.dispatch(
            "bypass403", json.dumps({"url": "http://t.example/admin"}), _ctx(tmp_path)
        )  # 一轮 ~25 变体全失败 → 连错条纹爆表
        content, is_error = registry.dispatch(
            "bypass403", json.dumps({"url": "http://t.example/admin"}), _ctx(tmp_path)
        )
        assert is_error and "动态封禁" in content
        assert calls["n"] < 50  # 第二轮被拦,没有再齐射


class TestExpandPorts:
    """nmap 差集的覆盖集合解析:解析不了宁可放弃差集,不误记 filtered。"""

    def test_plain_list(self):
        from hexhammer.tools.attack import _expand_ports

        assert _expand_ports("21,22,80") == {21, 22, 80}

    def test_ranges(self):
        from hexhammer.tools.attack import _expand_ports

        assert _expand_ports("80-82") == {80, 81, 82}

    def test_mixed_with_protocol_prefix(self):
        from hexhammer.tools.attack import _expand_ports

        assert _expand_ports("T:80,443") == {80, 443}

    def test_unparseable_returns_none(self):
        from hexhammer.tools.attack import _expand_ports

        assert _expand_ports("-") is None
        assert _expand_ports("8O,443") is None  # 字母 O 混入:整体放弃
        assert _expand_ports("") is None


class TestSnapshotAttached:
    def test_http_output_carries_recon_state(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content="ok")

        ReconState(tmp_path).record("t.example", 80, "open")
        registry = default_registry(transport=httpx.MockTransport(handler))
        content, is_error = registry.dispatch(
            "http", json.dumps({"method": "GET", "url": "http://t.example/"}), _ctx(tmp_path)
        )
        assert not is_error
        assert "[recon-state]" in content and "80/tcp open" in content
