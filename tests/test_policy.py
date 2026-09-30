"""命令策略测试:nmap 形状白名单、速率上限、防重复、指路语义。

形状类用例直接测 CommandPolicy.check(纯函数,不执行命令);
只有防重复/旁路用例走 bash 工具真执行(echo,毫秒级)。
"""

import json

from hexhammer.tools import ToolContext, default_registry
from hexhammer.tools.policy import CommandPolicy, _nmap_min_rate, _nmap_port_span


def _ctx(tmp_path, **policy_kw) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path, policy=CommandPolicy(**policy_kw))


class TestNmapShape:
    """纯策略层:命令不执行,只判形状。"""

    def test_full_range_rejected(self):
        policy = CommandPolicy()
        for command in (
            "nmap -sT -Pn -p- 10.0.0.1",
            "nmap -sT -Pn -p 1-65535 10.0.0.1",
            "nmap -p 1-10000 10.0.0.1",
        ):
            allowed, message = policy.check(command)
            assert not allowed, command
            assert "端口跨度" in message

    def test_polite_shapes_allowed(self):
        policy = CommandPolicy()
        for command in (
            "nmap -sT -Pn --top-ports 200 --max-rate 300 --open 10.0.0.1",
            "nmap -sT -Pn -p 21,22,80,8443 --max-rate 300 10.0.0.1",
            "nmap -sT -Pn -p 1-2000 --max-rate 300 10.0.0.1",  # 跨度在上限内
        ):
            allowed, message = policy.check(command)
            assert allowed, (command, message)

    def test_min_rate_cap(self):
        policy = CommandPolicy()
        allowed, message = policy.check("nmap -p 1-100 --min-rate 2000 10.0.0.1")
        assert not allowed and "min-rate" in message
        allowed, _ = policy.check("nmap -p 1-100 --min-rate 500 10.0.0.1")
        assert allowed

    def test_parsers(self):
        assert _nmap_port_span("nmap -p- x") == 65535
        assert _nmap_port_span("nmap -p 1-5000 x") == 5000
        assert _nmap_port_span("nmap -p 21,22,80,8443 x") == 4
        assert _nmap_port_span("nmap -pT:80,U:53 x") == 2
        assert _nmap_port_span("nmap --top-ports 100 x") is None
        assert _nmap_min_rate("nmap --min-rate 2000 x") == 2000
        assert _nmap_min_rate("nmap --min-rate=800 x") == 800
        assert _nmap_min_rate("nmap x") is None

    def test_non_nmap_never_shape_rejected(self):
        policy = CommandPolicy()
        allowed, _ = policy.check("curl -sS -m 10 http://10.0.0.1/")
        assert allowed


class TestDispatchIntegration:
    """bash 工具入口:拒绝发生在执行之前;重复守卫按 ctx 隔离。"""

    def test_rejected_command_never_executes_with_guidance(self, tmp_path):
        registry = default_registry()
        content, is_error = registry.dispatch(
            "bash",
            json.dumps({"command": "nmap -p- 10.0.0.1"}),
            _ctx(tmp_path),
        )
        assert is_error
        assert "换方法" in content  # exit-75 式指路
        assert "端口跨度" in content

    def test_identical_command_blocked_after_limit(self, tmp_path):
        registry = default_registry()
        ctx = _ctx(tmp_path)  # allow_repeats=2
        cmd = json.dumps({"command": "echo dup-check"})
        results = [registry.dispatch("bash", cmd, ctx)[1] for _ in range(4)]
        assert results == [False, False, True, True]  # 前两次放行,后续拒绝

    def test_repeats_are_per_context(self, tmp_path):
        registry = default_registry()
        cmd = json.dumps({"command": "echo fresh"})
        for _ in range(3):
            # 每次新 ctx(新任务)→ 历史不串场
            _, is_error = registry.dispatch("bash", cmd, _ctx(tmp_path))
            assert not is_error

    def test_normal_echo_flows_through(self, tmp_path):
        registry = default_registry()
        content, is_error = registry.dispatch(
            "bash", json.dumps({"command": "echo 'flag{policy-ok}'"}), _ctx(tmp_path)
        )
        assert not is_error and "flag{policy-ok}" in content
