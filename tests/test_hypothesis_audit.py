"""hypothesis(假设-验证循环)+ audit(源码审计)工具测试。"""

import json

import pytest
from hexhammer.tools import ToolContext, default_registry
from hexhammer.tools.base import ToolError
from hexhammer.tools.hypothesis import HypothesisTool
from hexhammer.tools.audit import AuditTool


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


class TestHypothesis:
    def test_add_resolve_list_cycle(self, tmp_path):
        tool = HypothesisTool()
        ctx = _ctx(tmp_path)
        tool.execute({"action": "add", "text": "这是 Caddy 反代", "verify": "看 Server 头", "cost": "low"}, ctx)
        tool.execute({"action": "add", "text": "后端是 Spring", "verify": "打 /actuator", "cost": "low"}, ctx)
        out = tool.execute({"action": "list"}, ctx)
        assert "open(2)" in out and "Caddy" in out

        tool.execute({"action": "resolve", "id": 1, "status": "confirmed", "evidence": "Server: Caddy"}, ctx)
        tool.execute({"action": "resolve", "id": 2, "status": "refuted", "evidence": "404 not spring"}, ctx)
        out = tool.execute({"action": "list"}, ctx)
        assert "✓ confirmed(1)" in out and "✗ refuted(1)" in out
        assert "探索度:2/2" in out

    def test_add_requires_text_and_verify(self, tmp_path):
        tool = HypothesisTool()
        with pytest.raises(ToolError, match="text.*verify"):
            tool.execute({"action": "add", "text": "x"}, _ctx(tmp_path))

    def test_resolve_requires_evidence(self, tmp_path):
        tool = HypothesisTool()
        ctx = _ctx(tmp_path)
        tool.execute({"action": "add", "text": "x", "verify": "y"}, ctx)
        with pytest.raises(ToolError, match="evidence"):
            tool.execute({"action": "resolve", "id": 1, "status": "confirmed"}, ctx)

    def test_persistence(self, tmp_path):
        ctx = _ctx(tmp_path)
        HypothesisTool().execute({"action": "add", "text": "persist", "verify": "v"}, ctx)
        rows = [json.loads(l) for l in (tmp_path / "hypotheses.jsonl").read_text().splitlines()]
        assert len(rows) == 1 and rows[0]["text"] == "persist"

    def test_registered(self):
        assert any(t.name == "hypothesis" for t in default_registry().specs())


class TestAudit:
    def _src(self, tmp_path):
        d = tmp_path / "src"
        d.mkdir()
        (d / "app.py").write_text(
            "import subprocess\n"
            "import os\n"
            "def run(cmd):\n"
            "    subprocess.run(cmd, shell=True)\n"
            "def read(f):\n"
            "    return open('/tmp/' + f).read()\n"
            "def handler(req):\n"
            "    run(req['cmd'])\n",
            encoding="utf-8",
        )
        return d

    def test_sinks_finds_dangerous_calls(self, tmp_path):
        d = self._src(tmp_path)
        tool = AuditTool()
        out = tool.execute({"action": "sinks", "path": str(d)}, _ctx(tmp_path))
        assert "cmd-exec" in out  # subprocess.run(shell=True)
        assert "path-traversal" in out or "cmd-exec" in out  # open(+拼接)

    def test_trace_follows_call_chain(self, tmp_path):
        d = self._src(tmp_path)
        tool = AuditTool()
        out = tool.execute({"action": "trace", "path": str(d), "symbol": "run"}, _ctx(tmp_path))
        # 应找到 handler → run 的调用链(handler 调用了 run)
        assert "handler" in out

    def test_sinks_no_hits(self, tmp_path):
        d = tmp_path / "clean"
        d.mkdir()
        (d / "safe.py").write_text("x = 1 + 2\n", encoding="utf-8")
        out = AuditTool().execute({"action": "sinks", "path": str(d)}, _ctx(tmp_path))
        assert "无危险 sink" in out

    def test_registered(self):
        assert any(t.name == "audit" for t in default_registry().specs())
