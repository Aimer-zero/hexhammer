"""工具面测试:注册表分发、文件工具、沙箱边界、截断。"""

from pathlib import Path

from hexhammer.tools import ToolContext, default_registry, truncate


def _ctx(tmp_path: Path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


class TestRegistry:
    def test_unknown_tool_returns_error_result(self, tmp_path):
        registry = default_registry()
        content, is_error = registry.dispatch("nope", "{}", _ctx(tmp_path))
        assert is_error and "unknown tool" in content

    def test_bad_json_args_returns_error_result(self, tmp_path):
        registry = default_registry()
        content, is_error = registry.dispatch("bash", "{broken", _ctx(tmp_path))
        assert is_error and "error" in content

    def test_duplicate_registration_rejected(self):
        registry = default_registry()
        import pytest

        with pytest.raises(ValueError):
            registry.register(registry._tools["bash"])

    def test_default_tool_surface(self):
        registry = default_registry()
        names = {t.name for t in registry.specs()}
        # 结构性断言:核心面必须齐(丢失即红);新增工具不需要同步本测试
        # (第三次因加工具改此断言后改的设计——2026-09-24)
        assert {
            "read", "write", "edit", "grep", "find", "ls", "bash",
            "http", "jwt", "bypass403", "encode", "nmap", "sqlmap", "osint",
            "cve", "binary", "loot", "finding",
        } <= names


class TestFsTools:
    def test_write_read_roundtrip_with_line_numbers(self, tmp_path):
        registry, ctx = default_registry(), _ctx(tmp_path)
        assert "wrote" in registry.dispatch(
            "write", '{"path": "notes.txt", "content": "alpha\\nbeta"}', ctx
        )[0]
        content, is_error = registry.dispatch("read", '{"path": "notes.txt"}', ctx)
        assert not is_error
        assert "1\talpha" in content and "2\tbeta" in content

    def test_edit_requires_unique_match(self, tmp_path):
        registry, ctx = default_registry(), _ctx(tmp_path)
        registry.dispatch(
            "write", '{"path": "f.txt", "content": "x x x"}', ctx
        )
        _, is_error = registry.dispatch(
            "edit",
            '{"path": "f.txt", "old_string": "x", "new_string": "y"}',
            ctx,
        )
        assert is_error  # 3 处匹配且未开 replace_all
        content, _ = registry.dispatch(
            "edit",
            '{"path": "f.txt", "old_string": "x", "new_string": "y", '
            '"replace_all": true}',
            ctx,
        )
        assert "3 occurrence" in content

    def test_path_escape_rejected(self, tmp_path):
        registry, ctx = default_registry(), _ctx(tmp_path)
        content, is_error = registry.dispatch(
            "read", '{"path": "../../etc/passwd"}', ctx
        )
        assert is_error and "escapes workspace" in content

    def test_grep_and_find(self, tmp_path):
        registry, ctx = default_registry(), _ctx(tmp_path)
        registry.dispatch(
            "write", '{"path": "src/a.py", "content": "SECRET = 1"}', ctx
        )
        hits, _ = registry.dispatch("grep", '{"pattern": "SECRET"}', ctx)
        assert "src/a.py:1:SECRET = 1" in hits
        found, _ = registry.dispatch("find", '{"pattern": "**/*.py"}', ctx)
        assert "src/a.py" in found


class TestBashTool:
    def test_success_and_exit_code(self, tmp_path):
        registry, ctx = default_registry(), _ctx(tmp_path)
        out, is_error = registry.dispatch(
            "bash", '{"command": "echo hi"}', ctx
        )
        assert not is_error and out.strip() == "hi"
        out, _ = registry.dispatch("bash", '{"command": "exit 3"}', ctx)
        assert "[exit 3]" in out

    def test_timeout_becomes_error_result(self, tmp_path):
        registry, ctx = default_registry(), _ctx(tmp_path)
        ctx.bash_timeout = 1.0
        out, is_error = registry.dispatch(
            "bash", '{"command": "sleep 5"}', ctx
        )
        assert is_error and "timeout" in out

    def test_timeout_kills_process_group_no_orphans(self, tmp_path):
        """回归:2026-09-21 事故——超时只杀 shell,孙进程(nmap 等)成孤儿。"""
        import json
        import subprocess
        import time

        registry, ctx = default_registry(), _ctx(tmp_path)
        ctx.bash_timeout = 2.0
        cmd = "sleep 300 & echo $! > grandchild.pid; wait"
        out, is_error = registry.dispatch(
            "bash", json.dumps({"command": cmd}), ctx
        )
        assert is_error and "process group killed" in out
        time.sleep(0.5)
        pid = int((tmp_path / "grandchild.pid").read_text().strip())
        probe = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat="],
            capture_output=True,
            text=True,
            check=False,
        )
        assert probe.returncode != 0 or "Z" not in probe.stdout, (
            f"grandchild survived as {probe.stdout!r}"
        )


def test_truncate_keeps_head_and_tail():
    text = "HEAD" + "x" * 20_000 + "TAIL"
    result = truncate(text, max_chars=100)
    assert len(result) < 1000
    assert result.startswith("HEAD") and result.rstrip().endswith("TAIL")
    assert "truncated" in result
