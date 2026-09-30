"""攻击工具包测试:零网络(MockTransport / 纯函数 / which 补丁)。"""

import httpx
import pytest

from hexhammer.tools import Registry, ToolContext, default_registry
from hexhammer.tools import attack as attack_mod
from hexhammer.tools.attack import (
    EncodeTool,
    JwtTool,
    NmapTool,
    SqlmapTool,
    _parse_nmap,
    _port_span,
)


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


def _registry(transport=None) -> Registry:
    return default_registry(transport=transport)


class TestEncode:
    def test_round_trips(self, tmp_path):
        tool, ctx = EncodeTool(), _ctx(tmp_path)
        text = "flag{编码链-42}+<>&=?"
        for scheme in ("base64", "base64url", "hex", "url", "html", "unicode"):
            encoded = tool.execute(
                {"op": "encode", "scheme": scheme, "text": text}, ctx
            )
            assert tool.execute(
                {"op": "decode", "scheme": scheme, "text": encoded}, ctx
            ) == text, scheme

    def test_rot13_self_inverse_and_iterations(self, tmp_path):
        tool, ctx = EncodeTool(), _ctx(tmp_path)
        once = tool.execute({"op": "encode", "scheme": "rot13", "text": "Attack"}, ctx)
        assert tool.execute({"op": "encode", "scheme": "rot13", "text": once}, ctx) == "Attack"
        twice = tool.execute(
            {"op": "encode", "scheme": "base64", "text": "abc", "iterations": 2}, ctx
        )
        manual = tool.execute(
            {"op": "encode", "scheme": "base64",
             "text": tool.execute({"op": "encode", "scheme": "base64", "text": "abc"}, ctx)},
            ctx,
        )
        assert twice == manual

    def test_bad_decode_is_tool_error(self, tmp_path):
        from hexhammer.tools.base import ToolError

        with pytest.raises(ToolError):
            EncodeTool().execute(
                {"op": "decode", "scheme": "hex", "text": "zz-not-hex"}, _ctx(tmp_path)
            )


class TestJwt:
    def test_forge_hs256_decode_crack(self, tmp_path):
        tool, ctx = JwtTool(), _ctx(tmp_path)
        token = tool.execute(
            {
                "action": "forge", "algorithm": "HS256", "key": "s3cr3t-key",
                "payload": {"role": "admin", "flag": "flag{jwt-ok}"},
            },
            ctx,
        )
        assert token.count(".") == 2
        decoded = tool.execute({"action": "decode", "token": token}, ctx)
        assert '"role": "admin"' in decoded and "flag{jwt-ok}" in decoded
        # crack:显式字典命中
        cracked = tool.execute(
            {"action": "crack", "token": token, "wordlist": ["wrong", "s3cr3t-key"]}, ctx
        )
        assert "CRACKED" in cracked and "s3cr3t-key" in cracked
        # crack:内置弱密钥表命中(key=secret 在表内)
        weak = tool.execute(
            {"action": "forge", "algorithm": "HS256", "key": "secret",
             "payload": {"a": 1}}, ctx
        )
        assert "CRACKED" in tool.execute({"action": "crack", "token": weak}, ctx)

    def test_forge_none_and_alg_hint(self, tmp_path):
        tool, ctx = JwtTool(), _ctx(tmp_path)
        none_token = tool.execute(
            {"action": "forge", "algorithm": "none", "payload": {"x": 1}}, ctx
        )
        assert none_token.endswith(".")
        assert '"alg": "none"' in tool.execute(
            {"action": "decode", "token": none_token}, ctx
        )
        # 非 HS256 crack → 指路 forge(算法混淆)
        hint = tool.execute({"action": "crack", "token": none_token}, ctx)
        assert "混淆" in hint or "forge" in hint

    def test_malformed_token_errors(self, tmp_path):
        from hexhammer.tools.base import ToolError

        with pytest.raises(ToolError):
            JwtTool().execute({"action": "decode", "token": "a.b"}, _ctx(tmp_path))
        with pytest.raises(ToolError):  # HS256 无 key
            JwtTool().execute(
                {"action": "forge", "algorithm": "HS256", "payload": {}}, _ctx(tmp_path)
            )


class TestHttp:
    def test_request_shape_and_log(self, tmp_path):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["headers"] = dict(request.headers)
            captured["body"] = request.content.decode()
            return httpx.Response(
                200, headers={"Location": "/next", "Server": "nginx"},
                content="hello-body",
            )

        registry = _registry(httpx.MockTransport(handler))
        ctx = _ctx(tmp_path)
        content, is_error = registry.dispatch(
            "http",
            '{"method": "POST", "url": "https://t.example/api", "data": "a=1", '
            '"headers": {"X-Test": "1"}}',
            ctx,
        )
        assert not is_error
        assert captured["method"] == "POST" and captured["body"] == "a=1"
        assert captured["headers"]["x-test"] == "1"
        assert "HTTP 200" in content and "Location: /next" in content and "hello-body" in content
        log_line = (tmp_path / "http-log.jsonl").read_text(encoding="utf-8").strip()
        assert '"status": 200' in log_line and "t.example" in log_line

    def test_network_error_is_tool_error(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        registry = _registry(httpx.MockTransport(handler))
        _, is_error = registry.dispatch(
            "http", '{"method": "GET", "url": "https://dead.example/"}', _ctx(tmp_path)
        )
        assert is_error


class TestBypass403:
    def test_variant_hit_reported(self, tmp_path):
        seen_urls = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            if request.headers.get("x-original-url"):
                return httpx.Response(200, content="bypassed!")
            return httpx.Response(403, content="forbidden")

        registry = _registry(httpx.MockTransport(handler))
        content, is_error = registry.dispatch(
            "bypass403", '{"url": "https://t.example/admin/panel"}', _ctx(tmp_path)
        )
        assert not is_error
        assert "baseline=403" in content
        assert "HIT" in content
        assert "X-Original-URL" in content and "有效请求" in content
        # 纪律:所有变体都打同一台主机
        assert {u.split("/")[2] for u in seen_urls} == {"t.example"}

    def test_no_hit_mentions_skill(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, content="no")

        registry = _registry(httpx.MockTransport(handler))
        content, _ = registry.dispatch(
            "bypass403", '{"url": "https://t.example/x"}', _ctx(tmp_path)
        )
        assert "waf-bypass" in content


class TestNmap:
    def test_port_span(self):
        assert _port_span("21,22,80") == 3
        assert _port_span("1-3000") == 3000
        assert _port_span("1-") is None
        assert _port_span("T:80,U:53") == 2

    def test_build_command_guards(self):
        args = {"target": "10.0.0.1", "top_ports": 100, "rate": 9999}
        cmd = NmapTool.build_command(args)
        assert "--max-rate 600" in cmd and "--top-ports 100" in cmd
        assert NmapTool.build_command({"target": "10.0.0.1"}).count("--top-ports 200") == 1
        from hexhammer.tools.base import ToolError

        with pytest.raises(ToolError):
            NmapTool.build_command({"target": "10.0.0.1", "ports": "1-9999"})

    def test_parse_canned_output(self):
        raw = (
            "Starting Nmap 7.99\n"
            "PORT    STATE SERVICE VERSION\n"
            "22/tcp  open  ssh     OpenSSH 10.2p1\n"
            "443/tcp closed https\n"
            "80/tcp  open  http    Caddy\n"
            "Nmap done: 1 IP address (1 host up) scanned in 9.64 seconds\n"
        )
        lines, summary = _parse_nmap(raw)
        assert lines == ["22/tcp ssh OpenSSH 10.2p1", "80/tcp http Caddy"]
        assert summary.startswith("Nmap done")

    def test_missing_binary_clean_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(attack_mod.shutil, "which", lambda name: None)
        registry = _registry()
        content, is_error = registry.dispatch(
            "nmap", '{"target": "10.0.0.1", "top_ports": 10}', _ctx(tmp_path)
        )
        assert is_error and "nmap 二进制不存在" in content


class TestSqlmap:
    def test_build_command_caps(self):
        cmd = SqlmapTool.build_command(
            {"url": "http://t/?id=1", "level": 9, "risk": 9, "cookie": "c=1"}
        )
        assert "--level=3" in cmd and "--risk=2" in cmd
        assert "--batch" in cmd and "--random-agent" in cmd

    def test_missing_binary_clean_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(attack_mod.shutil, "which", lambda name: None)
        registry = _registry()
        content, is_error = registry.dispatch(
            "sqlmap", '{"url": "http://t/?id=1"}', _ctx(tmp_path)
        )
        assert is_error and "sqlmap 二进制不存在" in content
