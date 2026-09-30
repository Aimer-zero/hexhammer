"""OSINT 多源工具测试:四源解析、单源容错、合并溯源(MockTransport 零网络)。"""

import json

import httpx

from hexhammer.tools import ToolContext, default_registry
from hexhammer.tools.osint import (
    _looks_like_ip,
    _parse_cdx_json,
    _parse_crtsh_json,
    _parse_hackertarget,
)


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


class TestParsers:
    def test_ip_detect(self):
        assert _looks_like_ip("203.0.113.1")
        assert not _looks_like_ip("example.com")

    def test_hackertarget(self):
        body = "a.example.com\nb.example.com\napi.hackertarget.com\n"
        assert _parse_hackertarget(body, "1.2.3.4") == [
            "a.example.com", "b.example.com",
        ]
        assert _parse_hackertarget("API count exceeded", "1.2.3.4") == []

    def test_asset_junk_filtered(self):
        """实弹回归:页面 JS/CSS 资源名不得混入候选(2026-09-21 污染)。"""
        from hexhammer.tools.osint import _hosts_from_text, _parse_rapiddns

        junk_page = (
            '<script src="/static/jquery-2.2.4.min.js"></script>'
            "<script>document.addEventListener('x',function(){"
            "dropdown.classList.add('active')});</script>"
            '<link href="/css/bootstrap.css"/><img src="/img/avatar.jpg"/>'
            "fonts.googleapis.com blog.rapiddns.io"
        )
        assert _hosts_from_text(junk_page, "1.2.3.4") == []  # js/css/jpg 与样板全滤
        # RapidDNS 表格优先:链接列才是真数据
        page = (
            '<tr><td><a href="/subdomain/app1.example.com">app1.example.com</a></td>'
            '<td><a href="/subdomain/app2.example.com">app2.example.com</a></td></tr>'
            '<script src="/static/jquery-2.2.4.min.js"></script>'
            "<script>document.getElementById('x')</script>"
        )
        assert _parse_rapiddns(page, "1.2.3.4") == [
            "app1.example.com", "app2.example.com",
        ]

    def test_crtsh(self):
        body = json.dumps(
            [{"name_value": "*.example.com\nwww.example.com", "issuer": "x"}]
        )
        assert _parse_crtsh_json(body, "example.com") == ["www.example.com"]
        assert _parse_crtsh_json("not json", "x") == []

    def test_cdx(self):
        body = json.dumps(
            [
                ["urlkey", "timestamp", "original", "mimetype"],
                ["com,example)/", "20200101", "http://www.example.com/a", "text/html"],
                ["com,example)/b", "20200102", "https://api.example.com/b", ""],
            ]
        )
        assert _parse_cdx_json(body, "example.com") == [
            "api.example.com", "www.example.com",
        ]


class TestToolBehavior:
    def _transport(self, routing: dict) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host in routing:
                responder = routing[host]
                if isinstance(responder, Exception):
                    raise responder
                return httpx.Response(200, text=responder)
            return httpx.Response(404, text="unknown host")

        return httpx.MockTransport(handler)

    def test_ip_query_merges_sources_with_attribution(self, tmp_path):
        routing = {
            "api.hackertarget.com": "app1.example.com\napp2.example.com",
            "rapiddns.io": '<table><tr><td>app2.example.com</td><td>1.2.3.4</td></tr></table>',
            "crt.sh": json.dumps([{"name_value": "app1.example.com"}]),
            # wayback 失败:连接错 → 容错不拖垮整体
            "web.archive.org": httpx.ConnectError("down"),
        }
        registry = default_registry(transport=self._transport(routing))
        content, is_error = registry.dispatch(
            "osint", json.dumps({"query": "1.2.3.4"}), _ctx(tmp_path)
        )
        assert not is_error
        assert "app1.example.com" in content and "app2.example.com" in content
        assert "hackertarget" in content and "rapiddns" in content and "crtsh" in content
        assert "失败源" in content and "wayback" in content  # 单源失败显式标注
        assert "合并去重(2)" in content  # 去重后恰两个候选
        assert "SNI" in content  # 用法指路

    def test_domain_query_uses_cert_sources(self, tmp_path):
        routing = {
            "crt.sh": json.dumps(
                [{"name_value": "*.example.com\napi.example.com\nwww.example.com"}]
            ),
            "web.archive.org": json.dumps(
                [["urlkey", "ts", "original", "m"],
                 ["k", "t", "http://old.example.com/", "text/html"]]
            ),
        }
        registry = default_registry(transport=self._transport(routing))
        content, is_error = registry.dispatch(
            "osint", json.dumps({"query": "example.com"}), _ctx(tmp_path)
        )
        assert not is_error
        for host in ("api.example.com", "www.example.com", "old.example.com"):
            assert host in content
        assert "reverseiplookup" not in content  # 域名查询不打反查源

    def test_all_sources_dead_reports_negative(self, tmp_path):
        routing = {
            "api.hackertarget.com": httpx.ConnectError("x"),
            "rapiddns.io": httpx.ConnectError("x"),
            "crt.sh": httpx.ConnectError("x"),
            "web.archive.org": httpx.ConnectError("x"),
        }
        registry = default_registry(transport=self._transport(routing))
        content, is_error = registry.dispatch(
            "osint", json.dumps({"query": "1.2.3.4"}), _ctx(tmp_path)
        )
        assert not is_error  # 全灭也是合法输出:阴性格局
        assert "无候选" in content

    def test_registered_in_default_surface(self):
        names = {t.name for t in default_registry().specs()}
        assert "osint" in names
