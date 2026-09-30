"""武器研发工具测试:GitHub API 三动作 + 入库标准(幂等/证据强制)。"""

import json

import httpx
import pytest
from hexhammer import experience  # noqa: F401  (确保包结构完整)
from hexhammer.tools import ToolContext, default_registry
from hexhammer.tools.base import ToolError
from hexhammer.tools.weapon import WeaponTool, weapon_library_path


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


def _api_transport(routes: dict) -> httpx.MockTransport:
    """routes: path 前缀 → (status, body)"""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for prefix, (status, body) in routes.items():
            if path.startswith(prefix):
                return httpx.Response(status, text=body)
        return httpx.Response(404, text="not found")

    return httpx.MockTransport(handler)


class TestApiActions:
    def test_gh_search_sorted_output(self, tmp_path):
        tool = WeaponTool(transport=_api_transport({
            "/search/repositories": (200, json.dumps({
                "items": [
                    {"full_name": "a/poc", "stargazers_count": 369,
                     "pushed_at": "2022-01-01T00:00:00Z", "description": "grafana lfi"},
                ],
                "total_count": 1,
            })),
        }))
        out = tool.execute({"action": "gh_search", "query": "CVE-2021-43798"}, _ctx(tmp_path))
        assert "a/poc ★369" in out

    def test_gh_search_rate_limit_message(self, tmp_path):
        tool = WeaponTool(transport=_api_transport({
            "/search/repositories": (403, "rate limited"),
        }))
        out = tool.execute({"action": "gh_search", "query": "x"}, _ctx(tmp_path))
        assert "限流" in out

    def test_readme_raw(self, tmp_path):
        tool = WeaponTool(transport=_api_transport({
            "/repos/a/poc/readme": (200, "# PoC\nfix commit: https://github.com/g/g/commit/abc1234"),
        }))
        out = tool.execute({"action": "readme", "repo": "a/poc"}, _ctx(tmp_path))
        assert "commit/abc1234" in out

    def test_patch_diff_extraction(self, tmp_path):
        body = (
            "commit abc\nAuthor: x\n\n    fix path traversal\n\n"
            "diff --git a/pkg/route.go b/pkg/route.go\n--- a/pkg/route.go\n"
            "+ if strings.Contains(path, \"..\") { reject }"
        )
        tool = WeaponTool(transport=_api_transport({
            "/repos/g/g/commits/abc1234": (200, body),
        }))
        out = tool.execute(
            {"action": "patch",
             "commit_url": "https://github.com/g/g/commit/abc1234"},
            _ctx(tmp_path),
        )
        assert "# diff" in out and "path traversal" in out and "route.go" in out

    def test_patch_bad_url(self, tmp_path):
        tool = WeaponTool()
        with pytest.raises(ToolError, match="commit_url"):
            tool.execute({"action": "patch", "commit_url": "https://evil/x"}, _ctx(tmp_path))


class TestSave:
    def _lib(self, tmp_path, monkeypatch):
        lib = tmp_path / "library.jsonl"
        import hexhammer.tools.weapon as wmod

        monkeypatch.setattr(wmod, "weapon_library_path", lambda: lib)
        return lib

    def test_full_entry_saved(self, tmp_path, monkeypatch):
        lib = self._lib(tmp_path, monkeypatch)
        tool = WeaponTool()
        out = tool.execute({
            "action": "save", "cve": "CVE-2021-43798",
            "root_cause": "路由通配未过滤 ../",
            "trigger": "Grafana 8.0-8.2,GET /public/plugins/<id>/../../..",
            "poc": "curl --path-as-is http://t:3000/public/plugins/../../../../etc/passwd",
            "verified": "local-verified", "evidence": "root:x:0:0:root:/root",
        }, _ctx(tmp_path))
        assert "入库成功" in out and "靶验证 ✓" in out
        rows = [json.loads(l) for l in lib.read_text().splitlines()]
        assert len(rows) == 1 and rows[0]["verified"] == "local-verified"

    def test_idempotent_by_cve(self, tmp_path, monkeypatch):
        lib = self._lib(tmp_path, monkeypatch)
        tool = WeaponTool()
        for _ in range(2):
            tool.execute({
                "action": "save", "cve": "cve-2021-43798",
                "root_cause": "r", "trigger": "t", "poc": "p",
                "verified": "unverified",
            }, _ctx(tmp_path))
        rows = [json.loads(l) for l in lib.read_text().splitlines()]
        assert len(rows) == 1  # 第二次幂等跳过

    def test_incomplete_or_unverified_rejected(self, tmp_path, monkeypatch):
        self._lib(tmp_path, monkeypatch)
        tool = WeaponTool()
        with pytest.raises(ToolError, match="缺一不可"):
            tool.execute({"action": "save", "cve": "X", "root_cause": "r"}, _ctx(tmp_path))
        with pytest.raises(ToolError, match="evidence"):
            tool.execute({
                "action": "save", "cve": "X", "root_cause": "r",
                "trigger": "t", "poc": "p", "verified": "local-verified",
            }, _ctx(tmp_path))

    def test_registered(self, tmp_path):
        registry = default_registry()
        assert any(t.name == "weapon" for t in registry.specs())
