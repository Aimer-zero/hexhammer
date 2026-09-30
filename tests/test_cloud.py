"""云工具面测试:元数据探测(v1/v2)、凭证枚举脱敏、桶公开性判定。"""

import json

import httpx

from hexhammer.tools import ToolContext, default_registry


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


class TestMetadata:
    def test_imdsv1_open_and_v2_token(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PUT":
                return httpx.Response(200, content="FAKE-TOKEN-abcdef123")
            return httpx.Response(200, content="iam/\ninstance-id/\n")

        registry = default_registry(transport=httpx.MockTransport(handler))
        content, is_error = registry.dispatch(
            "cloud", json.dumps({"action": "metadata"}), _ctx(tmp_path)
        )
        assert not is_error
        assert "开放" in content
        assert "IMDSv2:token 可获取" in content
        # token 脱敏:不回吐全文
        assert "FAKE-TOKEN-abcdef123" not in content
        assert "FAKE-T…" in content or "len=22" in content

    def test_no_metadata_anywhere(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route")

        registry = default_registry(transport=httpx.MockTransport(handler))
        content, is_error = registry.dispatch(
            "cloud", json.dumps({"action": "metadata"}), _ctx(tmp_path)
        )
        assert not is_error
        assert "无云元数据" in content

    def test_gcp_requires_flavor_header(self, tmp_path):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "metadata.google.internal":
                seen["flavor"] = request.headers.get("Metadata-Flavor")
                return httpx.Response(200, content="id/\n")
            raise httpx.ConnectError("no")

        registry = default_registry(transport=httpx.MockTransport(handler))
        registry.dispatch("cloud", json.dumps({"action": "metadata"}), _ctx(tmp_path))
        assert seen["flavor"] == "Google"


class TestCreds:
    def test_file_and_env_hits_masked(self, tmp_path, monkeypatch):
        (tmp_path / ".aws").mkdir()
        (tmp_path / ".aws" / "credentials").write_text("[default]\naws_access_key_id=AKIAEXAMPLE123\n")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "FkSOlongsecrettokenvalue1234567890")
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)

        registry = default_registry()
        content, is_error = registry.dispatch(
            "cloud",
            json.dumps({"action": "creds", "home": str(tmp_path)}),
            _ctx(tmp_path),
        )
        assert not is_error
        assert ".aws/credentials" in content
        assert "AWS_SESSION_TOKEN" in content
        # 值脱敏:env 值不全文回显
        assert "FkSOlongsecrettokenvalue" not in content
        assert "(len=34)" in content

    def test_clean_environment(self, tmp_path, monkeypatch):
        for key in ("AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID"):
            monkeypatch.delenv(key, raising=False)
        empty_home = tmp_path / "home"
        empty_home.mkdir()

        registry = default_registry()
        content, is_error = registry.dispatch(
            "cloud",
            json.dumps({"action": "creds", "home": str(empty_home)}),
            _ctx(tmp_path),
        )
        assert not is_error and "无命中" in content


class TestBucket:
    def _dispatch(self, tmp_path, status, body):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, content=body)

        registry = default_registry(transport=httpx.MockTransport(handler))
        return registry.dispatch(
            "cloud", json.dumps({"action": "bucket", "url": "https://b.example.com/"}), _ctx(tmp_path)
        )

    def test_listable(self, tmp_path):
        content, is_error = self._dispatch(
            tmp_path, 200, '<?xml version="1.0"?><ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>'
        )
        assert not is_error and "公开可列" in content

    def test_private(self, tmp_path):
        content, is_error = self._dispatch(
            tmp_path, 403, "<Error><Code>AccessDenied</Code></Error>"
        )
        assert not is_error and "存在但私有" in content

    def test_missing(self, tmp_path):
        content, is_error = self._dispatch(
            tmp_path, 404, "<Error><Code>NoSuchBucket</Code></Error>"
        )
        assert not is_error and "不存在" in content

    def test_dns_dead_means_missing(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dns")

        registry = default_registry(transport=httpx.MockTransport(handler))
        content, is_error = registry.dispatch(
            "cloud", json.dumps({"action": "bucket", "url": "https://nope.example.com/"}), _ctx(tmp_path)
        )
        assert not is_error and "不存在" in content
