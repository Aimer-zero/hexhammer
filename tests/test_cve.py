"""CVE 情报聚合工具测试:NVD/PoC-in-GitHub 解析、单源失败不拖垮、id 规范化。"""

import json

import httpx
import pytest

from hexhammer.tools import ToolContext, default_registry
from hexhammer.tools.base import ToolError
from hexhammer.tools.cve import CveTool, _normalize_cve


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


_NVD_BODY = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "JNDI features in Log4j 2 allow RCE."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "severity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:apache:log4j:2.0-beta9:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.0-beta9",
                                        "versionEndExcluding": "2.15.0",
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [{"url": "https://example.com/advisory"}],
            }
        }
    ]
}

_POC_BODY = [
    {"full_name": "a/log4shell-poc", "stargazers_count": 42,
     "pushed_at": "2022-01-02T00:00:00Z", "html_url": "https://github.com/a/log4shell-poc"},
    {"full_name": "b/another", "stargazers_count": 7,
     "pushed_at": "2021-12-15T00:00:00Z", "html_url": "https://github.com/b/another"},
]


def _transport(handler):
    return httpx.MockTransport(handler)


class TestNormalize:
    def test_accepts_with_and_without_prefix(self):
        assert _normalize_cve("CVE-2021-44228") == "CVE-2021-44228"
        assert _normalize_cve("2021-44228") == "CVE-2021-44228"
        assert _normalize_cve("cve-2023-12345") == "CVE-2023-12345"

    def test_rejects_garbage(self):
        with pytest.raises(ToolError):
            _normalize_cve("log4shell")


class TestIntel:
    def test_full_aggregation(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            if "nvd.nist.gov" in request.url.host:
                return httpx.Response(200, json=_NVD_BODY)
            if "PoC-in-GitHub" in str(request.url):
                return httpx.Response(200, json=_POC_BODY)
            return httpx.Response(404)

        registry = default_registry(transport=_transport(handler))
        content, is_error = registry.dispatch(
            "cve", json.dumps({"query": "CVE-2021-44228"}), _ctx(tmp_path)
        )
        assert not is_error
        assert "10.0 CRITICAL" in content
        assert "log4j" in content and "versionEndExcluding=2.15.0" in content
        assert "a/log4shell-poc ★42" in content
        assert "复现建议" in content  # 指路下一步

    def test_poc_404_means_no_collection(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            if "nvd.nist.gov" in request.url.host:
                return httpx.Response(200, json=_NVD_BODY)
            return httpx.Response(404)

        registry = default_registry(transport=_transport(handler))
        content, is_error = registry.dispatch(
            "cve", json.dumps({"query": "2021-44228"}), _ctx(tmp_path)
        )
        assert not is_error
        assert "无收录" in content
        assert "10.0 CRITICAL" in content  # 单源 404 不拖垮另一源

    def test_source_failure_keeps_other_source(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            if "nvd.nist.gov" in request.url.host:
                raise httpx.ConnectError("nvd down")
            return httpx.Response(200, json=_POC_BODY)

        registry = default_registry(transport=_transport(handler))
        content, is_error = registry.dispatch(
            "cve", json.dumps({"query": "CVE-2021-44228"}), _ctx(tmp_path)
        )
        assert not is_error
        assert "a/log4shell-poc" in content
        assert "nvd" in content.split("失败源")[1]  # 失败源如实上报

    def test_star_sorting_truncates_to_eight(self, tmp_path):
        big = [
            {"full_name": f"r/{i}", "stargazers_count": i,
             "pushed_at": "2022-01-01T00:00:00Z", "html_url": f"https://github.com/r/{i}"}
            for i in range(20)
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            if "PoC-in-GitHub" in str(request.url):
                return httpx.Response(200, json=big)
            return httpx.Response(404)

        tool = CveTool(transport=_transport(handler))
        out = tool.execute({"query": "CVE-2021-44228", "sources": ["poc"]}, _ctx(tmp_path))
        assert "共 20 个" in out
        assert "r/19" in out and "r/18" in out
        assert "r/5\n" not in out  # 截断:低位星标不进清单
