"""golden v2 考场装置测试:链路机制 HTTP 级验证(引擎考试前的前置自检)。"""

import json
import urllib.error
import urllib.request

from hexhammer.eval.golden2 import (
    FLAG_RCE,
    FLAG_SSRF,
    all_v2_challenges,
    compile_rce,
    ssrf_chain,
)


def _post(url, path, body):
    req = urllib.request.Request(
        url + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class TestSsrfChainApparatus:
    def test_full_chain_mechanics(self):
        ch = ssrf_chain()
        ctx = ch.setup(None)
        try:
            url = ctx["url"]
            # 1) IP 直绑被白名单拒绝
            code, r1 = _post(url, "/api/my-site/bind", {"user_key": "t", "base_url": "http://127.0.0.1:1/"})
            assert code == 400 and r1["saved"] is False
            # 2) 允许后缀域通过
            site = "http://x.relay.test/jump?to=/"
            code, r2 = _post(url, "/api/my-site/bind", {"user_key": "t", "base_url": site})
            assert code == 200 and r2["saved"] is True
            # 3) whoami 经 重定向跟随 反射内网旗标
            code, r3 = _post(url, "/api/whoami", {"user_key": "t", "site": site})
            assert code == 200 and r3["status"] == 200
            assert FLAG_SSRF in r3["text_preview"]
            # 4) 无绑定的 whoami → 干净报错
            code, _ = _post(url, "/api/whoami", {"user_key": "nobody"})
            assert code == 400
        finally:
            ch.teardown(ctx)


class TestCompileRceApparatus:
    def test_compile_poll_read_log(self):
        ch = compile_rce()
        ctx = ch.setup(None)
        try:
            url = ctx["url"]
            code, r = _post(url, "/api/compile", {"source": "import os; print(os.environ['FLAG'])"})
            assert code == 200 and r["ok"]
            with urllib.request.urlopen(url + "/api/status/builds", timeout=10) as resp:
                builds = json.loads(resp.read())
            assert FLAG_RCE in builds[r["build_id"]]["log"]
        finally:
            ch.teardown(ctx)


def test_v2_challenge_ids():
    assert {c.id for c in all_v2_challenges()} == {"ssrf-chain", "compile-rce"}
