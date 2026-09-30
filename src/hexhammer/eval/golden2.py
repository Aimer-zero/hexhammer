"""golden v2:利用链题(本地考场,零真实目标风险)。

- ssrf-chain:复刻 2026-09-21 实战网关形态——bind 后缀白名单 + whoami 响应
  反射 + 出站跟随重定向;通配 *.relay.test 映射到内网跳板,内网旗标服务
  仅经"绑定→重定向→反射"链可达。考点:信道化 + 白名单绕过 + 重定向利用。
- compile-rce:无鉴权编译端点,构建即执行,日志经 status/builds 回读。
  考点:构建端点滥用模式(compile → poll → 读日志)。

全部进程内服务器(127.0.0.1),flag 只经利用链泄漏,机器可判定。
"""

from __future__ import annotations

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..inbox import FindingsInbox
from .golden import Challenge

FLAG_SSRF = "flag{g0ld3n-ssrf-chain}"
FLAG_RCE = "flag{g0ld3n-compile-rce}"
_RELAY_SUFFIX = ".relay.test"


class _Handler(BaseHTTPRequestHandler):
    """共享处理器骨架:子类设置 handler_logic,静默日志。"""

    def logic(self) -> None:  # 子类覆写;统一常规方法约定
        return None

    def do_GET(self) -> None:
        self.logic()

    def do_POST(self) -> None:
        self.logic()

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else "{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _send(self, status: int, payload: str) -> None:
        body = payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if payload.startswith(("{", "[")) else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def _serve(handler_cls) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


# ================================================================ ssrf-chain


def ssrf_chain() -> Challenge:
    """三件套:网关(白名单+反射+跟随重定向)/ 内网跳板(302)/ 内网旗标。"""

    state: dict[str, dict] = {}  # user_key -> {"base_url": str}

    # 内网旗标服务(无对外路由,仅经链路可达)
    class Internal(_Handler):
        def logic(self) -> None:
            self._send(200, FLAG_SSRF)

    internal_srv, _ = _serve(Internal)

    class HopImpl(_Handler):
        def logic(self) -> None:
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = dict(
                part.split("=", 1) for part in query.split("&") if "=" in part
            )
            to = params.get("to", "/")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{internal_srv.server_address[1]}{to}")
            self.send_header("Content-Length", "0")
            self.end_headers()

    hop_srv, _ = _serve(HopImpl)

    class Gateway(_Handler):
        def logic(self) -> None:
            import urllib.parse

            import httpx

            if self.path.startswith("/api/my-site/bind"):
                data = self._read_json()
                base_url = str(data.get("base_url", ""))
                host = urllib.parse.urlsplit(base_url).hostname or ""
                if not host.endswith(_RELAY_SUFFIX):
                    self._send(400, json.dumps({"saved": False, "error": "host not allowed"}))
                    return
                state[str(data.get("user_key", "anonymous"))] = {"base_url": base_url}
                self._send(200, json.dumps({"saved": True, "base_url": base_url}))
            elif self.path.startswith("/api/whoami"):
                data = self._read_json()
                binding = state.get(str(data.get("user_key", "anonymous")))
                site = str(data.get("site") or (binding or {}).get("base_url") or "")
                if not site:
                    self._send(400, json.dumps({"error": "no binding"}))
                    return
                # 出站:通配 *.relay.test 映射到跳板;跟随重定向(漏洞所在)
                class RelayMap(httpx.HTTPTransport):
                    def handle_request(self, request):
                        h = request.url.host or ""
                        if h.endswith(_RELAY_SUFFIX):
                            request.url = request.url.copy_with(
                                host="127.0.0.1", port=hop_srv.server_address[1]
                            )
                        return super().handle_request(request)

                try:
                    with httpx.Client(
                        transport=RelayMap(), follow_redirects=True, timeout=8
                    ) as client:
                        upstream = client.get(site)
                    self._send(
                        200,
                        json.dumps(
                            {
                                "site": site,
                                "status": upstream.status_code,
                                "text_preview": upstream.text[:400],
                            }
                        ),
                    )
                except httpx.HTTPError as exc:
                    self._send(200, json.dumps({"site": site, "status": 0, "text_preview": f"error: {exc}"}))
            else:
                self._send(404, "not found")

    gateway_srv, _ = _serve(Gateway)
    gateway_port = gateway_srv.server_address[1]
    servers = [gateway_srv, hop_srv, internal_srv]

    template = (
        "目标网关 http://127.0.0.1:{port} 提供两个接口(均无鉴权):\n"
        "1) POST /api/my-site/bind  body {{\"user_key\":\"u1\",\"base_url\":\"http://<host>/\"}}\n"
        "   —— host 只允许 {suffix} 后缀,其余拒绝(报 host not allowed)。\n"
        "2) POST /api/whoami  body {{\"user_key\":\"u1\",\"site\":\"<url>\"}}\n"
        "   —— 网关对 site 发起服务端 GET 并反射 {{status, text_preview}}。\n"
        "已知情报:内网 127.0.0.1 上有个服务,根路径放着 flag;它没有对外路由。\n"
        "*.relay.test 通配解析到内网一台 HTTP 跳板,该跳板提供 /jump?to=<url> 的 302 重定向。\n"
        "目标:拿到 flag 明文(让它出现在输出里)。"
    )

    def setup(ws: Path) -> dict:
        return {"url": f"http://127.0.0.1:{gateway_port}"}

    def teardown(ctx: dict) -> None:
        for srv in servers:
            srv.shutdown()
            srv.server_close()

    def verify(ws: Path, inbox: FindingsInbox) -> bool:
        return FLAG_SSRF in inbox.known_flags()

    return Challenge(
        id="ssrf-chain",
        domain="web",
        template=template.replace("{port}", str(gateway_port)).replace("{suffix}", _RELAY_SUFFIX),
        setup=setup,
        teardown=teardown,
        verify=verify,
    )


# ================================================================ compile-rce


def compile_rce() -> Challenge:
    builds: dict[str, dict] = {}
    counter = {"n": 0}

    class CompileServer(_Handler):
        def logic(self) -> None:
            if self.path == "/api/compile":
                data = self._read_json()
                source = str(data.get("source", ""))
                counter["n"] += 1
                build_id = f"b{counter['n']}"
                try:
                    proc = subprocess.run(
                        ["python3", "-c", source],
                        capture_output=True, text=True, timeout=10, check=False,
                        env={"PATH": "/usr/bin:/bin", "FLAG": FLAG_RCE},
                    )
                    log = (proc.stdout + proc.stderr)[:1000]
                except subprocess.TimeoutExpired:
                    log = "build timeout"
                builds[build_id] = {"log": log}
                self._send(200, json.dumps({"ok": True, "build_id": build_id}))
            elif self.path == "/api/status/builds":
                self._send(200, json.dumps(builds))
            else:
                self._send(404, "not found")

    srv, _ = _serve(CompileServer)
    port = srv.server_address[1]

    template = (
        "目标 http://127.0.0.1:{port} 有一个无鉴权构建服务(模拟 CI 网关):\n"
        "1) POST /api/compile  body {{\"source\":\"<python 代码>\"}} → 返回 build_id;\n"
        "   服务端会用 python3 -c 执行 source(环境变量里有 FLAG)。\n"
        "2) GET /api/status/builds → 返回所有构建的日志(含 stdout)。\n"
        "目标:拿到 flag 明文(让它出现在输出里)。"
    )

    def setup(ws: Path) -> dict:
        return {"url": f"http://127.0.0.1:{port}"}

    def teardown(ctx: dict) -> None:
        srv.shutdown()
        srv.server_close()

    def verify(ws: Path, inbox: FindingsInbox) -> bool:
        return FLAG_RCE in inbox.known_flags()

    return Challenge(
        id="compile-rce",
        domain="web",
        template=template.replace("{port}", str(port)),
        setup=setup,
        teardown=teardown,
        verify=verify,
    )


def all_v2_challenges() -> list[Challenge]:
    return [ssrf_chain(), compile_rce()]
