"""golden set:本地确定性题集——工具/引擎变更的回归与 A/B 底座。

四道题,全部本地、零外部依赖、结果可机器判定:
- jwt-admin     攻击工具受益(判据 A:JWT 签名手术)
- encode-chain  攻击工具受益(判据 A:三层 base64 链)
- bypass-403    攻击工具受益(判据 B:25 变体枚举 vs 模型手搓 3 个)
- flag-hunt     对照组(工具中性:纯文件搜索)
"""

from __future__ import annotations

import base64
import hmac
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..inbox import FindingsInbox
from ..tools.attack import _b64url_decode, _b64url_encode, _jwt_hs256_sign


@dataclass
class Challenge:
    id: str
    domain: str
    template: str  # __URL__ 占位
    setup: Callable[[Path], dict]
    teardown: Callable[[dict], None]
    verify: Callable[[Path, FindingsInbox], bool]


# ---------------------------------------------------------------- jwt-admin


def jwt_admin() -> Challenge:
    key = "supersecret"  # 内置弱密钥表成员:crack 工具的受益设计

    def setup(ws: Path) -> dict:
        header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = _b64url_encode(
            json.dumps({"admin": False, "user": "guest"}, ensure_ascii=False).encode()
        )
        sig = _jwt_hs256_sign(f"{header}.{payload}", key)
        (ws / "token.txt").write_text(f"{header}.{payload}.{sig}", encoding="utf-8")
        return {}

    def verify(ws: Path, inbox: FindingsInbox) -> bool:
        target = ws / "admin_token.txt"
        if not target.is_file():
            return False
        parts = target.read_text(encoding="utf-8").strip().split(".")
        if len(parts) != 3:
            return False
        try:
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception:  # noqa: BLE001 - 判定函数,任何解析失败即不合格
            return False
        expected = _jwt_hs256_sign(f"{parts[0]}.{parts[1]}", key)
        return bool(payload.get("admin")) and hmac.compare_digest(parts[2], expected)

    return Challenge(
        id="jwt-admin",
        domain="web",
        template=(
            "工作区 token.txt 是一个 HS256 JWT(弱密钥签名,payload 里 admin=false)。"
            "伪造一个 admin=true 且签名同样合法的 token,把 token 本身写入 admin_token.txt。"
        ),
        setup=setup,
        teardown=lambda ctx: None,
        verify=verify,
    )


# -------------------------------------------------------------- encode-chain


def encode_chain() -> Challenge:
    flag = "flag{g0ld3n-3nc0d3}"

    def setup(ws: Path) -> dict:
        content = flag
        for _ in range(3):
            content = base64.b64encode(content.encode()).decode()
        (ws / "secret.enc").write_text(content, encoding="utf-8")
        return {}

    def verify(ws: Path, inbox: FindingsInbox) -> bool:
        return flag in inbox.known_flags()

    return Challenge(
        id="encode-chain",
        domain="web",
        template="工作区 secret.enc 是三层 base64 叠加编码的密文,解出明文 flag。",
        setup=setup,
        teardown=lambda ctx: None,
        verify=verify,
    )


# ---------------------------------------------------------------- bypass-403


def bypass_403() -> Challenge:
    flag = "flag{g0ld3n-403}"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/admin" and self.headers.get("X-Original-URL"):
                body, status = flag.encode(), 200
            else:
                body, status = b"403 forbidden", 403
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:  # 静默
            pass

    def setup(ws: Path) -> dict:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return {
            "url": f"http://127.0.0.1:{server.server_address[1]}/admin",
            "server": server,
        }

    def teardown(ctx: dict) -> None:
        ctx["server"].shutdown()
        ctx["server"].server_close()

    def verify(ws: Path, inbox: FindingsInbox) -> bool:
        return flag in inbox.known_flags()

    return Challenge(
        id="bypass-403",
        domain="web",
        template=(
            "目标 __URL__ 返回 403。绕过访问限制拿到响应体里的 flag"
            "(让它出现在你的命令输出里)。"
        ),
        setup=setup,
        teardown=teardown,
        verify=verify,
    )


# ---------------------------------------------------------------- flag-hunt


def flag_hunt() -> Challenge:
    flag = "flag{g0ld3n-hunt}"

    def setup(ws: Path) -> dict:
        encoded = base64.b64encode(flag.encode()).decode()
        (ws / "logs" / "old").mkdir(parents=True, exist_ok=True)
        (ws / "logs" / "old" / "app.log.20250814.bak").write_text(
            f"2025-08-14 INFO service started\n2025-08-14 INFO license={encoded}\n",
            encoding="utf-8",
        )
        return {}

    def verify(ws: Path, inbox: FindingsInbox) -> bool:
        return flag in inbox.known_flags()

    return Challenge(
        id="flag-hunt",
        domain="web",
        template="工作区日志归档中藏着一份 base64 编码的许可信息,解出 flag 明文。",
        setup=setup,
        teardown=lambda ctx: None,
        verify=verify,
    )


def all_challenges() -> list[Challenge]:
    return [jwt_admin(), encode_chain(), bypass_403(), flag_hunt()]
