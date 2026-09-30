"""loot 敏感信息抽取:立足点后的第一件事,确定性正则矩阵。

判据 A(机械易错——模型手扫必漏)+ E(证据生成)。默认矩阵:云 AK、私钥、
JWT、API Key、连接串、密码行、邮箱、敏感文件名;内网 IP 为选配(渗透笔记
里遍地都是,默认开会淹没真命中)。行级命中带 文件:行号,值随行展示(引擎
要拿去用),每类封顶防刷屏;二进制/超 2MB 文件跳过。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from .base import ToolContext, ToolError, resolve_in_workspace

MAX_HITS_PER_CATEGORY = 30
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_SHOW = 160

PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "aliyun_ak": (re.compile(r"LTAI[A-Za-z0-9]{12,24}"), "阿里云 AccessKey"),
    "tencent_ak": (re.compile(r"AKID[A-Za-z0-9]{13,40}"), "腾讯云 SecretId"),
    "aws_ak": (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS AccessKey"),
    "gcp_sa": (re.compile(r"\"type\"\s*:\s*\"service_account\""), "GCP 服务账号 JSON"),
    "private_key": (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "私钥文件头",
    ),
    "jwt": (
        re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
        "JWT",
    ),
    "api_key": (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "API Key(sk- 系)"),
    "password_line": (
        re.compile(
            r"(?i)(?<![a-z0-9])(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
            r"\s*[=:]\s*['\"]?[^\s'\"]{4,}"
        ),
        "密码/凭证行",
    ),
    "conn_string": (
        re.compile(
            r"(?i)\b(mysql|postgres(?:ql)?|redis|mariadb|mongodb(?:\+srv)?|amqp|ftp)://[^\s'\"]+"
        ),
        "连接串",
    ),
    "email": (
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        "邮箱",
    ),
}

OPT_IN_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "internal_ip": (
        re.compile(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "内网 IP(选配)",
    ),
}

# 敏感文件名:命中即报,不看内容
SENSITIVE_NAMES = (
    ".env", "id_rsa", "id_ed25519", "id_ecdsa", ".git-credentials",
    ".bash_history", ".zsh_history", ".netrc", "known_hosts",
    "credentials.json", "secrets.yaml", "secrets.yml",
)


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\x00" in fh.read(4096)
    except OSError:
        return True


class LootTool:
    name = "loot"
    description = (
        "Scan workspace (or given paths) for secrets: cloud AK/SK (aliyun/tencent/"
        "aws/gcp), private keys, JWTs, API keys, connection strings, password "
        "lines, emails, sensitive filenames. Optional: internal_ip. Returns "
        "file:line hits grouped by category. Run this right after any foothold "
        "or after downloading configs."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "subpaths to scan (default: whole workspace)",
            },
            "patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "subset keys (default all; internal_ip opt-in)",
            },
        },
        "required": [],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        active: dict[str, tuple[re.Pattern, str]] = dict(PATTERNS)
        wanted = set(args.get("patterns") or [])
        if wanted:
            full = {**PATTERNS, **OPT_IN_PATTERNS}
            unknown = wanted - full.keys()
            if unknown:
                raise ToolError(f"未知 pattern:{sorted(unknown)}")
            active = {k: full[k] for k in wanted}

        roots = [resolve_in_workspace(ctx, p) for p in (args.get("paths") or ["."])]
        files: list[Path] = []
        for root in roots:
            if root.is_file():
                files.append(root)
            elif root.is_dir():
                files.extend(
                    p for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()
                )
        files = [p for p in files if p.stat().st_size <= MAX_FILE_BYTES]

        hits: dict[str, list[str]] = {}
        overflow: dict[str, int] = {}
        scanned = 0
        for path in files:
            rel = path.relative_to(ctx.workspace)
            scanned += 1
            name = path.name
            if any(key in name for key in SENSITIVE_NAMES):
                self._add(hits, overflow, "sensitive_file", f"{rel} | 敏感文件名命中")

            if _is_binary(path):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                for key, (pattern, _) in active.items():
                    if pattern.search(line):
                        self._add(
                            hits, overflow, key,
                            f"{rel}:{lineno} | {line.strip()[:MAX_LINE_SHOW]}",
                        )

        return self._format(scanned, hits, overflow)

    @staticmethod
    def _add(
        hits: dict[str, list[str]], overflow: dict[str, int], key: str, item: str
    ) -> None:
        bucket = hits.setdefault(key, [])
        if len(bucket) < MAX_HITS_PER_CATEGORY:
            bucket.append(item)
        else:
            overflow[key] = overflow.get(key, 0) + 1

    @staticmethod
    def _format(scanned: int, hits: dict[str, list[str]], overflow: dict[str, int]) -> str:
        labels = {**{k: v[1] for k, v in PATTERNS.items()},
                  **{k: v[1] for k, v in OPT_IN_PATTERNS.items()},
                  "sensitive_file": "敏感文件名"}
        if not hits:
            return f"# LOOT:扫描 {scanned} 个文件,零命中。"
        total = sum(len(v) for v in hits.values())
        lines = [f"# LOOT:{total} 处命中 / 扫描 {scanned} 个文件"]
        order = ["aliyun_ak", "tencent_ak", "aws_ak", "gcp_sa", "private_key",
                 "api_key", "jwt", "password_line", "conn_string", "email",
                 "internal_ip", "sensitive_file"]
        for key in order:
            if key not in hits:
                continue
            lines.append(f"## {labels.get(key, key)}({len(hits[key])})")
            lines.extend(f"- {h}" for h in hits[key])
            if key in overflow:
                lines.append(f"  …(另 {overflow[key]} 处被截断)")
        lines.append("提示:凭证类命中应立即尝试验证(cloud 域 playbook §1/§3);"
                     "发现 flag{} 记得让它出现在输出里。")
        return "\n".join(lines)
