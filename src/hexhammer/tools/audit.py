"""源码审计工具:危险 sink 枚举 + 调用链回溯(A② 源码审计链的机械部分)。

设计:模型做审计判断(哪个 sink 可利用、数据流是否可控),工具做机械正确
(全文扫描/调用链追踪/输出紧凑)。适合 Python/PHP/Java 的快速审计。

动作:
- sinks:扫描源码中的危险调用(命令执行/SQL拼接/路径拼接/反序列化/SSRF);
- trace:从指定符号向上追踪调用链(谁调用了这个函数→递归到入口)。

知识来源:resources/skills/source-audit(方法论);
sink 模式库来自 OWASP/CWE 常见危险函数族。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from .base import ToolContext, ToolError, resolve_in_workspace, truncate

# 危险 sink 模式库:类别 → 正则(匹配调用行)
_SINK_PATTERNS: list[tuple[str, re.Pattern]] = [
    # 命令执行
    ("cmd-exec", re.compile(
        r"(os\.system|subprocess\.(run|call|Popen|check_output)|os\.popen|"
        r"shell_exec|exec\(|system\(|passthru|popen\(|Runtime\.getRuntime|"
        r"ProcessBuilder|child_process\.(exec|spawn))", re.I)),
    # SQL 拼接
    ("sql-inject", re.compile(
        r"(execute\(|executemany|cursor\.execute|\.query\(|mysql_query|mysqli_query|"
        r"pg_query|sqlite3\.execute|raw\(|\.raw|SELECT.*\+|INSERT.*\+|UPDATE.*\+|"
        r'DELETE.*\+|.*f".*SELECT|.*f\'.*SELECT)', re.I)),
    # 路径拼接(用户可控)
    ("path-traversal", re.compile(
        r"(open\s*\(.*\+|os\.path\.join\s*\(.*request|send_file\s*\(.*\+|"
        r"readFile\s*\(.*\+|file_get_contents\s*\(.*\$|include\s*\(.*\$|"
        r"require\s*\(.*\$|fopen\s*\(.*\$|unlink\s*\(.*request)", re.I)),
    # 反序列化
    ("deserialization", re.compile(
        r"(pickle\.loads|yaml\.load\s*\(|unserialize|readObject|fromstring|"
        r"marshal\.loads|cPickle\.loads|java\.io\.ObjectInputStream)", re.I)),
    # SSRF
    ("ssrf", re.compile(
        r"(urllib\.request\.urlopen\s*\(.*request|requests\.(get|post|put|delete)"
        r"\s*\(.*request|curl_exec\s*\(.*\$|file_get_contents\s*\(.*http|"
        r"http\.Get\s*\(.*r\.|fetch\s*\(.*req\.)", re.I)),
    # XSS / 模板注入
    ("xss-ssti", re.compile(
        r"(innerHTML\s*=|document\.write\s*\(|\|safe|markRaw|\|raw|render_template"
        r"_string|Template\s*\(.*\+|Jinja2\s*\(.*autoescape.*False|eval\s*\()", re.I)),
    # 硬编码凭证
    ("hardcoded-secret", re.compile(
        r'(password\s*=\s*["\'][^"\']{6,}|api_key\s*=\s*["\'][A-Za-z0-9]'
        r'|secret\s*=\s*["\'][^"\']{6,}|token\s*=\s*["\'][A-Za-z0-9_-]{10,})', re.I)),
]

_EXTS = {".py", ".php", ".java", ".js", ".ts", ".go", ".rb", ".rs", ".kt", ".cs"}
_MAX_FILES = 300
_MAX_HITS = 60
_CONTEXT_LINES = 1


def _scan_file(path: Path, root: Path) -> list[dict]:
    hits: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    for lineno, line in enumerate(lines, 1):
        for category, pattern in _SINK_PATTERNS:
            if pattern.search(line):
                context = "\n".join(
                    lines[max(0, lineno - 1 - _CONTEXT_LINES): lineno + _CONTEXT_LINES]
                )
                hits.append({
                    "file": str(path.relative_to(root)),
                    "line": lineno,
                    "category": category,
                    "call": line.strip()[:200],
                    "context": context.strip()[:300],
                })
                break  # 每行只记一个类别
    return hits


class AuditTool:
    name = "audit"
    description = (
        "Source code audit: sinks (scan for dangerous calls: cmd-exec/sql-inject/"
        "path-traversal/deserialization/ssrf/xss-ssti/hardcoded-secret with file:"
        "line + context) and trace (follow the call chain upward from a symbol "
        "to its entry point). Use for source-assisted vulnerability research."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["sinks", "trace"]},
            "path": {"type": "string", "description": "source file or directory"},
            "lang": {
                "type": "string",
                "enum": ["python", "php", "java", "javascript", "go", "auto"],
                "description": "language hint (default auto)",
            },
            "symbol": {"type": "string", "description": "trace: function/method name"},
            "depth": {"type": "integer", "description": "trace: max depth (default 4)"},
        },
        "required": ["action", "path"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        action = args["action"]
        raw = str(args["path"])
        p = Path(raw)
        # 绝对路径直接用(外部代码审计场景);相对路径钉在 workspace 内
        target = p if p.is_absolute() else resolve_in_workspace(ctx, raw)
        if not target.exists():
            raise ToolError(f"路径不存在:{args['path']}")
        if action == "sinks":
            return self._sinks(target)
        if action == "trace":
            symbol = str(args.get("symbol") or "")
            if not symbol:
                raise ToolError("trace 需要 symbol(函数/方法名)")
            depth = min(int(args.get("depth") or 4), 6)
            return self._trace(target, symbol, depth)
        raise ToolError(f"unknown action {action!r}")

    # ---- sink 扫描

    def _sinks(self, target: Path) -> str:
        files: list[Path]
        if target.is_file():
            files = [target]
        else:
            files = sorted(
                f for f in target.rglob("*")
                if f.is_file() and f.suffix in _EXTS and ".git" not in str(f)
            )[:_MAX_FILES]

        all_hits: list[dict] = []
        for f in files:
            all_hits += _scan_file(f, target if target.is_dir() else target.parent)

        if not all_hits:
            return f"扫描 {len(files)} 个文件:无危险 sink 命中(或全被过滤)"

        by_cat: dict[str, list[dict]] = {}
        for hit in all_hits:
            by_cat.setdefault(hit["category"], []).append(hit)

        lines = [f"扫描 {len(files)} 文件 → {len(all_hits)} 个 sink 命中:"]
        for cat in sorted(by_cat, key=lambda c: -len(by_cat[c])):
            hits = by_cat[cat][:15]
            lines.append(f"\n## {cat}({len(by_cat[cat])})")
            for h in hits:
                lines.append(f"  {h['file']}:{h['line']}  {h['call'][:120]}")
        if len(all_hits) > _MAX_HITS:
            lines.append(f"\n(共 {len(all_hits)} 命中,截前 {_MAX_HITS})")
        lines.append(
            "\n下一步:对高价值 sink 用 trace 回溯入口(用户输入是否可达),"
            "再构造触发验证。方法论见 source-audit 技能。"
        )
        return "\n".join(lines)

    # ---- 调用链回溯

    def _trace(self, target: Path, symbol: str, max_depth: int) -> str:
        files: list[Path]
        if target.is_file():
            files = [target]
        else:
            files = sorted(
                f for f in target.rglob("*")
                if f.is_file() and f.suffix in _EXTS and ".git" not in str(f)
            )[:_MAX_FILES]

        # 构建简化调用图:file:line → 调用的符号
        call_sites: list[tuple[Path, int, str, str]] = []  # (file, line, caller_text, callee)
        func_defs: dict[str, tuple[Path, int]] = {}  # symbol → (file, line)

        def_pattern = re.compile(
            r"^\s*(?:def|function|public|private|protected|static|async|func)\s+"
            r"[\w<>]+\s+" + re.escape(symbol),
            re.I,
        )
        call_pattern = re.compile(re.escape(symbol) + r"\s*\(")

        for f in files:
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if def_pattern.match(stripped):
                    func_defs[symbol] = (f, lineno)
                elif call_pattern.search(stripped) and not def_pattern.match(stripped):
                    call_sites.append((f, lineno, stripped[:150], symbol))

        if not func_defs and not call_sites:
            return f"符号 {symbol!r} 在 {len(files)} 个文件中未找到定义或调用"

        lines_out = [f"符号 {symbol!r} 的调用链:"]
        if func_defs:
            f, ln = func_defs[symbol]
            lines_out.append(f"  定义:{f}:{ln}")

        # 递归向上找 caller(简化:找调用点的所在函数名)
        visited: set[str] = set()
        chain: list[str] = []

        def find_caller(file: Path, line: int, depth: int) -> str | None:
            try:
                content = file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                return None
            # 从调用行向上找最近的 def/function/public
            for i in range(line - 1, -1, -1):
                l = content[i].strip() if i < len(content) else ""
                m = re.match(
                    r"(?:def|function|public|private|protected|static|async|func)"
                    r"\s+(\w+)", l,
                )
                if m:
                    caller = m.group(1)
                    if caller in visited or depth > max_depth:
                        return None
                    visited.add(caller)
                    loc = f"{file.name}:{i + 1}"
                    # 递归找 caller 的 caller
                    upper = None
                    for cf, cl, _, cs in call_sites:
                        if cs == caller:
                            upper = find_caller(cf, cl, depth + 1)
                            break
                    if upper:
                        return f"{loc} → {caller} → {upper}"
                    return f"{loc} → {caller}"
            return None

        for cf, cl, text, _ in call_sites[:20]:
            caller = find_caller(cf, cl, 1)
            if caller:
                chain.append(f"  {cf.name}:{cl}  {caller}")

        if chain:
            lines_out.extend(chain)
        else:
            lines_out.append("  未找到上游调用(可能是入口函数)")

        lines_out.append(
            "\n判读:如果入口是路由处理/CLI 入口且中间无过滤,数据流可控 → "
            "高价值 sink;否则标记为已防。"
        )
        return "\n".join(lines_out)
