"""ELF 分析工具包:二进制维度的结构化入口。

设计同 attack.py:flash 级模型手搓 readelf/objdump 管道最容易翻车(参数
记错+输出喷涌烧 token)。结构化动作 = 模型表达意图,机械细节确定性执行:

- info:file 判定(架构/静态动态/stripped);
- checksec:加固画像(PIE/NX/RELRO/Canary)——从 readelf 输出判定,不依赖
  checksec 二进制;
- symbols / dangerous:符号表与危险函数导入(system/strcpy/execve 族——
  漏洞挖掘第一线索);
- strings:可打印串(可过滤);
- disasm:按函数名或地址窗反汇编;
- gadgets:ROPgadget 封装(二进制缺失给干净报错)。

macOS 宿主无原生 readelf:自动回落 greadelf/gobjdump(brew binutils);
Linux 容器/物理层原生存在。
"""

from __future__ import annotations

import shutil
import subprocess
from typing import ClassVar

from .base import ToolContext, ToolError, resolve_in_workspace, truncate

# 危险导入表:出现即值得深挖(不区分 PLT/DYN,由调用格式呈现)
_DANGEROUS_SYMBOLS = (
    "system", "popen", "execve", "execvp", "execl", "execlp",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "realpath", "getenv", "setuid", "setgid", "chmod", "chown",
    "dlopen", "mmap", "memcpy",
)

_MAX_SYMBOLS = 60
_MAX_STRINGS = 80
_DISASM_LIMIT = 120  # 反汇编行数上限


def _find(*names: str) -> str:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    raise ToolError(f"二进制工具缺失:{'/'.join(names)}"
                    "(物理层镜像内可用;macOS 宿主 brew install binutils)")


def _run(command: list[str], ctx: ToolContext, timeout: float = 60.0) -> str:
    try:
        proc = subprocess.run(
            command, cwd=ctx.workspace, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise ToolError(f"命令超时(>{timeout}s):{' '.join(command[:3])}") from None
    if proc.returncode != 0:
        raise ToolError(f"exit {proc.returncode}: {proc.stderr.strip()[:200]}")
    return proc.stdout


# ---------------------------------------------------------------- 解析(纯函数)


def parse_checksec(header: str, program_headers: str, dynsyms: str) -> list[str]:
    """readelf -h/-l/--dyn-syms 输出 → 加固画像行。"""
    lines: list[str] = []
    is_pie = "Type:" in header and "DYN" in header
    lines.append("PIE    : Yes" if is_pie else "PIE    : No")
    nx_off = "GNU_STACK" in program_headers and "RWE" in program_headers
    lines.append("NX     : disabled(GNU_STACK RWE)" if nx_off else "NX     : enabled")
    has_relro = "GNU_RELRO" in program_headers
    bind_now = "BIND_NOW" in dynsyms or "FLAGS_1" in dynsyms and "NOW" in dynsyms
    if has_relro and bind_now:
        lines.append("RELRO  : Full")
    elif has_relro:
        lines.append("RELRO  : Partial")
    else:
        lines.append("RELRO  : None")
    canary = "__stack_chk_fail" in dynsyms
    lines.append("Canary : Yes" if canary else "Canary : No")
    lines.append("提示:No PIE + NX off + Canary No = 栈溢出直接 ROP 路线;"
                 "Full RELRO 则改写 GOT 路线关闭。")
    return lines


def parse_dangerous(dynsyms: str) -> list[str]:
    """符号表输出 → 命中的危险函数(保留出现序,去重)。"""
    hits: dict[str, None] = {}
    for name in _DANGEROUS_SYMBOLS:
        if name in dynsyms:
            hits.setdefault(name)
    return list(hits)


# ---------------------------------------------------------------- 工具


class BinaryTool:
    name = "binary"
    description = (
        "ELF analysis toolkit. Actions: info (file type), checksec (PIE/NX/RELRO/"
        "canary hardening profile), symbols (dynamic symbols, filterable), "
        "dangerous (dangerous imported functions), strings (filterable), "
        "disasm (by symbol name or address window), gadgets (ROPgadget). "
        "Use for binary exploitation / reverse engineering targets."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["info", "checksec", "symbols", "dangerous",
                          "strings", "disasm", "gadgets"],
            },
            "path": {"type": "string", "description": "binary in workspace"},
            "filter": {"type": "string", "description": "substring (symbols/strings)"},
            "symbol": {"type": "string", "description": "disasm: function name"},
            "start": {"type": "integer", "description": "disasm: start address"},
            "count": {"type": "integer", "description": "disasm: bytes to cover"},
        },
        "required": ["action", "path"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        target = resolve_in_workspace(ctx, str(args["path"]))
        if not target.is_file():
            raise ToolError(f"目标不存在:{args['path']}")
        action = args["action"]

        if action == "info":
            return self._info(target, ctx)
        if action == "checksec":
            return self._checksec(target, ctx)
        if action == "symbols":
            return self._symbols(target, ctx, str(args.get("filter") or ""))
        if action == "dangerous":
            return self._dangerous(target, ctx)
        if action == "strings":
            return self._strings(target, ctx, str(args.get("filter") or ""))
        if action == "disasm":
            return self._disasm(target, ctx, args)
        if action == "gadgets":
            return self._gadgets(target, ctx)
        raise ToolError(f"unknown action {action!r}")

    # ---- 各动作

    def _info(self, target, ctx: ToolContext) -> str:
        out = _run([_find("file"), str(target)], ctx)
        return out.strip()

    def _checksec(self, target, ctx: ToolContext) -> str:
        readelf = _find("readelf", "greadelf")
        header = _run([readelf, "-h", str(target)], ctx)
        phdrs = _run([readelf, "-l", str(target)], ctx)
        dynsyms = _run([readelf, "--dyn-syms", str(target)], ctx)
        return "\n".join(parse_checksec(header, phdrs, dynsyms))

    def _dynsyms_raw(self, target, ctx: ToolContext) -> str:
        readelf = _find("readelf", "greadelf")
        return _run([readelf, "-W", "--dyn-syms", str(target)], ctx)

    def _symbols(self, target, ctx: ToolContext, flt: str) -> str:
        raw = self._dynsyms_raw(target, ctx)
        lines = [
            ln.strip() for ln in raw.splitlines()
            if flt in ln and ("FUNC" in ln or "OBJECT" in ln or "IFUNC" in ln)
        ]
        if not lines:
            return f"无匹配符号(filter={flt!r})"
        return "\n".join(lines[:_MAX_SYMBOLS]) + f"\n({len(lines)} 行,截前 {_MAX_SYMBOLS})"

    def _dangerous(self, target, ctx: ToolContext) -> str:
        hits = parse_dangerous(self._dynsyms_raw(target, ctx))
        if not hits:
            return "无危险函数导入(静态链接?先跑 info 确认,再 strings 找线索)"
        return "危险导入:" + ", ".join(hits) + "\n优先深挖:system/popen(直接 RCE)、gets/strcpy/sprintf(溢出)、execve 族。"

    def _strings(self, target, ctx: ToolContext, flt: str) -> str:
        out = _run([_find("strings", "gstrings"), "-n", "6", str(target)], ctx, timeout=90)
        lines = [ln.strip() for ln in out.splitlines() if flt in ln]
        if not lines:
            return f"无匹配串(filter={flt!r})"
        return "\n".join(lines[:_MAX_STRINGS]) + f"\n({len(lines)} 行,截前 {_MAX_STRINGS})"

    def _disasm(self, target, ctx: ToolContext, args: dict) -> str:
        objdump = _find("objdump", "gobjdump")
        command = [objdump, "-d", "-M", "intel"]
        if args.get("symbol"):
            command += [f"--disassemble={args['symbol']}"]
        elif args.get("start") is not None:
            start = int(args["start"])
            count = min(int(args.get("count", 64)), 512)
            command += [
                f"--start-address={start}",
                f"--stop-address={start + count}",
            ]
        else:
            raise ToolError("disasm 需要 symbol 或 start(+count)")
        out = _run(command + [str(target)], ctx, timeout=90)
        lines = out.splitlines()
        return "\n".join(lines[:_DISASM_LIMIT]) + (
            f"\n({len(lines)} 行,截前 {_DISASM_LIMIT})" if len(lines) > _DISASM_LIMIT else ""
        )

    def _gadgets(self, target, ctx: ToolContext) -> str:
        rop = shutil.which("ROPgadget")
        if rop is None:
            raise ToolError("ROPgadget 不存在(pip install ROPgadget;物理层镜像内可用)")
        out = _run(
            [rop, "--binary", str(target), "--only", "pop|ret|syscall|leave"],
            ctx, timeout=120,
        )
        return truncate(out, ctx.max_output_chars)
