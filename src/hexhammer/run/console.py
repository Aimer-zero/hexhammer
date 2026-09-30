"""chat 控制台渲染层:紧凑 markdown + 左边线 + 同行标记(2026-09-29 终版)。

视觉:⏺ 同行、紧凑 markdown(自动降级纯文本)、2 空格左边距、dim 基调。"""

from __future__ import annotations

TOOL_MARK = "⏺"
STATUS_MARK = "✻"
SUB_MARK = "⎿"
SPINNER_WORDS = ("Pondering", "Percolating", "Simmering", "Vibing", "Wandering")

_SUMMARY_KEYS = ("command", "url", "target", "query", "path", "action", "text", "op", "scheme")


def args_summary(arguments_json: str, limit: int = 64) -> str:
    import json
    try:
        args = json.loads(arguments_json or "{}")
    except (ValueError, TypeError):
        return (arguments_json or "")[:limit]
    parts: list[str] = []
    for key in _SUMMARY_KEYS:
        if key in args:
            value = str(args[key])
            if len(value) > limit:
                value = value[: limit - 1] + "…"
            parts.append(f"{key}={value}")
            if len(parts) >= 2:
                break
    for key in args:
        if len(parts) >= 3:
            break
        if key not in _SUMMARY_KEYS:
            parts.append(f"{key}={str(args[key])[:32]}")
    return " ".join(parts) if parts else "(no args)"


def _has_markdown(text: str) -> bool:
    """检测是否含 markdown 语法(决定用 Markdown 渲染还是纯 Text)。"""
    import re
    return bool(re.search(r"(```|^\s*[-*]\s|^\s*\d+\.\s|^\s*#{1,3}\s|\*\*|__|`[^`]+`|\|.*\|)", text, re.M))


# ================================================== PlainConsole(测试/管道)

class PlainConsole:
    def __init__(self, print_fn=print) -> None:
        self._print = print_fn
    def welcome(self, info): self._print(f"hexhammer 交互模式。{info}")
    def user(self, text): pass
    def assistant(self, text):
        if text: self._print(f"\n引擎> {text}")
    def tool_start(self, name, summary): pass
    def tool_end(self, name, ok, summary, seconds):
        mark = "✓" if ok else "✗"
        self._print(f"  [{mark} {name}] {summary.replace(chr(10),' ')[:120]}")
    def notice(self, text): self._print(f"({text})")
    def stats(self, turns, seconds): pass
    def status(self, text):
        import contextlib; return contextlib.nullcontext()
    def stream_text(self): return _PlainStream(self)


class _PlainStream:
    def __init__(self, console):
        self._c = console; self._parts = []
    def write(self, chunk): self._parts.append(chunk)
    def close(self):
        text = "".join(self._parts).strip()
        if text: self._c.assistant(text)


# ================================================== RichChatConsole(生产)

class RichChatConsole:
    """⏺ 同行 · 纯文本优先(无 markdown 时) · 左边距 2 · 呼吸感。"""

    def __init__(self) -> None:
        from rich.console import Console
        self._c = Console(highlight=False, soft_wrap=False)

    def _text(self, content: str, style: str = "") -> "object":
        from rich.text import Text
        return Text(content, style=style) if style else Text(content)

    def _render_body(self, text: str, mark: bool = True) -> None:
        """正文渲染:有 markdown 语法的用 Markdown,否则纯 Text(更紧凑)。"""
        from rich.text import Text

        if mark:
            # ⏺ 与首行同行
            self._c.print(Text(f"  {TOOL_MARK} ", style="bold blue"), end="")
        else:
            self._c.print(Text("    ", style=""), end="")

        if _has_markdown(text):
            from rich.markdown import Markdown
            self._c.print(Markdown(text, code_theme="ansi_dark"))
        else:
            # 纯文本:更紧凑,无边距
            self._c.print(text)

    def welcome(self, info):
        from rich.text import Text
        line = Text()
        line.append("  ✦ ", style="bold cyan")
        line.append("sapper", style="bold")
        line.append("  自主渗透 · 复现 · 攻防一体", style="dim")
        self._c.print(Text())
        self._c.print(line)
        self._c.print(Text(f"  {info}", style="dim"))
        self._c.print(Text())

    def user(self, text): pass

    def assistant(self, text):
        if not text: return
        from rich.text import Text
        self._c.print(Text())  # 块前空行
        self._render_body(text, mark=True)

    def tool_start(self, name, summary):
        from rich.text import Text
        self._c.print(Text())  # 块前空行
        line = Text()
        line.append(f"  {TOOL_MARK} ", style="bold blue")
        line.append(name, style="bold")
        line.append(f"({summary})", style="dim")
        self._c.print(line)

    def tool_end(self, name, ok, summary, seconds):
        from rich.text import Text
        lines = (summary or "").strip().splitlines()
        style = "red bold" if not ok else "dim"
        line = Text()
        line.append(f"  {SUB_MARK} ", style="dim")
        line.append((lines[0][:80] if lines else ""), style=style)
        line.append(f"  {seconds:.1f}s", style="dim")
        self._c.print(line)
        for extra in lines[1:3]:
            self._c.print(Text(f"    {extra[:80]}", style="dim"))
        if len(lines) > 3:
            self._c.print(Text(f"    …(+{len(lines)-3} 行)", style="dim"))

    def notice(self, text):
        from rich.text import Text
        self._c.print(Text(f"  {STATUS_MARK} {text}", style="dim"))

    def stats(self, turns, seconds):
        from rich.text import Text
        self._c.print(Text(f"  {STATUS_MARK} {turns} 轮 · {seconds:.1f}s", style="dim"))

    def status(self, text):
        import random
        word = random.choice(SPINNER_WORDS)
        return self._c.status(f"  {STATUS_MARK} {word}…", spinner="dots")

    def stream_text(self):
        return _RichStream(self)


class _RichStream:
    """流式:缓冲到段边界,逐段渲染(⏺ 首段打一次,后续段缩进)。"""

    def __init__(self, console: RichChatConsole):
        self._console = console
        self._buf = ""
        self._first = True

    def write(self, chunk: str):
        self._buf += chunk
        if "\n\n" in self._buf:
            para, _, rest = self._buf.partition("\n\n")
            self._flush(para)
            self._buf = rest

    def _flush(self, text):
        from rich.text import Text
        if self._first:
            self._console._c.print(Text())  # 块前空行
            self._console._render_body(text.strip(), mark=True)
            self._first = False
        else:
            self._console._render_body(text.strip(), mark=False)

    def close(self):
        if self._buf.strip():
            self._flush(self._buf)


def make_console(print_fn=None):
    if print_fn is not None:
        return PlainConsole(print_fn)
    try:
        return RichChatConsole()
    except ImportError:
        return PlainConsole()
