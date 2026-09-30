"""bash 工具:工作区内执行 shell 命令,超时与输出上限受控。

超时杀整个进程组(start_new_session 让 shell 自成 pgid):只杀 shell 会
留下 nmap/sleep 等孙进程孤儿——2026-09-21 服务器侦察验证的实测事故,
三个孤儿 nmap 以 min-rate 2000 叠打目标。
"""

from __future__ import annotations

import os
import signal
import subprocess
from typing import ClassVar

from .base import ToolContext, ToolError


class BashTool:
    name = "bash"
    description = (
        "Run a bash command in the workspace. stdout+stderr combined; exit code "
        "appended. Long-running tasks: append ' & echo started' or use nohup."
    )
    parameters: ClassVar[dict] = {
        "type": "object",
        "properties": {
            "command": {"type": "string"},
            "timeout": {"type": "number", "description": "seconds, default 120"},
        },
        "required": ["command"],
    }

    def execute(self, args: dict, ctx: ToolContext) -> str:
        command = args["command"]
        allowed, guidance = ctx.policy.check(command)
        if not allowed:
            raise ToolError(guidance)
        timeout = min(float(args.get("timeout", ctx.bash_timeout)), ctx.bash_timeout)
        proc = subprocess.Popen(
            command,
            shell=True,
            cwd=ctx.workspace,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,  # 自成进程组,超时可整组回收
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
            partial = (stdout or "") + (stderr or "")
            raise ToolError(
                f"timeout after {timeout}s (process group killed); "
                f"partial output:\n{partial}"
            )
        output = stdout + (f"\n[stderr]\n{stderr}" if stderr else "")
        output = output.strip()
        returncode = proc.returncode or 0
        if returncode != 0:
            output += f"\n[exit {returncode}]"
        return output or f"[exit {returncode}, no output]"
