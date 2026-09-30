"""工具层命令策略:把扫描纪律从提示词搬进代码。

背景(2026-09-21 服务器侦察事故):提示词写死"礼貌扫描",模型照样发
`nmap -p 1-10000 --min-rate 2000` 并在超时后原样重发,三个孤儿进程叠打
目标。Heimdall 的解法是 PATH 钩子 exit-75 拒绝执行并把方向打回 stderr;
sapper 的解法是在 bash 工具入口做策略检查——**拒绝 + 指路**,让模型换
方法而不是换姿势重试。

策略(可配):
- nmap 端口跨度:单条命令端口总数 ≤ max_port_span(默认 2048,
  即 -p 1-65535 / -p- / -p 1-10000 全拒;top-ports 不受限);
- nmap 速率:--min-rate 值 > rate_cap(默认 1000)即拒,提示改
  --max-rate ≤ 600;
- 防重复:同一条命令(空白归一后)最多执行 allow_repeats 次(默认 2,
  容一次合法重试),超出即拒并提示换方法——超时后原样重发正是事故形态。
"""

from __future__ import annotations

from dataclasses import dataclass, field

GUIDANCE = (
    "策略拒绝了这条命令(这是物理纪律,不是建议)。{reason}"
    "换方法:缩小端口范围(如 --top-ports 200 或明确的端口列表)、"
    "限速(--max-rate 300)、或改用针对性探测;原样重发不会成功。"
)


@dataclass
class CommandPolicy:
    max_port_span: int = 2048
    rate_cap: int = 1000
    allow_repeats: int = 2
    _history: dict[str, int] = field(default_factory=dict, repr=False)

    # ---------------------------------------------------------------- 入口

    def check(self, command: str) -> tuple[bool, str]:
        """返回 (允许, 拒绝时的人类可读指路)。历史计数含被拒尝试。"""
        normalized = " ".join(command.split())
        self._history[normalized] = self._history.get(normalized, 0) + 1

        if self._history[normalized] > self.allow_repeats:
            count = self._history[normalized]
            return False, GUIDANCE.format(
                reason=f"该命令已执行/尝试 {count} 次(上限 {self.allow_repeats}),"
                "超时后原样重发是典型事故形态。"
            )

        if _word_in("nmap", command):
            span_problem = _nmap_port_span(command)
            if span_problem is not None and span_problem > self.max_port_span:
                return False, GUIDANCE.format(
                    reason=f"nmap 端口跨度 {span_problem} 超过上限 "
                    f"{self.max_port_span}。"
                )
            rate = _nmap_min_rate(command)
            if rate is not None and rate > self.rate_cap:
                return False, GUIDANCE.format(
                    reason=f"--min-rate {rate} 超过上限 {self.rate_cap},"
                    "高速叠打会打崩靶机也会引来封禁。"
                )
        return True, ""


# -------------------------------------------------------------------- 解析


def _word_in(word: str, command: str) -> bool:
    return f" {word} " in f" {command} " or command.startswith(f"{word} ")


def _nmap_port_span(command: str) -> int | None:
    """解析 nmap -p 参数的端口总数;无 -p(如 --top-ports)返回 None。"""
    tokens = command.split()
    port_spec: str | None = None
    for i, token in enumerate(tokens):
        if token == "-p" and i + 1 < len(tokens):
            port_spec = tokens[i + 1]
            break
        if token.startswith("-p") and not token.startswith("--") and len(token) > 2:
            port_spec = token[2:]
            break
    if port_spec is None:
        return None

    total = 0
    for part in port_spec.split(","):
        part = part.strip()
        # 形如 T:80 / U:53 的协议前缀
        if ":" in part and part.split(":", 1)[0] in ("T", "U"):
            part = part.split(":", 1)[1]
        if part == "-" or part == "*":  # -p- 全端口
            return 65535
        if "-" in part:
            lo, _, hi = part.rpartition("-")
            try:
                total += int(hi) - int(lo) + 1
            except ValueError:
                return 65535  # 解析不了按最坏情况拒
        elif part.isdigit():
            total += 1
        # 服务名(如 -p http)单端口,忽略
    return total


def _nmap_min_rate(command: str) -> int | None:
    tokens = command.split()
    for i, token in enumerate(tokens):
        if token == "--min-rate" and i + 1 < len(tokens):
            value = tokens[i + 1]
            if value.isdigit():
                return int(value)
        if token.startswith("--min-rate="):
            value = token.split("=", 1)[1]
            if value.isdigit():
                return int(value)
    return None
