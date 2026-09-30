"""observer 外圈:证据窗 → 覆盖图注入(Heimdall "Circle of Circles" 的 hexhammer 版)。

职责:每隔 N 轮(或事件触发)把近期证据蒸馏成紧凑覆盖图,注入 solver
会话——长程记忆与工作记忆分离,压缩后幸存。字段语义:

- CONFIRMED:有证据支撑的事实(存活地址/有效凭证/已验证漏洞);
- LOCK:约束与已证死路(防重复侦察——token 效率的关键);
- ANGLES:下一批最值得试的方向,带具体命令;
- TENSION:证据矛盾点(该重验的地方)。

纪律:严格 JSON 输出、条数/字数封顶(总图 ≤3.5KB)、解析失败 fail-open
(保留旧图继续跑,绝不阻塞 solver——Heimdall 简报生成的同款教训)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .llm.types import (
    AssistantTurn,
    Conversation,
    LLMClientProtocol,
    LLMResponse,
    ToolResult,
    safe_json_loads,
)

MAX_ITEMS_PER_FIELD = 6
MAX_ITEM_CHARS = 160
_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


OBSERVER_SYSTEM = """你是 hexhammer 观察者(外圈),只读证据、不下场攻击。

读"任务目标"与"证据窗",输出严格 JSON(不要 markdown 代码块,不要多余文字):
{"confirmed": ["..."], "lock": ["..."], "angles": ["..."], "tension": ["..."]}

字段规则:
- confirmed:已证实事实(存活地址、有效凭证、确认的漏洞点),每条注明依据;
- lock:约束与已证死路(打不通的端口、被拦的 payload、平台限制)——写死,
  防止 solver 重复踩;
- angles:≤3 条,下一批最值得试的方向,每条带可直接执行的命令;
- tension:证据矛盾点(两个输出打架、结果不稳定)。

每条 ≤160 字符;每字段 ≤6 条;只输出 JSON 本体。"""


@dataclass
class ObserverMap:
    confirmed: list[str] = field(default_factory=list)
    lock: list[str] = field(default_factory=list)
    angles: list[str] = field(default_factory=list)
    tension: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, payload: dict) -> ObserverMap:
        def clean(items: object) -> list[str]:
            if not isinstance(items, list):
                return []
            return [
                str(item).strip()[:MAX_ITEM_CHARS]
                for item in items[:MAX_ITEMS_PER_FIELD]
                if str(item).strip()
            ]

        return cls(
            confirmed=clean(payload.get("confirmed")),
            lock=clean(payload.get("lock")),
            angles=clean(payload.get("angles")),
            tension=clean(payload.get("tension")),
        )

    def render(self) -> str:
        def section(title: str, items: list[str]) -> str:
            body = "\n".join(f"- {item}" for item in items) or "- (none)"
            return f"## {title}\n{body}"

        return (
            "<hexhammer-map>\n"
            + section("CONFIRMED(已证实)", self.confirmed)
            + "\n"
            + section("LOCK(约束/死路,勿重复)", self.lock)
            + "\n"
            + section("ANGLES(下一值得试)", self.angles)
            + "\n"
            + section("TENSION(待澄清的矛盾)", self.tension)
            + "\n</hexhammer-map>"
        )


def extract_json_object(text: str) -> dict:
    """从模型输出中抠出 JSON 对象;容忍 markdown 围栏与前后废话。"""
    stripped = text.strip()
    fenced = _JSON_FENCE.search(stripped)
    if fenced:
        stripped = fenced.group(1).strip()
    start, end = stripped.find("{"), stripped.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object found")
    return safe_json_loads(stripped[start : end + 1])


class Observer:
    """证据窗 → ObserverMap;失败 fail-open(返回 None,保留旧图)。"""

    def __init__(self, client: LLMClientProtocol, *, retries: int = 1) -> None:
        self._client = client
        self._retries = retries

    def observe(self, goal: str, evidence: str) -> ObserverMap | None:
        conversation = Conversation()
        conversation.add_user(
            f"# 任务目标\n{goal}\n\n# 证据窗(自上次观察)\n{evidence or '(空)'}"
        )
        for _ in range(self._retries + 1):
            try:
                response = self._client.chat(OBSERVER_SYSTEM, conversation)
                return ObserverMap.from_json(extract_json_object(response.turn.text))
            except Exception:  # noqa: BLE001, S112 - fail-open:观察者永不阻塞 solver
                continue
        return None


def evidence_window(
    conversation: Conversation, since_index: int, max_chars: int = 6000
) -> str:
    """把会话中 since_index 之后的内容压成观察者证据文本。"""
    chunks: list[str] = []
    for role, payload in conversation.items()[since_index:]:
        if role == "assistant":
            turn: AssistantTurn = payload
            if turn.text:
                chunks.append(f"[模型] {turn.text[:200]}")
            for call in turn.tool_calls:
                chunks.append(f"[调用] {call.name} {call.arguments[:200]}")
        elif role == "tool":
            result: ToolResult = payload
            tag = "错误" if result.is_error else "输出"
            chunks.append(f"[{tag}] {result.content[:400]}")
        # user 注入(目标/覆盖图)不进证据窗
    text = "\n".join(chunks)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n...(截断)"
    return text


def observation_response(text: str) -> LLMResponse:
    """测试/兜底辅助:把文本包装成 LLMResponse。"""
    from .llm.types import Usage

    return LLMResponse(turn=AssistantTurn(text=text), usage=Usage())
