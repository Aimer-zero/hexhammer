"""会话持久化:进程死 ≠ 任务死。

落盘物(每任务工作区):
- conversation.json:solver 会话(user/assistant/tool 全量,JSON 编解码);
- session.json:任务元数据(attempts/phase/elapsed/flags/stop_reasons)。

恢复语义:崩溃重启后,orchestrator 从断点继续——恢复会话以
"[恢复]" 注入续跑(复用方法也复用工作记忆),尝试计数与 PassClock
不归零。通关即清档(下次同题从零);失败保留(下轮可续)。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .llm.types import AssistantTurn, Conversation, ToolCall, ToolResult

CONVERSATION_FILE = "conversation.json"
SESSION_FILE = "session.json"


# ---------------------------------------------------------------- 会话编解码


def conversation_to_json(conversation: Conversation) -> str:
    items: list[dict] = []
    for role, payload in conversation.items():
        if role == "user":
            items.append({"role": "user", "text": payload})
        elif role == "assistant":
            turn: AssistantTurn = payload
            items.append(
                {
                    "role": "assistant",
                    "text": turn.text,
                    "tool_calls": [
                        {"id": c.id, "name": c.name, "arguments": c.arguments}
                        for c in turn.tool_calls
                    ],
                }
            )
        else:
            result: ToolResult = payload
            items.append(
                {
                    "role": "tool",
                    "tool_call_id": result.tool_call_id,
                    "content": result.content,
                    "is_error": result.is_error,
                }
            )
    return json.dumps({"version": 1, "items": items}, ensure_ascii=False, indent=1)


def conversation_from_json(raw: str) -> Conversation:
    data = json.loads(raw)
    conversation = Conversation()
    for item in data.get("items", []):
        role = item.get("role")
        if role == "user":
            conversation.add_user(item["text"])
        elif role == "assistant":
            conversation.add_assistant(
                AssistantTurn(
                    text=item.get("text", ""),
                    tool_calls=[
                        ToolCall(
                            id=c["id"], name=c["name"], arguments=c["arguments"]
                        )
                        for c in item.get("tool_calls", [])
                    ],
                )
            )
        elif role == "tool":
            conversation.add_tool(
                ToolResult(
                    tool_call_id=item["tool_call_id"],
                    content=item["content"],
                    is_error=item.get("is_error", False),
                )
            )
    return conversation


# ---------------------------------------------------------------- 会话档案


@dataclass
class Session:
    attempts: int = 0
    phase: int = 1
    elapsed_s: float = 0.0
    flags: list[str] = field(default_factory=list)
    stop_reasons: list[str] = field(default_factory=list)
    conversation: Conversation | None = None
    goal_head: str = ""  # 归属指纹:存档所属任务的 goal 前缀


class SessionStore:
    """每任务工作区的会话档案:原子写,通关清档。"""

    def __init__(self, workspace: Path) -> None:
        self._workspace = Path(workspace)

    def _write_atomic(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)

    def save(
        self,
        *,
        attempts: int,
        phase: int,
        elapsed_s: float,
        flags: list[str],
        stop_reasons: list[str],
        conversation: Conversation | None,
        goal_head: str = "",
    ) -> None:
        self._write_atomic(
            self._workspace / SESSION_FILE,
            json.dumps(
                {
                    "version": 1,
                    "attempts": attempts,
                    "phase": phase,
                    "elapsed_s": elapsed_s,
                    "flags": flags,
                    "stop_reasons": stop_reasons,
                    "goal_head": goal_head[:120],
                },
                ensure_ascii=False,
                indent=1,
            ),
        )
        if conversation is not None and conversation.items():
            self._write_atomic(
                self._workspace / CONVERSATION_FILE,
                conversation_to_json(conversation),
            )

    def load(self) -> Session | None:
        meta_path = self._workspace / SESSION_FILE
        if not meta_path.is_file():
            return None
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError):
            return None
        session = Session(
            attempts=int(meta.get("attempts", 0)),
            phase=int(meta.get("phase", 1)),
            elapsed_s=float(meta.get("elapsed_s", 0.0)),
            flags=list(meta.get("flags", [])),
            stop_reasons=list(meta.get("stop_reasons", [])),
            goal_head=str(meta.get("goal_head", "")),
        )
        conv_path = self._workspace / CONVERSATION_FILE
        if conv_path.is_file():
            try:
                session.conversation = conversation_from_json(
                    conv_path.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, ValueError, KeyError):
                session.conversation = None  # 会话损坏:丢会话保元数据
        return session

    def clear(self) -> None:
        """通关清档:同题下次从零开始。

        会话不删、挪 tmp/conversation-final.json 归档——复盘要对照引擎真实
        行为(0003 教训:accepted 清档把行为评估证据一并删了);归档不参与
        恢复语义,重复通关覆盖。
        """
        conv = self._workspace / CONVERSATION_FILE
        if conv.is_file():
            archive = self._workspace / "tmp" / "conversation-final.json"
            archive.parent.mkdir(parents=True, exist_ok=True)
            conv.replace(archive)
        meta = self._workspace / SESSION_FILE
        if meta.exists():
            meta.unlink()
