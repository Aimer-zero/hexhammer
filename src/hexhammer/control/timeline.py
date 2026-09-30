"""时间线:编排全程留痕(章程纪律 3——复盘与举报自证都靠它)。"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path


class Timeline:
    """线程安全的 JSONL 事件流,一行一个事件。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event: str, **fields: object) -> dict:
        record: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
        }
        for key, value in fields.items():
            record[key] = str(value) if isinstance(value, Path) else value
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return record


def null_timeline() -> Callable[..., dict]:
    """无档案模式(单测用):吞掉所有事件。"""
    return lambda event, **fields: {"event": event, **fields}
