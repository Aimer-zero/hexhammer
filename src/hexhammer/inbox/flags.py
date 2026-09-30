"""findings 收件箱:flag/发现 与提交解耦(架构铁律 2)。

模型只负责把发现写进收件箱(bash 输出刮取或显式调用);提交、去重、
对账由 adapter/控制面负责。持久化为工作区内一个 JSON 文件,原子写。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

# 三种平台旗标格式(对齐 Heimdall flag-scraper 的正则族)
FLAG_PATTERNS = (
    re.compile(r"flag\{[^}\s]{1,512}\}"),
    re.compile(r"ctf\{[^}\s]{1,512}\}"),
    re.compile(r"hack\{[^}\s]{1,512}\}"),
)


def extract_flags(text: str) -> list[str]:
    """按出现序提取去重后的 flag 候选。"""
    seen: dict[str, None] = {}
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            seen.setdefault(match)
    return list(seen)


class FindingsInbox:
    """flag 收件箱:add / pending / mark;JSON 持久化,原子替换写。

    多实例安全:solver 刮取与 adapter 冲洗各持实例,每次读写前都重载
    磁盘——否则后写者会用旧内存态覆盖前者的状态标记(实测竞态:
    flush 标的 submitted 被 solver 的下一次 add 冲回 pending → 重复提交)。
    写者同任务线程内串行,无并发写。
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._entries: list[dict] = []
        self._load()

    def _load(self) -> None:
        if self.path.is_file():
            try:
                self._entries = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, ValueError):
                self._entries = []
        else:
            self._entries = []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self._entries, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        tmp.replace(self.path)

    def add(self, flag: str, source: str = "") -> bool:
        """新增 flag 候选;已存在返回 False(幂等)。"""
        self._load()
        if any(e["flag"] == flag for e in self._entries):
            return False
        self._entries.append(
            {
                "seq": len(self._entries) + 1,
                "flag": flag,
                "source": source,
                "status": "pending",
                "ts": time.time(),
                "detail": "",
            }
        )
        self._save()
        return True

    def add_many(self, flags: list[str], source: str = "") -> list[str]:
        """批量入库,返回实际新增的 flag 列表。"""
        return [f for f in flags if self.add(f, source)]

    def pending(self) -> list[dict]:
        self._load()
        return [
            e for e in self._entries
            if e["status"] == "pending" and e.get("kind", "flag") == "flag"
        ]

    def flags_only(self) -> list[dict]:
        self._load()
        return [e for e in self._entries if e.get("kind", "flag") == "flag"]

    def add_finding(
        self,
        title: str,
        evidence: str,
        *,
        severity: str = "medium",
        kind: str = "vuln",
        endpoint: str = "",
    ) -> bool:
        """通用发现入库(漏洞/凭证/情报;flag 走 add)。按 title 幂等。

        真实目标通常没有 flag——确认的漏洞就是交付物,即时结构化落账。
        """
        self._load()
        if any(
            e.get("kind", "flag") == kind and e.get("title") == title
            for e in self._entries
        ):
            return False
        self._entries.append(
            {
                "seq": len(self._entries) + 1,
                "kind": kind,
                "title": title[:200],
                "severity": severity,
                "evidence": evidence[:2000],
                "endpoint": endpoint[:300],
                "status": "confirmed",
                "ts": time.time(),
                "flag": "",
                "source": "finding-tool",
                "detail": "",
            }
        )
        self._save()
        return True

    def findings(self, kind: str | None = None) -> list[dict]:
        self._load()
        return [
            e for e in self._entries
            if e.get("kind", "flag") != "flag"
            and (kind is None or e.get("kind") == kind)
        ]

    def mark(self, flag: str, status: str, detail: str = "") -> None:
        """状态迁移:pending → submitted / duplicate / rejected。"""
        self._load()
        for entry in self._entries:
            if entry["flag"] == flag:
                entry["status"] = status
                entry["detail"] = detail
        self._save()

    def known_flags(self) -> set[str]:
        self._load()
        return {e["flag"] for e in self._entries}

    def all_entries(self) -> list[dict]:
        self._load()
        return list(self._entries)
