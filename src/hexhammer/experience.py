"""经验库:跨 mission 的 LOCK/CONFIRMED/PATTERN 条目——引擎的长期记忆。

三个角色(章程路线①,2026-09-24 立):
- **存储**:ExperienceStore,单文件 JSONL;正式库在 resources/experience/
  library.jsonl(git 化,人审后入库);待审库在各 mission 目录
  experience-pending.jsonl;
- **蒸馏**:distill(mission_dir, client)——mission 结束后用 LLM 从档案
  (notes/findings/timeline)提取经验条目,每条必须带证据引用(档案路径+定位);
- **注入**:match+render——新 mission 装配时按域命中,以 [历史经验] 块附进
  goal(≤6 条),引擎带着历史上场,不重复踩坑。

人审门(铁律):pending → 正式库的唯一通道是操作者批准
(`hexhammer review <dir> --approve-all` 或手动改库)。错误经验固化比没有更糟,
战场提示注入也可能污染蒸馏产物——LLM 只提候选,人做裁决。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

_KINDS = ("lock", "confirmed", "pattern")
_KIND_LABEL = {"lock": "死路", "confirmed": "有效手法", "pattern": "漏洞模式"}
MAX_ENTRIES = 6
MAX_RENDER_CHARS = 2048

LIBRARY_FILENAME = "library.jsonl"
PENDING_FILENAME = "experience-pending.jsonl"

_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "resources" / "experience"


def default_library_path() -> Path:
    return _DEFAULT_LIBRARY / LIBRARY_FILENAME


@dataclass
class ExperienceEntry:
    kind: str            # lock | confirmed | pattern
    domain: str          # web/pentest/binary/cloud/evasion/exploit/general
    condition: str       # 适用条件:什么样的目标/场景下适用
    finding: str         # 结论/手法本体(一句话可执行)
    evidence: str        # 证据引用:哪个 mission 档案的哪部分
    confidence: int = 1  # 实弹验证次数
    origin: str = ""     # 来源 mission 标识(如 mission-001)
    approved: bool = False

    def validate(self) -> str | None:
        """返回错误原因;None=合法。"""
        if self.kind not in _KINDS:
            return f"kind 必须是 {'/'.join(_KINDS)}"
        for name in ("condition", "finding", "evidence"):
            value = getattr(self, name)
            if not value or not str(value).strip():
                return f"{name} 为空"
        if self.origin and ("/" in self.origin or "\\" in self.origin) and not any(
            self.origin.startswith(p) for p in ("val/", "runs/")
        ):
            return f"origin 非档案路径:{self.origin}"
        return None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> ExperienceEntry:
        return cls(
            kind=str(raw.get("kind", "")),
            domain=str(raw.get("domain", "general")),
            condition=str(raw.get("condition", "")),
            finding=str(raw.get("finding", "")),
            evidence=str(raw.get("evidence", "")),
            confidence=int(raw.get("confidence", 1)),
            origin=str(raw.get("origin", "")),
            approved=bool(raw.get("approved", False)),
        )


class ExperienceStore:
    """JSONL 读写;正式库字段 approved=True(由 review 流程写入)。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> list[ExperienceEntry]:
        if not self.path.is_file():
            return []
        entries: list[ExperienceEntry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(ExperienceEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, ValueError):
                continue
        return entries

    def add(self, entry: ExperienceEntry) -> bool:
        problem = entry.validate()
        if problem:
            raise ValueError(f"非法经验条目:{problem}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return True

    def add_many(self, entries: list[ExperienceEntry]) -> int:
        return sum(1 for e in entries if self.add(e))

    # -------------------------------------------------- 匹配与注入

    @staticmethod
    def _condition_fragments(condition: str) -> list[str]:
        """条件的匹配片段:英文按词,中文按 2-gram(中文无空格分词)。"""
        import re

        fragments: list[str] = []
        for chunk in re.findall(r"[\u4e00-\u9fff]+|[A-Za-z0-9.-]{2,}", condition.lower()):
            if re.match(r"[\u4e00-\u9fff]", chunk):
                fragments += [chunk[i : i + 2] for i in range(len(chunk) - 1)]
            else:
                fragments.append(chunk)
        return fragments

    def match(self, domain: str, traits: str = "") -> list[ExperienceEntry]:
        """按域命中;condition 特征片段出现在 traits 里则加权,得分排序。"""
        scored: list[tuple[int, ExperienceEntry]] = []
        traits_l = (traits or "").lower()
        for entry in self.load():
            if entry.domain not in (domain, "general"):
                continue
            score = entry.confidence
            if traits_l and any(
                frag in traits_l for frag in self._condition_fragments(entry.condition)
            ):
                score += 10  # 条件特征命中:强相关
            scored.append((score, entry))
        scored.sort(key=lambda pair: -pair[0])
        return [e for _, e in scored[:MAX_ENTRIES]]

    def render(self, entries: list[ExperienceEntry]) -> str:
        """注入块:可空;超预算截断条目。"""
        if not entries:
            return ""
        lines = [
            "[历史经验](实弹档案蒸馏,人审入库;与当前现场观察冲突时,以现场为准)",
        ]
        used = len(lines[0])
        for entry in entries:
            label = _KIND_LABEL.get(entry.kind, entry.kind)
            body = f"- [{label}|{entry.condition}] {entry.finding}(证据:{entry.evidence})"
            if used + len(body) > MAX_RENDER_CHARS:
                lines.append("- (其余经验因注入预算截断,详见经验库)")
                break
            lines.append(body)
            used += len(body)
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 蒸馏

DISTILL_SYSTEM = """你是 hexhammer 的复盘蒸馏官。读一份 mission 档案,提取可跨目标复用的经验条目。

严格输出 JSON 数组(不要 markdown 围栏、不要多余文字),每条:
{"kind":"lock|confirmed|pattern","domain":"web|pentest|binary|cloud|evasion|exploit|general",
 "condition":"适用条件——什么特征的目标/场景下适用(具体,如:云防护目标的 8443 高频探测)",
 "finding":"结论/手法一句话(可执行,如:单发间隔>=2s 全程不触发封禁)",
 "evidence":"证据定位(必须引用档案内可查的内容,如:mission-001 notes §结论)",
 "origin":"<mission_id>"}

提取规则:
- 只收**可跨目标复用**的:死路(lock,防止重复踩)、有效手法(confirmed)、
  可识别的漏洞模式(pattern);目标专属事实(某端口某域名)不收;
- 每条 evidence 必须能回到档案里查到(路径+小节/关键词),编造引用=废条;
- 宁缺毋滥:2~5 条高质量即可,没有就输出 []。"""




# 目标特定信息的泛化映射(章程纪律 6:知识资产不携带单目标标识)
_SANITIZE_MAP = {
    # 常见云厂商 IP 段示例
    # IP 段泛化(按需扩充,勿硬编码真实段)
    # 具体端点泛化(按需扩充)
    "/api/doctor": "<诊断端点>",
    "/api/setup": "<配置端点>",
    "/api/bind": "<绑定端点>",
    "/api/whoami": "<触发端点>",
}


def _sanitize_entry(entry: ExperienceEntry) -> None:
    """蒸馏产物的自动脱敏:域名/IP 泛化(章程纪律 6)。"""
    for field in ("condition", "finding", "evidence"):
        value = getattr(entry, field, "")
        for old_text, new_text in _SANITIZE_MAP.items():
            value = value.replace(old_text, new_text)
        setattr(entry, field, value)

def _mission_material(mission_dir: Path, mission_id: str) -> str:
    """蒸馏材料:notes 全文(截断)+ findings 摘要 + timeline 事件统计。"""
    parts: list[str] = [f"# mission {mission_id} 档案材料"]

    notes = sorted(mission_dir.rglob("notes.md"))
    if notes:
        text = notes[0].read_text(encoding="utf-8", errors="ignore")[:8000]
        parts.append(f"## notes.md(主报告)\n{text}")

    flags = sorted(mission_dir.rglob("flags.json"))
    for path in flags:
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError, OSError):
            continue
        findings = [
            f"- [{r.get('severity', '?')}] {r.get('title', '')}"
            for r in rows
            if r.get("kind") != "flag"
        ]
        if findings:
            parts.append(
                f"## {path.parent.name}/findings({len(findings)} 条)\n" + "\n".join(findings[:12])
            )

    timeline = mission_dir / "timeline.jsonl"
    if timeline.is_file():
        events = [
            json.loads(line)
            for line in timeline.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        kinds: dict[str, int] = {}
        for ev in events:
            kinds[ev.get("event", "?")] = kinds.get(ev.get("event", "?"), 0) + 1
        summary = ", ".join(f"{k}×{v}" for k, v in sorted(kinds.items()))
        parts.append(f"## timeline 事件统计\n{summary}")
        for ev in events:
            if ev.get("event") in ("task_end", "mission_end"):
                parts.append(json.dumps(ev, ensure_ascii=False)[:400])

    return "\n\n".join(parts)


def _extract_json_array(text: str) -> list[dict]:
    stripped = text.strip()
    if stripped.startswith("```"):
        first_newline = stripped.find("\n")
        stripped = stripped[first_newline + 1 :] if first_newline >= 0 else ""
        stripped = stripped.rsplit("```", 1)[0]
    start, end = stripped.find("["), stripped.rfind("]")
    if start < 0 or end <= start:
        raise ValueError("no JSON array found")
    return json.loads(stripped[start : end + 1])


def distill(
    mission_dir: Path,
    client,
    mission_id: str = "",
) -> list[ExperienceEntry]:
    """mission 档案 → LLM 蒸馏 → 待审条目(fail-open:出错返回 [])。

    产物不直接入库——写 <mission_dir>/experience-pending.jsonl,等人审。
    """
    from .llm.types import Conversation

    mission_dir = Path(mission_dir)
    mission_id = mission_id or str(mission_dir)
    material = _mission_material(mission_dir, mission_id)
    if len(material) < 200:  # 档案太空,没有蒸馏价值
        return []

    conversation = Conversation()
    conversation.add_user(material)
    try:
        response = client.chat(DISTILL_SYSTEM, conversation)
        rows = _extract_json_array(response.turn.text)
    except Exception:  # noqa: BLE001 - 蒸馏 fail-open:档案仍在,人可手写
        return []

    entries: list[ExperienceEntry] = []
    for row in rows[:8]:
        if not isinstance(row, dict):
            continue
        row.setdefault("origin", mission_id)
        entry = ExperienceEntry.from_dict({**row, "approved": False})
        if entry.validate() is None:
            _sanitize_entry(entry)
            entries.append(entry)

    if entries:
        pending = ExperienceStore(mission_dir / PENDING_FILENAME)
        pending.add_many(entries)
    return entries


def review(mission_dir: Path, *, approve_all: bool = False, print_fn=print) -> list[ExperienceEntry]:
    """人审门:显示 pending;approve_all=True 时合并入正式库(幂等)。"""
    mission_dir = Path(mission_dir)
    pending = ExperienceStore(mission_dir / PENDING_FILENAME)
    entries = pending.load()
    if not entries:
        print_fn(f"{mission_dir}:无待审经验条目。")
        return []

    for i, entry in enumerate(entries, 1):
        label = _KIND_LABEL.get(entry.kind, entry.kind)
        print_fn(
            f"[{i}] {label} · {entry.domain} 域\n"
            f"    条件:{entry.condition}\n"
            f"    结论:{entry.finding}\n"
            f"    证据:{entry.evidence}\n"
            f"    来源:{entry.origin}"
        )

    if not approve_all:
        print_fn(f"\n共 {len(entries)} 条待审。确认后:hexhammer review {mission_dir} --approve-all")
        return entries

    library = ExperienceStore(default_library_path())
    existing = {
        (e.kind, e.condition, e.finding) for e in library.load()
    }
    merged: list[ExperienceEntry] = []
    for entry in entries:
        key = (entry.kind, entry.condition, entry.finding)
        if key in existing:
            continue
        entry.approved = True
        library.add(entry)
        existing.add(key)
        merged.append(entry)
    print_fn(f"已入库 {len(merged)} 条(去重 {len(entries) - len(merged)}),正式库:{default_library_path()}")
    return merged
