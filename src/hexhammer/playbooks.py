"""playbook 装配线:域知识 → solver system prompt。

知识资产(resources/playbooks/<domain>/playbook.md + skills)在这里变成
引擎的活知识:按域挂载、启动时内联进 system prompt(Heimdall 验证过的
注入方式)。
"""

from __future__ import annotations

from pathlib import Path

DOMAINS = ("web", "pentest", "binary", "cloud", "evasion", "exploit")

# 引擎级协议:所有域共享的底座(收件箱纪律、工具约定)
BASE_PROTOCOL = """你是 hexhammer 攻防 agent,在授权范围内执行自主渗透测试。

双重目标(按目标类型自动取舍):
- 有 flag 体系的目标(本地靶场):拿 flag,让它出现在命令输出里,引擎自动收集入库(验收用)。
- 真实目标(通常无 flag):**确认的漏洞就是交付物**——每确认一个,立即用 finding 工具
  记录(标题/证据=请求响应摘录/严重度),最终交付 findings + report.md。不要只盯着 flag。

通用纪律:
- 工作区内行动;命令超时=形状不对或服务不响应:换方法,不原样重发。
- 长输出先落文件再 grep;每有阶段性结论就追加写入 notes.md。
- 遵守任务描述里的范围与限制,不做破坏性动作。
"""

_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "resources"


def load_playbook(domain: str, resources_root: Path | None = None) -> str:
    root = (resources_root or _DEFAULT_ROOT) / "playbooks" / domain / "playbook.md"
    if not root.is_file():
        raise ValueError(f"playbook missing for domain {domain!r}: {root}")
    return root.read_text(encoding="utf-8")


def build_system_prompt(
    domain: str,
    resources_root: Path | None = None,
    *,
    skills: tuple[str, ...] = (),
    base_protocol: str = BASE_PROTOCOL,
) -> str:
    """组装 system prompt = 引擎协议 + 域 playbook (+ 附加技能全文)。"""
    parts = [base_protocol.strip(), "\n# 域知识\n", load_playbook(domain, resources_root)]
    root = resources_root or _DEFAULT_ROOT
    for skill in skills:
        skill_path = root / "skills" / skill / "SKILL.md"
        if not skill_path.is_file():
            raise ValueError(f"skill missing: {skill_path}")
        parts.append(f"\n# 技能:{skill}\n" + skill_path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def default_skills_for(domain: str) -> tuple[str, ...]:
    """挂载策略:WAF 绕过进 web/exploit/evasion;exploit 再挂复现+武器研发。"""
    if domain == "exploit":
        return ("waf-bypass", "cve-repro", "weapon-research", "source-audit")
    if domain == "pentest":
        return ("unknown-explore",)
    return ("waf-bypass",) if domain in ("web", "evasion") else ()
