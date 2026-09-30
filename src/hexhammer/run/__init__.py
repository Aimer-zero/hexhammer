"""hexhammer.run:自用入口——对任意授权目标跑一轮引擎任务,或交互对话/自检。

python -m hexhammer.run scan --target 1.2.3.4 [--domain example.com]
    [--mode recon|webapp|chain] [--budget-min 30] [--authorize-rce-proof]
    [--out runs/manual-<ts>]
python -m hexhammer.run chat [--target ...] [--domain pentest]
python -m hexhammer.run doctor

设计约束(章程):
- goal 只含任务语义,不喂任何答案册;
- 默认 a 档授权(只读+无害验证);--authorize-rce-proof 显式升 b 档
  (RCE 证明级:无害取证+写入复原,不落盘不持久化);
- 产物落 --out:notes.md / flags.json / timeline.jsonl / cost.json / records.json。
"""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import load_env_file, model_config_from_env
from ..control.orchestrator import MissionHooks, Orchestrator, TaskSpec
from ..control.timeline import Timeline
from ..inbox import FindingsInbox
from ..llm import OpenAICompatClient
from ..llm.types import (
    ContextOverflowError,
    Conversation,
    TokenLedger,
    ToolResult,
)
from ..playbooks import build_system_prompt
from ..tools import ToolContext, default_registry
from .console import args_summary, make_console

MODES = ("recon", "webapp", "chain")

# 外部依赖清单:工具名 → (候选可执行, 安装命令, 用途说明)
EXTERNAL_DEPS = (
    ("nmap", ("nmap",), "brew install nmap / apt install nmap", "端口与服务侦察"),
    ("sqlmap", ("sqlmap",), "apt install sqlmap / pip install sqlmap", "SQL 注入"),
    ("readelf 族", ("readelf", "greadelf"), "brew install binutils(Linux 自带)", "ELF 结构/checksec"),
    ("objdump 族", ("objdump", "gobjdump"), "brew install binutils(Linux 自带)", "反汇编"),
    ("strings 族", ("strings", "gstrings"), "brew install binutils(Linux 自带)", "字符串提取"),
    ("ROPgadget", ("ROPgadget",), "pip install ROPgadget", "ROP gadget 检索"),
    ("openssl", ("openssl",), "系统自带", "TLS/SNI 探测"),
    ("curl", ("curl",), "系统自带", "HTTP 请求"),
    ("nc", ("nc", "netcat"), "系统自带", "TCP 探测"),
    ("docker", ("docker",), "OrbStack / Docker Desktop", "本地靶与容器复现"),
)


def doctor(print_fn=print) -> dict[str, str | None]:
    """外部依赖自检:缺失不阻塞(工具调用时优雅报错),装上即用。"""
    found: dict[str, str | None] = {}
    for name, binaries, install, usage in EXTERNAL_DEPS:
        hit = next((b for b in binaries if shutil.which(b)), None)
        found[name] = hit
        mark = "✓" if hit else "✗"
        tail = hit if hit else f"缺失 → {install}"
        print_fn(f"{mark} {name:12} {tail:46} {usage}")
    missing = [n for n, f in found.items() if not f]
    if missing:
        print_fn(f"\n{len(missing)} 项缺失(不阻塞:对应工具调用时会给出干净报错与安装指引)。")
    else:
        print_fn("\n全部就绪。")
    return found


def _make_input(model: str, domain: str, workspace: Path, context_probe):
    """生产输入:prompt_toolkit(历史 ↑↓ + 底部状态栏:模型·域·Context 条)。

    缺库回退裸 input()。context_probe() -> (used_tokens, window)。
    """
    try:
        from prompt_toolkit import HTML, PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.styles import Style
    except ImportError:
        return input

    def toolbar():
        used, window = context_probe()
        window = max(window, 1)
        pct = used * 100 // window
        filled = round(pct / 5)
        bar = "█" * filled + "░" * (20 - filled)
        # 短对话(<1%)时百分比永远是 0 → 改显示实际 token 数,更有感
        if pct == 0 and used > 0:
            ctx_str = f"{used} tok"
        else:
            ctx_str = f"{pct}%"
        return HTML(
            f"{model} · {domain} 域 · Context "
            f"<ansicyan>{bar}</ansicyan> {ctx_str}"
        )

    # 底栏去反色(prompt_toolkit 默认反白条,与整体风格冲突)→ 普通 dim 行
    style = Style.from_dict({
        "bottom-toolbar": "noreverse fg:ansibrightblack",
        "bottom-toolbar.text": "fg:ansibrightblack",
    })
    session = PromptSession(
        history=FileHistory(str(workspace / ".chat_history")),
        style=style,
    )

    def _ask():
        return session.prompt(HTML("<ansibrightblue>❯ </ansibrightblue>"), bottom_toolbar=toolbar)

    return _ask


def chat(
    *,
    target: str = "",
    domain: str = "pentest",
    workspace: Path,
    env_path: Path = Path(".env"),
    max_turns_per_reply: int = 6,
    client=None,
    input_fn=None,
    print_fn=None,
    console=None,
) -> Conversation:
    """交互模式:你说一句,引擎做一步(逐轮显示工具调用),会话贯穿。

    与 scan 的自主到底不同:人在环上,随时纠偏/追问;单轮工具上限防失控。
    命令:exit/quit 退出;/clear 清会话重开;/ctx 重看目标上下文。
    """
    env = model_config_from_env(env_path)
    if not env.resolved():
        raise SystemExit("error: .env 缺 LLM 配置(SAPPER_LLM_BASE_URL/MODEL/API_KEY)")
    engine = client or OpenAICompatClient(env, ledger=TokenLedger())
    ui = console or make_console(print_fn)
    registry = default_registry()
    system = build_system_prompt(domain)
    ctx_line = (
        f"[操作者授权目标] {target} —— 当操作者的请求涉及对该目标的行动时,"
        "只在此目标范围内进行。闲聊与一般技术问题正常回答,不要主动发起对"
        "目标的扫描或攻击;确要行动时,先一句话说明将要做什么再动手。\n"
        if target else ""
    )
    conversation = Conversation()
    workspace.mkdir(parents=True, exist_ok=True)
    tool_ctx = ToolContext(workspace=workspace)
    first = True
    if input_fn is None:
        input_fn = _make_input(
            env.model, domain, workspace,
            lambda: (conversation.approx_tokens(), env.context_window),
        )

    ui.welcome("命令:exit 退出 / clear 清会话 / ctx 看目标")
    while True:
        try:
            user = input_fn().strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            ui.notice("再见")
            break
        if user.lower() in ("exit", "quit", "q"):
            break
        if not user:
            continue
        if user.lower() == "clear":
            conversation = Conversation()
            first = True
            ui.notice("会话已清空")
            continue
        if user.lower() == "ctx":
            ui.notice(ctx_line or "未指定目标(/target <ip或域名> 可设置)")
            continue
        if user.lower().startswith("/target ") or user.lower().startswith("target "):
            new_target = user.split(" ", 1)[1].strip()
            if not new_target:
                ui.notice("用法:/target <ip或域名>")
                continue
            target = new_target
            ctx_line = (
                f"[操作者授权目标] {target} —— 当操作者的请求涉及对该目标的行动时,"
                "只在此目标范围内进行。此前目标不再授权。闲聊与一般技术问题正常"
                "回答,不要主动发起扫描或攻击;确要行动时,先说明将要做什么。\n"
            )
            first = True  # 下一条消息重新携带授权上下文(不塞独立消息,保持交替)
            ui.notice(f"目标已切换:{target}(旧目标解除,下一条消息生效)")
            continue

        conversation.add_user(ctx_line + user if first else user)
        if first and target:
            ui.notice(f"目标已注入:{target}")
        first = False
        started = time.monotonic()
        tool_rounds = 0
        try:
            for _ in range(max_turns_per_reply):
                if getattr(engine, "streaming", False):
                    writer = ui.stream_text()
                    response = engine.chat(
                        system, conversation, registry.specs(),
                        stream_cb=writer.write,
                    )
                    writer.close()
                else:
                    with ui.status(""):
                        response = engine.chat(system, conversation, registry.specs())
                    if response.turn.text:
                        ui.assistant(response.turn.text)
                conversation.add_assistant(response.turn)
                if not response.turn.tool_calls:
                    break
                for call in response.turn.tool_calls:
                    ui.tool_start(call.name, args_summary(call.arguments))
                    t0 = time.monotonic()
                    with ui.status(f"running {call.name}"):
                        content, is_error = registry.dispatch(
                            call.name, call.arguments, tool_ctx
                        )
                    ui.tool_end(
                        call.name, not is_error, content, time.monotonic() - t0
                    )
                    conversation.add_tool(
                        ToolResult(
                            tool_call_id=call.id, content=content, is_error=is_error
                        )
                    )
                tool_rounds += 1
            else:
                ui.notice("单轮工具上限,回复截断;继续输入可延续会话")
        except ContextOverflowError:
            ui.notice("会话超窗:输入 clear 重开,或 exit 退出;工作区文件仍保留")
        except KeyboardInterrupt:
            ui.notice("已中断本轮回复(会话保留,可继续输入或 exit 退出)")
        ui.stats(tool_rounds, time.monotonic() - started)
    return conversation

DISCIPLINE = """
纪律(必须遵守):
- 单发探测间隔 >=2 秒;禁止并发扫描;遵守工具输出的 [recon-state] 状态行;
- 工具报「动态封禁」退避指引时立即停止主动探测,把已有发现收尾成报告;
- 长输出先落文件再 grep;阶段性结论立即追加写入 notes.md;
- 确认的漏洞/情报立即用 finding 工具落账(标题/证据原文/严重度),
  证据必须可独立重放(请求+响应摘录)。
"""

AUTH_A = "操作者授权(默认档):只读探测与无害验证。禁止任何改写目标状态的操作。"

AUTH_B = (
    "操作者授权(RCE 证明档):允许无害 RCE 取证(id/echo/whoami/sleep 时间盲注类)"
    "与写端点测试(测试后立即复原,若服务支持 delete/reset);"
    "禁止:落盘、部署 webshell、任何持久化、DoS、对外网横向。证完即撤,"
    "复原过程写入 notes.md。"
)

_GOALS = {
    "recon": (
        "任务:对目标 {target}{domain_hint} 做外部侦察并产出画像报告。\n"
        "覆盖:端口与服务(nmap 工具,阶梯 top_ports 100→300→1000)、"
        "Web/TLS 行为(证书/SNI 敏感性/跳转链)、暴露面 OSINT(被动,osint 工具)。\n"
        "交付:notes.md = 攻击面清单(端口/服务/版本/行为特征)+ 值得打的入口排序"
        "+ 每项证据摘录 + 结论。\n{auth}\n{discipline}"
    ),
    "webapp": (
        "任务:对目标 {target}{domain_hint} 做 Web/API 渗透测试(授权范围仅此目标)。\n"
        "方法:若有 /openapi.json 先拉全量端点并按 读/写/删/认证模式分类;"
        "认证模式对照 securitySchemes 声明与实际校验;逐项验证越权与注入面"
        "(路径穿越/SSTI/命令盲注/结构化注入——每项给出探测证据,证伪也算结论);"
        "按授权档推进到边界为止。\n"
        "交付:notes.md = 攻击面分类表 + 漏洞验证(可重放请求/响应)+ 证伪表 + 结论;"
        "findings >=1 条(带完整证据)。\n{auth}\n{discipline}"
    ),
}

_CHAIN_RECON_ID = "recon"
_CHAIN_WEB_ID = "webapp"


@dataclass
class RunPlan:
    """一次 scan 的装配结果(纯数据,可单测)。"""

    specs: list[TaskSpec]
    out_dir: Path
    mode: str


def build_goal(mode: str, target: str, domain: str, rce_proof: bool) -> str:
    if mode not in _GOALS:
        raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")
    auth = AUTH_B if rce_proof else AUTH_A
    domain_hint = f"(关联域名:{domain})" if domain else ""
    return _GOALS[mode].format(
        target=target, domain_hint=domain_hint, auth=auth, discipline=DISCIPLINE
    )


def _acceptance(*keywords: str, min_chars: int = 400, require_finding: bool = False):
    def accept(ws: Path, inbox: FindingsInbox) -> bool:
        notes = ws / "notes.md"
        if not notes.is_file():
            return False
        text = notes.read_text(encoding="utf-8")
        report_ok = len(text) > min_chars and all(k in text for k in keywords)
        return report_ok and (not require_finding or len(inbox.findings()) >= 1)

    return accept


def build_specs(mode: str, target: str, domain: str, rce_proof: bool,
                out_dir: Path, budget_min: float) -> list[TaskSpec]:
    budget_s = budget_min * 60.0
    common = {
        "priority": 1,
        "budget_regular_s": min(budget_s, 1800.0),
        "budget_loop_s": budget_s,
        "max_attempts": 2,
    }
    specs: list[TaskSpec] = []
    if mode in ("recon", "chain"):
        specs.append(TaskSpec(
            task_id=_CHAIN_RECON_ID,
            domain="pentest",
            goal=build_goal("recon", target, domain, rce_proof),
            workspace=out_dir / _CHAIN_RECON_ID,
            acceptance_fn=_acceptance("端口", "结论"),
            **common,
        ))
    if mode in ("webapp", "chain"):
        specs.append(TaskSpec(
            task_id=_CHAIN_WEB_ID,
            domain="web",
            goal=build_goal("webapp", target, domain, rce_proof),
            workspace=out_dir / _CHAIN_WEB_ID,
            acceptance_fn=_acceptance("结论", require_finding=True),
            **common,
        ))
    return specs


def run_scan(
    target: str,
    *,
    domain: str = "",
    mode: str = "webapp",
    budget_min: float = 30.0,
    rce_proof: bool = False,
    out_dir: Path,
    env_path: Path = Path(".env"),
) -> list[dict]:
    """装配并执行;返回 records 摘要 dict 列表。"""
    env = model_config_from_env(env_path)
    if not env.resolved():
        raise SystemExit("error: .env 缺 LLM 配置(SAPPER_LLM_BASE_URL/MODEL/API_KEY)")
    if mode not in MODES:
        raise SystemExit(f"error: --mode 必须是 {'/'.join(MODES)}")
    raw = load_env_file(env_path)
    target = target or raw.get("SAPPER_TARGET_IP", "")
    domain = domain or raw.get("SAPPER_TARGET_DOMAIN", "")
    if not target:
        raise SystemExit("error: 需要 --target(或 .env 配 SAPPER_TARGET_IP)")

    out_dir.mkdir(parents=True, exist_ok=True)
    # 历史经验注入:同域命中条目附进 goal(引擎带着实弹教训上场,不重复踩坑)
    from ..experience import ExperienceStore, default_library_path
    library = ExperienceStore(default_library_path())
    for spec in specs:
        addon = library.render(library.match(spec.domain, f"{target} {domain}"))
        if addon:
            spec.goal = f"{spec.goal}\n{addon}"

    timeline = Timeline(out_dir / "timeline.jsonl")
    ledgers: dict[str, TokenLedger] = {}
    specs = build_specs(mode, target, domain, rce_proof, out_dir, budget_min)

    orchestrator = Orchestrator(
        lambda spec: (
            ledgers.setdefault(spec.task_id, TokenLedger()),
            OpenAICompatClient(env, ledger=ledgers[spec.task_id]),
        )[1],
        lambda domain: build_system_prompt(domain),
        slots=1,  # 自用默认串行:单目标纪律
        timeline=timeline,
        hooks=MissionHooks(),
    )
    records = orchestrator.run(specs)

    import json

    (out_dir / "cost.json").write_text(
        json.dumps({t: l.snapshot() for t, l in ledgers.items()},
                   ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    summary = [
        {
            "task_id": r.spec.task_id,
            "status": r.status,
            "elapsed_s": round(r.elapsed_s, 1),
            "stop_reasons": r.stop_reasons,
            "error": r.error,
        }
        for r in records
    ]
    (out_dir / "records.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return summary
