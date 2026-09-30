"""CLI 壳:sapper scan ... / python -m hexhammer.run scan ...

不要直接以文件路径执行本模块(相对 import 需要包上下文)。
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.exit(
        "直接执行该文件不可用(相对 import 无包上下文)。\n"
        "用包模式:uv run python -m hexhammer.run scan ...\n"
        "或装好的命令:uv run hexhammer scan ..."
    )

from . import MODES, run_scan


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hexhammer.run",
        description="sapper 引擎自用入口:对授权目标跑一轮渗透任务",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="对单一授权目标执行任务")
    scan.add_argument("--target", default="",
                      help="目标 IP/URL(缺省读 .env 的 SAPPER_TARGET_IP)")
    scan.add_argument("--domain", default="",
                      help="关联域名(缺省读 SAPPER_TARGET_DOMAIN)")
    scan.add_argument("--mode", choices=MODES, default="webapp",
                      help="recon=侦察画像 webapp=Web/API 渗透 chain=两者串行")
    scan.add_argument("--budget-min", type=float, default=30.0,
                      help="单任务时间预算(分钟,默认 30)")
    scan.add_argument("--authorize-rce-proof", action="store_true",
                      help="授权升到 RCE 证明档(默认只读+无害验证)")
    scan.add_argument("--out", default="",
                      help="输出目录(默认 runs/manual-<时间戳>)")
    scan.add_argument("--env", default=".env")

    chat_cmd = sub.add_parser("chat", help="交互对话模式(人说一句,引擎做一步)")
    chat_cmd.add_argument("--target", default="",
                          help="可选:预先钉死的授权目标;缺省不预设,对话里给什么测什么")
    chat_cmd.add_argument("--domain", default="pentest",
                          choices=["web", "pentest", "binary", "cloud", "evasion", "exploit"])
    chat_cmd.add_argument("--workspace", default="",
                          help="工作区(默认 runs/chat-<时间戳>)")
    chat_cmd.add_argument("--env", default=".env")

    sub.add_parser("doctor", help="外部依赖自检(缺失项给安装命令)")

    review_cmd = sub.add_parser("review", help="审阅 mission 蒸馏的经验条目(人审门)")
    review_cmd.add_argument("dir", nargs="?", default="",
                            help="mission 目录(含 experience-pending.jsonl)")
    review_cmd.add_argument("--approve-all", action="store_true",
                            help="全部批准并入正式经验库")

    args = parser.parse_args(argv)

    if args.cmd == "doctor":
        from . import doctor
        doctor()
        return 0

    if args.cmd == "review":
        from ..experience import default_library_path
        from ..experience import review as review_fn
        if not args.dir:
            from ..experience import ExperienceStore
            lib = ExperienceStore(default_library_path()).load()
            print(f"正式经验库:{default_library_path()}({len(lib)} 条)")
            for e in lib[-10:]:
                print(f"  [{e.kind}] {e.condition} → {e.finding[:60]}")
            return 0
        review_fn(Path(args.dir), approve_all=args.approve_all)
        return 0

    if args.cmd == "chat":
        from . import chat as chat_fn
        # 目标不预设:用户在对话里给什么就测什么;--target 仅用于预先钉死授权范围
        target = args.target
        workspace = Path(args.workspace) if args.workspace else Path(
            f"runs/chat-{_stamp()}"
        )
        chat_fn(target=target, domain=args.domain,
                workspace=workspace, env_path=Path(args.env))
        print(f"会话工作区:{workspace.resolve()}")
        return 0

    out = Path(args.out) if args.out else Path(
        f"runs/manual-{_stamp()}"
    )
    summary = run_scan(
        args.target,
        domain=args.domain,
        mode=args.mode,
        budget_min=args.budget_min,
        rce_proof=args.authorize_rce_proof,
        out_dir=out,
        env_path=Path(args.env),
    )
    for row in summary:
        print(f"{row['task_id']}: {row['status']} elapsed={row['elapsed_s']}s "
              f"stops={row['stop_reasons']}")
    print(f"产物目录:{out.resolve()}")
    return 0 if all(r["status"] == "accepted" for r in summary) else 1


if __name__ == "__main__":
    raise SystemExit(main())
