"""CLI:python -m hexhammer.eval run [--variant full|basic|both] [--ids ...]"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..config import model_config_from_env
from ..llm import OpenAICompatClient
from ..llm.types import TokenLedger
from .golden import all_challenges
from .runner import format_report, results_as_dicts, run_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hexhammer.eval")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run golden suite with real LLM")
    run.add_argument("--variant", choices=["full", "basic", "both"], default="both")
    run.add_argument("--ids", nargs="*", help="challenge ids (default all)")
    run.add_argument("--env", default=".env")
    run.add_argument("--root", default="/tmp/sapper-golden")
    run.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    cfg = model_config_from_env(args.env)
    if not cfg.resolved():
        print("error: .env 缺 LLM 配置(SAPPER_LLM_BASE_URL/MODEL/API_KEY)")
        return 2

    def factory() -> tuple[OpenAICompatClient, TokenLedger]:
        ledger = TokenLedger()
        return OpenAICompatClient(cfg, ledger=ledger), ledger

    challenges = [
        c for c in all_challenges() if not args.ids or c.id in args.ids
    ]
    variants = ["full", "basic"] if args.variant == "both" else [args.variant]
    results = []
    for variant in variants:
        results += run_suite(factory, challenges, variant=variant, root=Path(args.root))

    print(format_report(results))
    if args.json:
        print(json.dumps(results_as_dicts(results), ensure_ascii=False, indent=1))
    return 0 if all(r.solved for r in results if r.variant == "full") else 1


if __name__ == "__main__":
    raise SystemExit(main())
