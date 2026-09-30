"""评测:golden set 题集(v1 判定题 / v2 利用链题)+ A/B 运行器。"""

from .golden import Challenge, all_challenges
from .golden2 import all_v2_challenges
from .runner import SuiteResult, format_report, results_as_dicts, run_suite

__all__ = [
    "Challenge",
    "SuiteResult",
    "all_challenges",
    "all_v2_challenges",
    "format_report",
    "results_as_dicts",
    "run_suite",
]
