"""引擎配置:.env / 环境变量加载与模型配置守卫。

守卫背景:deepseek-flash 系模型若不显式声明长上下文参数,网关会按短窗
默认截断,长会话死于输出预算崩溃(竞品 CyberPenda CONTEXT.md:262 的实
测教训)。因此 ModelConfig 的 context_window / max_output_tokens 一律
显式默认,绝不静默采用网关缺省。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def load_env_file(path: str | Path = ".env") -> dict[str, str]:
    """加载 KEY=VALUE 行到返回值;**不写回 os.environ、不覆盖已有环境变量**。

    凭证纪律(章程):token/密钥只进 .env(gitignored),不进 git、不进日志。
    """
    loaded: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return loaded
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # 去一层可选引号
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            loaded[key] = value
    return loaded


@dataclass
class ModelConfig:
    """LLM 接入配置。所有字段可用环境变量 HEXHAMMER_LLM_* 覆盖。"""

    protocol: str = "openai"  # "openai" | "anthropic" 兼容网关
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    # 显式长上下文守卫:见模块 docstring。
    context_window: int = 1_000_000
    max_output_tokens: int = 131_072
    temperature: float | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def resolved(self) -> bool:
        return bool(self.base_url and self.model)


def _env(loaded: dict[str, str], key: str) -> str | None:
    """环境变量优先于 .env 文件。"""
    if key in os.environ:
        return os.environ[key]
    return loaded.get(key)


def model_config_from_env(env_file: str | Path = ".env") -> ModelConfig:
    loaded = load_env_file(env_file)
    cfg = ModelConfig()
    cfg.protocol = _env(loaded, "HEXHAMMER_LLM_PROTOCOL") or cfg.protocol
    cfg.base_url = _env(loaded, "HEXHAMMER_LLM_BASE_URL") or cfg.base_url
    cfg.api_key = _env(loaded, "HEXHAMMER_LLM_API_KEY") or cfg.api_key
    cfg.model = _env(loaded, "HEXHAMMER_LLM_MODEL") or cfg.model
    if v := _env(loaded, "HEXHAMMER_LLM_CONTEXT_WINDOW"):
        cfg.context_window = int(v)
    if v := _env(loaded, "HEXHAMMER_LLM_MAX_OUTPUT_TOKENS"):
        cfg.max_output_tokens = int(v)
    if v := _env(loaded, "HEXHAMMER_LLM_TEMPERATURE"):
        cfg.temperature = float(v)
    return cfg
