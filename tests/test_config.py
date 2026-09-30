"""config 模块测试:.env 加载优先级与长上下文守卫默认值。"""

from pathlib import Path

from hexhammer.config import ModelConfig, load_env_file, model_config_from_env


def test_load_env_file_parses_quotes_and_comments(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "SOME_SECRET=uuid-1234\n"
        'HEXHAMMER_LLM_API_KEY="sk-quoted"\n'
        "HEXHAMMER_LLM_BASE_URL=https://gw.example.com/v1\n"
        "\n"
        "MALFORMED_LINE_NO_EQUALS\n",
        encoding="utf-8",
    )
    loaded = load_env_file(env)
    assert loaded == {
        "SOME_SECRET": "uuid-1234",
        "HEXHAMMER_LLM_API_KEY": "sk-quoted",
        "HEXHAMMER_LLM_BASE_URL": "https://gw.example.com/v1",
    }


def test_load_env_file_missing_returns_empty(tmp_path: Path):
    assert load_env_file(tmp_path / "nope.env") == {}


def test_model_config_from_env_env_vars_take_precedence(
    tmp_path: Path, monkeypatch
):
    env = tmp_path / ".env"
    env.write_text(
        "HEXHAMMER_LLM_MODEL=from-file\nHEXHAMMER_LLM_BASE_URL=https://file/v1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HEXHAMMER_LLM_MODEL", "from-env")
    cfg = model_config_from_env(env)
    assert cfg.model == "from-env"
    assert cfg.base_url == "https://file/v1"  # 文件值兜底


def test_long_context_guard_defaults(tmp_path: Path, monkeypatch):
    for key in (
        "HEXHAMMER_LLM_PROTOCOL",
        "HEXHAMMER_LLM_MODEL",
        "HEXHAMMER_LLM_BASE_URL",
        "HEXHAMMER_LLM_CONTEXT_WINDOW",
        "HEXHAMMER_LLM_MAX_OUTPUT_TOKENS",
    ):
        monkeypatch.delenv(key, raising=False)
    cfg = model_config_from_env(tmp_path / "nope.env")
    # 守卫:flash 系必须显式长窗,防输出预算崩溃(见 config.py docstring)
    assert cfg.context_window == 1_000_000
    assert cfg.max_output_tokens == 131_072
    assert ModelConfig().context_window == 1_000_000
