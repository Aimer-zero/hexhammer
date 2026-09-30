"""playbook 装配线测试:prompt 组装、技能挂载。"""

from pathlib import Path

import pytest

from hexhammer.playbooks import (
    build_system_prompt,
    default_skills_for,
    load_playbook,
)


class TestAssembly:
    def _fake_root(self, tmp_path: Path) -> Path:
        (tmp_path / "playbooks" / "web").mkdir(parents=True, exist_ok=True)
        (tmp_path / "playbooks" / "web" / "playbook.md").write_text("WEB-KB-42", encoding="utf-8")
        (tmp_path / "skills" / "waf-bypass").mkdir(parents=True, exist_ok=True)
        (tmp_path / "skills" / "waf-bypass" / "SKILL.md").write_text("WAF-KB-7", encoding="utf-8")
        return tmp_path

    def test_prompt_contains_protocol_and_playbook(self, tmp_path):
        prompt = build_system_prompt("web", self._fake_root(tmp_path))
        assert "hexhammer" in prompt and "WEB-KB-42" in prompt

    def test_skill_mounting(self, tmp_path):
        prompt = build_system_prompt(
            "web", self._fake_root(tmp_path), skills=default_skills_for("web")
        )
        assert "WAF-KB-7" in prompt
        # pentest 不挂 WAF 技能:为其建一个空 playbook 验证不携带
        root = self._fake_root(tmp_path)
        (root / "playbooks" / "pentest").mkdir(parents=True)
        (root / "playbooks" / "pentest" / "playbook.md").write_text("PT-KB", encoding="utf-8")
        assert "WAF-KB-7" not in build_system_prompt("pentest", root)

    def test_missing_playbook_raises(self, tmp_path):
        with pytest.raises(ValueError, match="missing"):
            build_system_prompt("cloud", self._fake_root(tmp_path))

    def test_repo_playbooks_present(self):
        # 仓库真实知识资产抽查(web/pentest 已交付)
        assert "flag" in load_playbook("web")
        assert len(load_playbook("pentest")) > 5000
