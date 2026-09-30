"""二进制工具测试:checksec/dangerous 纯解析 + 工具面接入。"""

import json

from hexhammer.tools import ToolContext, default_registry
from hexhammer.tools.binary import parse_checksec, parse_dangerous


def _ctx(tmp_path) -> ToolContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(workspace=tmp_path)


_HEADER_PIE = "  Type: DYN (Position-Independent Executable file)"
_HEADER_EXEC = "  Type: EXEC (Executable file)"
_PHDRS_RELRO = """
  GNU_RELRO      0x000e00 0x00000e00 0x00000e00 0x00100
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 RW  0x10
"""
_PHDRS_RWX = """
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 RWE 0x10
"""
_DYNSYMS_CANARY = "   123: 0000000000010000     5 FUNC    GLOBAL DEFAULT   14 __stack_chk_fail"
_DYNSYMS_NOW = "0x000000006ffffdf5 (FLAGS_1)            Flags: NOW"


class TestParseChecksec:
    def test_hardened_profile(self):
        lines = parse_checksec(_HEADER_PIE, _PHDRS_RELRO, _DYNSYMS_CANARY + "\n" + _DYNSYMS_NOW)
        assert "PIE    : Yes" in lines
        assert "NX     : enabled" in lines
        assert "RELRO  : Full" in lines
        assert "Canary : Yes" in lines

    def test_naked_profile(self):
        lines = parse_checksec(_HEADER_EXEC, _PHDRS_RWX, "")
        joined = "\n".join(lines)
        assert "PIE    : No" in joined
        assert "NX     : disabled" in joined
        assert "RELRO  : None" in joined
        assert "Canary : No" in joined
        # 裸配置 = 栈溢出直接 ROP 路线,提示必须给出
        assert "ROP" in joined

    def test_partial_relro(self):
        lines = parse_checksec(_HEADER_EXEC, _PHDRS_RELRO, _DYNSYMS_CANARY)
        assert "RELRO  : Partial" in lines


class TestParseDangerous:
    def test_hits_ordered_deduped(self):
        raw = "   5: system\n   6: strcpy\n   7: system\n   8: printf\n"
        assert parse_dangerous(raw) == ["system", "strcpy"]

    def test_clean_symbols(self):
        assert parse_dangerous("   5: printf\n   6: malloc\n") == []


class TestIntegration:
    def test_registered_in_default_surface(self, tmp_path):
        registry = default_registry()
        names = {t.name for t in registry.specs()}
        assert "binary" in names

    def test_missing_file_clean_error(self, tmp_path):
        registry = default_registry()
        content, is_error = registry.dispatch(
            "binary", json.dumps({"action": "checksec", "path": "nope.elf"}), _ctx(tmp_path)
        )
        assert is_error and "不存在" in content

    def test_disasm_requires_target(self, tmp_path):
        elf = tmp_path / "a.elf"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
        registry = default_registry()
        content, is_error = registry.dispatch(
            "binary", json.dumps({"action": "disasm", "path": "a.elf"}), _ctx(tmp_path)
        )
        assert is_error and ("symbol" in content or "start" in content)
