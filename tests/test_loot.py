"""loot 工具测试:类目矩阵、二进制/大文件跳过、敏感文件名、选配与子集。"""

import json

from hexhammer.tools import ToolContext, default_registry

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.KnM3sPvmH5MfU7bBZSjJLx"


def _workspace(tmp_path):
    ws = tmp_path / "ws"
    (ws / "config").mkdir(parents=True)
    (ws / "keys").mkdir()
    (ws / "config" / ".env").write_text(
        "ALIYUN_AK=LTAI5tGx7VmNoKv3qZw1AbCdEf\nDB_PASSWORD=SuperSecret99\n",
        encoding="utf-8",
    )
    (ws / "keys" / "id_rsa").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n",
        encoding="utf-8",
    )
    (ws / "app.log").write_text(
        f"login ok token={JWT}\ndb_url=mysql://root:pass123@10.0.0.5/prod\n"
        "admin contact: ops@example.com\n",
        encoding="utf-8",
    )
    # 二进制:内含 AK 样串,但必须被跳过
    (ws / "blob.bin").write_bytes(b"\x00\x01LTAI5tGx7VmNoKv3qZw1AbCdEf\x00")
    return ws


def _dispatch(ws, args: dict):
    return default_registry().dispatch(
        "loot", json.dumps(args), ToolContext(workspace=ws)
    )


class TestLoot:
    def test_full_matrix_hits(self, tmp_path):
        ws = _workspace(tmp_path)
        content, is_error = _dispatch(ws, {})
        assert not is_error
        assert "阿里云 AccessKey" in content and "LTAI5tGx7VmNoKv3qZw1AbCdEf" in content
        assert "密码/凭证行" in content and "SuperSecret99" in content
        assert "私钥文件头" in content
        assert "JWT" in content and JWT in content
        assert "连接串" in content and "mysql://root:pass123@10.0.0.5" in content
        assert "邮箱" in content and "ops@example.com" in content
        assert "敏感文件名" in content and ".env" in content and "id_rsa" in content
        # 行级定位
        assert "app.log:1" in content
        # 二进制里的 AK 不得命中
        assert "blob.bin" not in content

    def test_internal_ip_opt_in(self, tmp_path):
        ws = _workspace(tmp_path)
        content, _ = _dispatch(ws, {})
        assert "内网 IP" not in content  # 默认关:渗透笔记里遍地都是
        content, _ = _dispatch(ws, {"patterns": ["internal_ip"]})
        assert "10.0.0.5" in content and "内网 IP(选配)" in content

    def test_pattern_subset_and_unknown(self, tmp_path):
        ws = _workspace(tmp_path)
        content, _ = _dispatch(ws, {"patterns": ["jwt"]})
        assert JWT in content and "LTAI" not in content
        content, is_error = _dispatch(ws, {"patterns": ["nope"]})
        assert is_error and "未知 pattern" in content

    def test_big_file_skipped(self, tmp_path):
        ws = _workspace(tmp_path)
        (ws / "huge.log").write_text("x" * (2 * 1024 * 1024 + 100) + "\nLTAI5tGx7VmNoKv3qZw1AbCdEf\n", encoding="utf-8")
        content, _ = _dispatch(ws, {})
        assert "huge.log" not in content

    def test_empty_workspace_negative(self, tmp_path):
        ws = tmp_path / "empty"
        ws.mkdir()
        content, is_error = _dispatch(ws, {})
        assert not is_error and "零命中" in content
