"""工具面:基础七件套 + 攻击工具包(http/jwt/bypass403/encode/nmap/sqlmap)。"""

from .attack import register_attack_tools
from .base import Registry, Tool, ToolContext, ToolError, truncate
from .fs import default_fs_tools
from .shell import BashTool

__all__ = [
    "BashTool",
    "Registry",
    "Tool",
    "ToolContext",
    "ToolError",
    "default_fs_tools",
    "register_attack_tools",
    "truncate",
]


def default_registry(transport=None) -> Registry:
    """solver 默认工具面:文件六件套 + bash + 攻击六件套。

    transport 仅供测试注入 MockTransport;生产为 None(真实网络)。
    """
    registry = Registry()
    for tool in default_fs_tools():
        registry.register(tool)
    registry.register(BashTool())
    register_attack_tools(registry, transport)
    return registry
