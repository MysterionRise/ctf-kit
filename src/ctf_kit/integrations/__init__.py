"""
Tool integrations for CTF Kit.

Each subpackage contains wrappers for tools in that category.
"""

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolChain,
    ToolResult,
    ToolStatus,
    get_all_tools,
    get_tool,
    get_tools_by_category,
    register_tool,
)

__all__ = [
    "BaseTool",
    "ToolCategory",
    "ToolChain",
    "ToolResult",
    "ToolStatus",
    "get_all_tools",
    "get_tool",
    "get_tools_by_category",
    "register_tool",
]

# Import all tool modules to register them
from ctf_kit.integrations import (
    basic,  # noqa: F401  # file, strings
    crypto,  # noqa: F401  # hashid, xortool
    forensics,  # noqa: F401  # binwalk
    stego,  # noqa: F401  # exiftool, zsteg
)

# These imports will be uncommented as tools are implemented
# from ctf_kit.integrations import archive
# from ctf_kit.integrations import network
# from ctf_kit.integrations import web
# from ctf_kit.integrations import pwn
# from ctf_kit.integrations import reversing
# from ctf_kit.integrations import osint
