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
    archive,  # noqa: F401  # bkcrack
    basic,  # noqa: F401  # file, strings
    crypto,  # noqa: F401  # hashid, xortool, rsactftool, john, hashcat
    encoding,  # noqa: F401  # cyberchef
    forensics,  # noqa: F401  # binwalk, volatility, tshark, foremost
    misc,  # noqa: F401  # zbarimg, qrencode
    osint,  # noqa: F401  # sherlock, theharvester, whois, dig, shodan
    pwn,  # noqa: F401  # checksec, ropgadget, pwntools
    reversing,  # noqa: F401  # radare2, ghidra
    stego,  # noqa: F401  # exiftool, zsteg, steghide
    web,  # noqa: F401  # sqlmap, gobuster, ffuf, nikto
)
