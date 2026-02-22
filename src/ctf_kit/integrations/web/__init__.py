"""
Web security tool integrations for CTF Kit.

Tools for web application testing, SQL injection, and fuzzing.
"""

from ctf_kit.integrations.web.ffuf import FfufTool
from ctf_kit.integrations.web.gobuster import GobusterTool
from ctf_kit.integrations.web.nikto import NiktoTool
from ctf_kit.integrations.web.sqlmap import SqlmapTool

__all__ = ["FfufTool", "GobusterTool", "NiktoTool", "SqlmapTool"]
