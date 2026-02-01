"""
CTF Kit skills for AI-assisted challenge solving.

Skills orchestrate tools to analyze and solve specific challenge types.
"""

# Import skills to register them
from ctf_kit.skills.analyze import AnalyzeSkill
from ctf_kit.skills.base import (
    BaseSkill,
    SkillResult,
    get_all_skills,
    get_skill,
    get_skills_by_category,
    register_skill,
)
from ctf_kit.skills.crypto import CryptoSkill
from ctf_kit.skills.forensics import ForensicsSkill
from ctf_kit.skills.misc import MiscSkill
from ctf_kit.skills.osint import OSINTSkill
from ctf_kit.skills.pwn import PwnSkill
from ctf_kit.skills.reversing import ReversingSkill
from ctf_kit.skills.stego import StegoSkill
from ctf_kit.skills.web import WebSkill

__all__ = [
    "AnalyzeSkill",
    "BaseSkill",
    "CryptoSkill",
    "ForensicsSkill",
    "MiscSkill",
    "OSINTSkill",
    "PwnSkill",
    "ReversingSkill",
    "SkillResult",
    "StegoSkill",
    "WebSkill",
    "get_all_skills",
    "get_skill",
    "get_skills_by_category",
    "register_skill",
]
