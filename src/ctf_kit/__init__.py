"""
CTF Kit - AI-assisted CTF challenge solver toolkit.
"""

import sys

if sys.version_info < (3, 11):
    raise RuntimeError(
        f"CTF Kit requires Python 3.11 or later (running {sys.version}). "
        "See README.md for setup instructions using uv or pyenv."
    )

__version__ = "0.1.0"
__author__ = "Your Name"

from ctf_kit.config import Config, get_config

__all__ = ["Config", "__version__", "get_config"]
