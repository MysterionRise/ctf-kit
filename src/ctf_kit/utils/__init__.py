"""
CTF Kit utilities.
"""

from ctf_kit.utils.file_detection import (
    CTFCategory,
    FileInfo,
    detect_file_type,
    get_magic_bytes,
    suggest_category,
)

__all__ = [
    "CTFCategory",
    "FileInfo",
    "detect_file_type",
    "get_magic_bytes",
    "suggest_category",
]
