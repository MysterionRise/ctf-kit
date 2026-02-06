"""
File detection utilities for CTF Kit.

Provides file type detection, magic byte analysis, and CTF category suggestion.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - subprocess is required for file detection


class CTFCategory(StrEnum):
    """CTF challenge categories."""

    CRYPTO = "crypto"
    FORENSICS = "forensics"
    STEGO = "stego"
    WEB = "web"
    PWN = "pwn"
    REVERSING = "reversing"
    OSINT = "osint"
    MISC = "misc"


# Magic bytes for common file types
MAGIC_BYTES: dict[bytes, str] = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"BM": "BMP image",
    b"RIFF": "RIFF (WAV/AVI)",
    b"PK\x03\x04": "ZIP archive",
    b"PK\x05\x06": "ZIP archive (empty)",
    b"\x1f\x8b": "GZIP compressed",
    b"BZh": "BZIP2 compressed",
    b"\xfd7zXZ\x00": "XZ compressed",
    b"\x7fELF": "ELF executable",
    b"MZ": "DOS/Windows executable",
    b"%PDF": "PDF document",
    b"\x00\x00\x00\x14ftyp": "MP4 video",
    b"\x00\x00\x00\x18ftyp": "MP4 video",
    b"\x00\x00\x00\x1cftyp": "MP4 video",
    b"\x00\x00\x00\x20ftyp": "MP4 video",
    b"ID3": "MP3 audio",
    b"\xff\xfb": "MP3 audio",
    b"\xff\xfa": "MP3 audio",
    b"fLaC": "FLAC audio",
    b"OggS": "OGG audio/video",
    b"FORM": "IFF (AIFF/8SVX)",
    b"\x00asm": "WebAssembly",
    b"SQLite format 3": "SQLite database",
    b"\x50\x4b\x03\x04\x14\x00\x06\x00": "Office Open XML",
    b"Rar!\x1a\x07": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7z archive",
    b"\xca\xfe\xba\xbe": "Mach-O (32-bit)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64-bit)",
    b"BLENDER": "Blender file",
    b"\x1aE\xdf\xa3": "MKV video",
}

# File extensions to CTF category mapping
EXTENSION_CATEGORIES: dict[str, CTFCategory] = {
    # Crypto
    ".pem": CTFCategory.CRYPTO,
    ".key": CTFCategory.CRYPTO,
    ".pub": CTFCategory.CRYPTO,
    ".crt": CTFCategory.CRYPTO,
    ".csr": CTFCategory.CRYPTO,
    ".enc": CTFCategory.CRYPTO,
    # Forensics
    ".pcap": CTFCategory.FORENSICS,
    ".pcapng": CTFCategory.FORENSICS,
    ".raw": CTFCategory.FORENSICS,
    ".dmp": CTFCategory.FORENSICS,
    ".vmem": CTFCategory.FORENSICS,
    ".E01": CTFCategory.FORENSICS,
    ".ad1": CTFCategory.FORENSICS,
    # Stego
    ".png": CTFCategory.STEGO,
    ".jpg": CTFCategory.STEGO,
    ".jpeg": CTFCategory.STEGO,
    ".gif": CTFCategory.STEGO,
    ".bmp": CTFCategory.STEGO,
    ".wav": CTFCategory.STEGO,
    ".mp3": CTFCategory.STEGO,
    ".flac": CTFCategory.STEGO,
    # Web
    ".html": CTFCategory.WEB,
    ".js": CTFCategory.WEB,
    ".php": CTFCategory.WEB,
    ".sql": CTFCategory.WEB,
    ".db": CTFCategory.WEB,
    ".sqlite": CTFCategory.WEB,
    ".sqlite3": CTFCategory.WEB,
    # Pwn/Reversing
    ".elf": CTFCategory.PWN,
    ".so": CTFCategory.PWN,
    ".exe": CTFCategory.REVERSING,
    ".dll": CTFCategory.REVERSING,
    ".apk": CTFCategory.REVERSING,
    ".jar": CTFCategory.REVERSING,
    ".class": CTFCategory.REVERSING,
    ".pyc": CTFCategory.REVERSING,
    ".wasm": CTFCategory.REVERSING,
    # Misc
    ".zip": CTFCategory.MISC,
    ".tar": CTFCategory.MISC,
    ".gz": CTFCategory.MISC,
    ".bz2": CTFCategory.MISC,
    ".7z": CTFCategory.MISC,
    ".rar": CTFCategory.MISC,
    ".txt": CTFCategory.MISC,
    ".pdf": CTFCategory.MISC,
}

# Content patterns for category detection
CONTENT_PATTERNS: dict[str, tuple[CTFCategory, str]] = {
    r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----": (CTFCategory.CRYPTO, "Private key"),
    r"-----BEGIN (RSA |DSA |EC )?PUBLIC KEY-----": (CTFCategory.CRYPTO, "Public key"),
    r"-----BEGIN CERTIFICATE-----": (CTFCategory.CRYPTO, "X.509 certificate"),
    r"-----BEGIN PGP MESSAGE-----": (CTFCategory.CRYPTO, "PGP encrypted message"),
    r"[0-9a-f]{32,128}": (CTFCategory.CRYPTO, "Possible hash value"),
    r"flag\{[^}]+\}": (CTFCategory.MISC, "Flag format detected"),
    r"CTF\{[^}]+\}": (CTFCategory.MISC, "Flag format detected"),
    r"picoCTF\{[^}]+\}": (CTFCategory.MISC, "Flag format detected"),
    r"<\?php": (CTFCategory.WEB, "PHP code"),
    r"<script": (CTFCategory.WEB, "JavaScript detected"),
    r"SELECT .* FROM": (CTFCategory.WEB, "SQL query"),
    r"UNION SELECT": (CTFCategory.WEB, "SQL injection pattern"),
}


@dataclass
class FileInfo:
    """Information about a file."""

    path: Path
    name: str
    size: int
    extension: str
    magic_bytes: bytes
    file_type: str
    mime_type: str | None = None
    suggested_category: CTFCategory | None = None
    content_matches: list[str] = field(default_factory=list)
    is_text: bool = False
    encoding: str | None = None

    def to_dict(self) -> dict[str, str | int | bool | list[str] | None]:
        """Convert to dictionary for serialization."""
        return {
            "path": str(self.path),
            "name": self.name,
            "size": self.size,
            "extension": self.extension,
            "magic_bytes": self.magic_bytes.hex(),
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "suggested_category": self.suggested_category.value
            if self.suggested_category
            else None,
            "content_matches": self.content_matches,
            "is_text": self.is_text,
            "encoding": self.encoding,
        }


def get_magic_bytes(path: Path, num_bytes: int = 32) -> bytes:
    """Read first N bytes of a file for magic byte detection."""
    try:
        with path.open("rb") as f:
            return f.read(num_bytes)
    except OSError:
        return b""


def detect_magic_type(magic: bytes) -> str | None:
    """Detect file type from magic bytes."""
    for signature, file_type in MAGIC_BYTES.items():
        if magic.startswith(signature):
            return file_type
    return None


def run_file_command(path: Path) -> tuple[str, str | None]:
    """Run the 'file' command to detect file type."""
    file_binary = shutil.which("file")
    if not file_binary:
        return "Unknown (file command not available)", None

    try:
        result = subprocess.run(  # nosec B603 - intentional tool execution
            [file_binary, "-b", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        file_type = result.stdout.strip()

        # Try to get MIME type
        mime_result = subprocess.run(  # nosec B603 - intentional tool execution
            [file_binary, "-b", "--mime-type", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        mime_type = mime_result.stdout.strip() if mime_result.returncode == 0 else None
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return "Unknown (file command failed)", None
    else:
        return file_type, mime_type


def is_text_file(path: Path) -> tuple[bool, str | None]:
    """Check if a file is text and detect encoding."""
    file_binary = shutil.which("file")
    if not file_binary:
        # Fallback: try to read as text
        try:
            with path.open("r", encoding="utf-8") as f:
                f.read(1024)
        except (UnicodeDecodeError, OSError):
            return False, None
        else:
            return True, "utf-8"

    try:
        result = subprocess.run(  # nosec B603 - intentional tool execution
            [file_binary, "-b", "--mime-encoding", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        encoding = result.stdout.strip()
        is_binary = encoding in ("binary", "unknown-8bit")
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False, None
    else:
        return not is_binary, encoding if not is_binary else None


def check_content_patterns(path: Path) -> list[str]:
    """Check file content for CTF-relevant patterns."""
    matches: list[str] = []

    try:
        # Read first 10KB
        with path.open("rb") as f:
            content = f.read(10240)

        # Try to decode as text
        try:
            text_content = content.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            text_content = content.decode("latin-1", errors="ignore")

        for pattern, (category, description) in CONTENT_PATTERNS.items():
            if re.search(pattern, text_content, re.IGNORECASE):
                matches.append(f"{description} ({category.value})")

    except OSError:
        pass

    return matches


def suggest_category(file_info: FileInfo) -> CTFCategory:
    """Suggest CTF category based on file information."""
    # Check extension first
    if file_info.extension.lower() in EXTENSION_CATEGORIES:
        return EXTENSION_CATEGORIES[file_info.extension.lower()]

    # Check file type
    file_type_lower = file_info.file_type.lower()

    # ELF binaries are typically PWN challenges
    if "elf" in file_type_lower and ("32-bit" in file_type_lower or "64-bit" in file_type_lower):
        return CTFCategory.PWN

    if "executable" in file_type_lower:
        if "windows" in file_type_lower or "pe32" in file_type_lower.lower():
            return CTFCategory.REVERSING
        return CTFCategory.PWN

    if any(img in file_type_lower for img in ["image", "png", "jpeg", "gif", "bmp"]):
        return CTFCategory.STEGO

    if any(audio in file_type_lower for audio in ["audio", "wav", "mp3", "flac"]):
        return CTFCategory.STEGO

    if "pcap" in file_type_lower:
        return CTFCategory.FORENSICS

    if any(vid in file_type_lower for vid in ["video", "mp4", "avi", "mkv"]):
        return CTFCategory.FORENSICS

    if "pdf" in file_type_lower:
        return CTFCategory.FORENSICS

    if any(archive in file_type_lower for archive in ["zip", "tar", "gzip", "rar", "7z"]):
        return CTFCategory.MISC

    if "ascii" in file_type_lower or "text" in file_type_lower:
        # Check content patterns for text files
        for match in file_info.content_matches:
            if "crypto" in match.lower():
                return CTFCategory.CRYPTO
            if "web" in match.lower() or "sql" in match.lower():
                return CTFCategory.WEB

    return CTFCategory.MISC


def detect_file_type(path: Path) -> FileInfo:
    """
    Comprehensive file type detection.

    Args:
        path: Path to the file

    Returns:
        FileInfo with detected information
    """
    if not path.exists():
        return FileInfo(
            path=path,
            name=path.name,
            size=0,
            extension=path.suffix,
            magic_bytes=b"",
            file_type="File not found",
        )

    if not path.is_file():
        return FileInfo(
            path=path,
            name=path.name,
            size=0,
            extension=path.suffix,
            magic_bytes=b"",
            file_type="Not a regular file",
        )

    # Get basic info
    size = path.stat().st_size
    extension = path.suffix

    # Get magic bytes
    magic = get_magic_bytes(path)

    # Run file command
    file_type, mime_type = run_file_command(path)

    # Check if magic bytes give us more info
    magic_type = detect_magic_type(magic)
    if magic_type and file_type == "data":
        file_type = magic_type

    # Check if text
    is_text, encoding = is_text_file(path)

    # Check content patterns
    content_matches = check_content_patterns(path)

    # Create FileInfo
    info = FileInfo(
        path=path,
        name=path.name,
        size=size,
        extension=extension,
        magic_bytes=magic,
        file_type=file_type,
        mime_type=mime_type,
        is_text=is_text,
        encoding=encoding,
        content_matches=content_matches,
    )

    # Suggest category
    info.suggested_category = suggest_category(info)

    return info


def analyze_directory(path: Path) -> list[FileInfo]:
    """Analyze all files in a directory."""
    if not path.is_dir():
        return []

    return [
        detect_file_type(item)
        for item in path.iterdir()
        if item.is_file() and not item.name.startswith(".")
    ]


def format_size(size: int) -> str:
    """Format file size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} TB"
