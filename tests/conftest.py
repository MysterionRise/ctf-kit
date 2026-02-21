"""Shared pytest fixtures for CTF Kit test suite."""

from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Directory / path helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CHALLENGES_DIR = FIXTURES_DIR / "challenges"


@pytest.fixture()
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture()
def challenges_dir():
    return CHALLENGES_DIR


# ---------------------------------------------------------------------------
# Per-category challenge file fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def crypto_base64_file():
    return CHALLENGES_DIR / "crypto_base64.txt"


@pytest.fixture()
def crypto_hash_file():
    return CHALLENGES_DIR / "crypto_hash.txt"


@pytest.fixture()
def crypto_xor_file():
    return CHALLENGES_DIR / "crypto_xor.bin"


@pytest.fixture()
def forensics_embedded_file():
    return CHALLENGES_DIR / "forensics_embedded.bin"


@pytest.fixture()
def stego_test_image():
    return CHALLENGES_DIR / "stego_test.png"


@pytest.fixture()
def web_php_file():
    return CHALLENGES_DIR / "web_vuln.php"


@pytest.fixture()
def web_flask_file():
    return CHALLENGES_DIR / "web_flask.py"


@pytest.fixture()
def pwn_source_file():
    return CHALLENGES_DIR / "pwn_overflow.c"


@pytest.fixture()
def reverse_pyc_file():
    return CHALLENGES_DIR / "reverse_check.pyc"


@pytest.fixture()
def osint_profile_file():
    return CHALLENGES_DIR / "osint_profile.txt"


@pytest.fixture()
def misc_brainfuck_file():
    return CHALLENGES_DIR / "misc_brainfuck.bf"


@pytest.fixture()
def misc_encoding_file():
    return CHALLENGES_DIR / "misc_encoding.txt"


# ---------------------------------------------------------------------------
# Temp file helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def make_temp_file(tmp_path):
    """Factory fixture for creating temp files with content."""

    def _make(name, content, binary=False):
        path = tmp_path / name
        if binary:
            path.write_bytes(content)
        else:
            path.write_text(content)
        return path

    return _make


# ---------------------------------------------------------------------------
# Skill instance fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def analyze_skill():
    from ctf_kit.skills.analyze import AnalyzeSkill
    return AnalyzeSkill()


@pytest.fixture()
def crypto_skill():
    from ctf_kit.skills.crypto import CryptoSkill
    return CryptoSkill()


@pytest.fixture()
def forensics_skill():
    from ctf_kit.skills.forensics import ForensicsSkill
    return ForensicsSkill()


@pytest.fixture()
def stego_skill():
    from ctf_kit.skills.stego import StegoSkill
    return StegoSkill()


@pytest.fixture()
def web_skill():
    from ctf_kit.skills.web import WebSkill
    return WebSkill()


@pytest.fixture()
def pwn_skill():
    from ctf_kit.skills.pwn import PwnSkill
    return PwnSkill()


@pytest.fixture()
def reversing_skill():
    from ctf_kit.skills.reversing import ReversingSkill
    return ReversingSkill()


@pytest.fixture()
def osint_skill():
    from ctf_kit.skills.osint import OSINTSkill
    return OSINTSkill()


@pytest.fixture()
def misc_skill():
    from ctf_kit.skills.misc import MiscSkill
    return MiscSkill()
