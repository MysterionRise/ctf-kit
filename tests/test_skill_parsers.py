"""Tests for skill script output parsers in skills/_lib/."""

import importlib.util
from pathlib import Path

import pytest

# Load parser modules from skills/_lib/ directory
LIB_DIR = Path(__file__).parent.parent / "skills" / "_lib"


def _load_parser(name: str):
    """Load a parser module by name."""
    spec = importlib.util.spec_from_file_location(name, LIB_DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        pytest.skip(f"Parser {name} not found")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestParseBinwalk:
    """Tests for parse-binwalk.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-binwalk")

    def test_parse_signatures(self, parser):
        raw = """DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v2.0 to extract
1024          0x400           PNG image data, 100 x 100"""
        result = parser.parse_binwalk(raw, "test.bin")

        assert result["tool"] == "binwalk"
        assert result["signature_count"] == 2
        assert result["signatures"][0]["offset"] == 0
        assert result["signatures"][0]["type"] == "zip"
        assert result["signatures"][1]["type"] == "png"
        assert "zip" in result["file_types"]
        assert "png" in result["file_types"]

    def test_next_steps_flags(self, parser):
        raw = "0  0x0  Zip archive data"
        result = parser.parse_binwalk(raw, "test.bin")

        assert result["next_steps"]["has_archives"] is True
        assert result["next_steps"]["has_executables"] is False

    def test_empty_output(self, parser):
        result = parser.parse_binwalk("", "test.bin")

        assert result["signature_count"] == 0
        assert "No embedded files" in result["suggestions"][0]

    def test_suggestions_for_multiple_sigs(self, parser):
        raw = """0  0x0  Zip archive data
1024  0x400  ELF, 64-bit"""
        result = parser.parse_binwalk(raw)

        assert any("Multiple" in s for s in result["suggestions"])

    def test_elf_detection(self, parser):
        raw = "0  0x0  ELF, 64-bit LSB executable"
        result = parser.parse_binwalk(raw)

        assert "elf" in result["file_types"]
        assert result["next_steps"]["has_executables"] is True


class TestParseStrings:
    """Tests for parse-strings.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-strings")

    def test_flag_detection(self, parser):
        raw = "flag{test_flag_123}\nsome other string"
        result = parser.parse_strings(raw, "test.bin")

        assert result["has_flag"] is True
        assert "flag" in result["findings"]["flags"][0]
        assert "FLAG FOUND" in result["suggestions"][0]

    def test_url_detection(self, parser):
        raw = "https://example.com/path"
        result = parser.parse_strings(raw)

        assert result["findings"]["urls"]
        assert any("URL" in s for s in result["suggestions"])

    def test_hash_detection(self, parser):
        raw = "5d41402abc4b2a76b9719d911017c592"
        result = parser.parse_strings(raw)

        assert result["findings"]["hashes"]
        assert any("hash" in s.lower() for s in result["suggestions"])

    def test_empty_input(self, parser):
        result = parser.parse_strings("")

        assert result["total_strings"] == 0

    def test_email_detection(self, parser):
        raw = "admin@example.com"
        result = parser.parse_strings(raw)

        assert result["findings"]["emails"]


class TestParseHashid:
    """Tests for parse-hashid.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-hashid")

    def test_parse_hashid_output(self, parser):
        raw = """Analyzing '5d41402abc4b2a76b9719d911017c592'
[+] MD5
[+] MD4
[+] NTLM"""
        result = parser.parse_hashid(raw, "5d41402abc4b2a76b9719d911017c592")

        assert result["hash_count"] == 1
        assert result["hashes"][0]["types"][0]["type"] == "MD5"
        assert result["hashes"][0]["types"][0]["hashcat_mode"] == 0

    def test_length_fallback(self, parser):
        result = parser.parse_hashid("", "5d41402abc4b2a76b9719d911017c592")

        assert result["hash_count"] == 1
        assert any("MD5" in t["type"] for t in result["hashes"][0]["types"])

    def test_sha1_by_length(self, parser):
        result = parser.parse_hashid("", "a" * 40)

        assert any("SHA1" in t["type"] for t in result["hashes"][0]["types"])

    def test_suggestions_include_commands(self, parser):
        raw = """Analyzing 'hash'
[+] MD5"""
        result = parser.parse_hashid(raw, "hash")

        assert any("hashcat" in s for s in result["suggestions"])
        assert any("john" in s for s in result["suggestions"])


class TestParseChecksec:
    """Tests for parse-checksec.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-checksec")

    def test_all_disabled(self, parser):
        raw = "No RELRO  No canary found  NX disabled  No PIE"
        result = parser.parse_checksec(raw, "./vuln")

        assert result["protections"]["relro"] == "none"
        assert result["protections"]["stack_canary"] == "disabled"
        assert result["protections"]["nx"] == "disabled"
        assert result["protections"]["pie"] == "disabled"
        assert "buffer_overflow" in result["attack_vectors"]
        assert "shellcode" in result["attack_vectors"]

    def test_all_enabled(self, parser):
        raw = "Full RELRO  Canary found  NX enabled  PIE enabled"
        result = parser.parse_checksec(raw)

        assert result["protections"]["relro"] == "full"
        assert result["protections"]["stack_canary"] == "enabled"
        assert result["protections"]["nx"] == "enabled"
        assert result["protections"]["pie"] == "enabled"

    def test_arch_detection(self, parser):
        raw = "Arch:     amd64-64-little\nNo RELRO"
        result = parser.parse_checksec(raw)

        assert result["arch"] == "amd64-64-little"

    def test_strategy_shellcode(self, parser):
        raw = "No canary found  NX disabled  No PIE"
        result = parser.parse_checksec(raw)

        assert any("STRATEGY" in s and "shellcode" in s for s in result["suggestions"])


class TestParseExiftool:
    """Tests for parse-exiftool.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-exiftool")

    def test_json_input(self, parser):
        raw = '[{"Comment": "flag{hidden_in_metadata}", "FileSize": "1234"}]'
        result = parser.parse_exiftool(raw, "image.png")

        assert result["has_flag"] is True
        assert result["flags"]
        assert result["interesting_fields"]

    def test_text_input(self, parser):
        raw = "File Size : 1234\nComment : secret message"
        result = parser.parse_exiftool(raw)

        assert result["field_count"] == 2
        assert any(f["field"] == "Comment" for f in result["interesting_fields"])

    def test_gps_detection(self, parser):
        raw = '[{"GPSLatitude": "40.7128", "GPSLongitude": "-74.0060"}]'
        result = parser.parse_exiftool(raw)

        assert result["gps_data"]
        assert any("GPS" in s for s in result["suggestions"])


class TestParseXortool:
    """Tests for parse-xortool.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-xortool")

    def test_key_length_detection(self, parser):
        raw = """   2:   5.2%
   4:  12.3%
   8:  42.1%
The most probable key length is: 8"""
        result = parser.parse_xortool(raw, "encrypted.bin")

        assert result["best_key_length"] == 8
        assert len(result["key_lengths"]) == 3
        assert result["key_lengths"][0]["length"] == 8  # sorted by probability

    def test_key_found(self, parser):
        raw = "key: 'secretkey'"
        result = parser.parse_xortool(raw)

        assert result["key_found"] == "secretkey"
        assert any("key found" in s.lower() for s in result["suggestions"])


class TestParseZsteg:
    """Tests for parse-zsteg.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-zsteg")

    def test_text_finding(self, parser):
        raw = 'b1,r,lsb,xy .. text: "hidden secret message"'
        result = parser.parse_zsteg(raw, "image.png")

        assert result["finding_count"] == 1
        assert result["text_findings"]
        assert result["findings"][0]["channel"] == "b1,r,lsb,xy"

    def test_flag_in_content(self, parser):
        raw = 'b1,rgb,lsb,xy .. text: "flag{stego_solved}"'
        result = parser.parse_zsteg(raw)

        assert result["has_flag"] is True
        assert "flag{stego_solved}" in result["flags"]

    def test_file_finding(self, parser):
        raw = "b1,rgb,lsb,xy .. file: PNG image data"
        result = parser.parse_zsteg(raw)

        assert result["file_findings"]
        assert any("Extract" in s for s in result["suggestions"])


class TestParseSteghide:
    """Tests for parse-steghide.py."""

    @pytest.fixture
    def parser(self):
        return _load_parser("parse-steghide")

    def test_extraction_success(self, parser):
        raw = """embedded file "secret.txt":
  size: 42 bytes
SUCCESS with password: 'hidden'
wrote extracted data to "secret.txt"."""
        result = parser.parse_steghide(raw, "image.jpg")

        assert result["has_embedded_data"] is True
        assert result["password_used"] == "hidden"
        assert result["extracted_file"] == "secret.txt"

    def test_no_data(self, parser):
        raw = "could not extract any data"
        result = parser.parse_steghide(raw)

        assert result["has_embedded_data"] is False
        assert any("No steghide data" in s or "failed" in s.lower() for s in result["suggestions"])
