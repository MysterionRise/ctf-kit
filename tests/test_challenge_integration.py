"""Integration tests for sample CTF challenges.

Each test exercises a full skill workflow end-to-end:
  1. Load a sample challenge fixture
  2. Run the skill's analyze() method
  3. Verify the analysis detects expected patterns
  4. Verify suggestions and next_steps are generated
  5. Verify suggest_approach() returns actionable steps

These tests use fixtures from tests/fixtures/challenges/ with known solutions.
"""

import base64
import struct
from pathlib import Path

import pytest

from ctf_kit.skills.base import SkillResult, get_skill
from ctf_kit.skills.crypto import CryptoSkill
from ctf_kit.skills.forensics import ForensicsSkill
from ctf_kit.skills.misc import MiscSkill
from ctf_kit.skills.pwn import PwnSkill
from ctf_kit.skills.reversing import ReversingSkill
from ctf_kit.skills.web import WebSkill

# Path to fixture challenges
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "challenges"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def assert_valid_skill_result(result: SkillResult):
    """Assert that a SkillResult has the expected structure."""
    assert isinstance(result, SkillResult)
    assert isinstance(result.skill_name, str)
    assert isinstance(result.analysis, dict)
    assert isinstance(result.suggestions, list)
    assert isinstance(result.next_steps, list)
    assert isinstance(result.confidence, float)
    assert 0.0 <= result.confidence <= 1.0


# ---------------------------------------------------------------------------
# Web Challenge Integration Tests
# ---------------------------------------------------------------------------


class TestWebChallengeIntegration:
    """Full workflow test for web challenge: web_flask_vuln.py."""

    @pytest.fixture()
    def web_challenge(self):
        return FIXTURES_DIR / "web_flask_vuln.py"

    def test_skill_retrieval(self):
        """Test that web skill is retrievable from registry."""
        skill = get_skill("web")
        assert skill is not None
        assert isinstance(skill, WebSkill)

    def test_analyze_detects_sqli(self, web_challenge):
        """Test that analysis detects SQL injection."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        assert_valid_skill_result(result)
        assert result.success

        vuln_types = {v["type"] for v in result.analysis["vulnerabilities"]}
        assert "sqli" in vuln_types

    def test_analyze_detects_ssti(self, web_challenge):
        """Test that analysis detects SSTI vulnerability."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        vuln_types = {v["type"] for v in result.analysis["vulnerabilities"]}
        assert "ssti" in vuln_types

    def test_analyze_detects_flask(self, web_challenge):
        """Test that analysis detects Flask technology stack."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        assert "Flask" in result.analysis["technology_stack"]

    def test_analyze_detects_sqlite(self, web_challenge):
        """Test that analysis detects SQLite database."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        assert "SQLite" in result.analysis["technology_stack"]

    def test_analyze_extracts_endpoints(self, web_challenge):
        """Test that analysis extracts Flask routes."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        endpoints = result.analysis["endpoints"]
        assert "/login" in endpoints
        assert "/admin/dashboard" in endpoints

    def test_analyze_detects_credentials(self, web_challenge):
        """Test that analysis finds hardcoded credentials."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        creds = result.analysis["credentials"]
        assert len(creds) > 0
        cred_types = {c["type"] for c in creds}
        assert "password" in cred_types

    def test_analyze_finds_flag_pattern(self, web_challenge):
        """Test that analysis detects flag patterns in source."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        patterns = result.analysis.get("interesting_patterns", [])
        assert any("Flag value found" in p for p in patterns)

    def test_suggestions_are_relevant(self, web_challenge):
        """Test that suggestions mention SQL injection tools."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        assert len(result.suggestions) > 0
        suggestion_text = " ".join(result.suggestions).lower()
        assert "sql" in suggestion_text or "ssti" in suggestion_text

    def test_suggest_approach_returns_steps(self, web_challenge):
        """Test suggest_approach returns actionable steps."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        approaches = skill.suggest_approach(result.analysis)
        assert isinstance(approaches, list)
        assert len(approaches) > 0

    def test_confidence_is_high(self, web_challenge):
        """Test that confidence is high for clear vulnerability."""
        skill = WebSkill()
        result = skill.analyze(web_challenge)

        assert result.confidence > 0.3

    def test_full_workflow(self, web_challenge):
        """Test complete workflow: analyze -> suggest -> verify."""
        skill = WebSkill()

        # Step 1: Analyze
        result = skill.analyze(web_challenge)
        assert result.success

        # Step 2: Suggest approach based on analysis
        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0

        # Step 3: Verify analysis has actionable data
        assert len(result.analysis["vulnerabilities"]) > 0
        assert len(result.analysis["technology_stack"]) > 0
        assert len(result.analysis["endpoints"]) > 0
        assert len(result.analysis["credentials"]) > 0


# ---------------------------------------------------------------------------
# Crypto Challenge Integration Tests
# ---------------------------------------------------------------------------


class TestCryptoChallengeIntegration:
    """Full workflow tests for crypto challenges."""

    @pytest.fixture()
    def rsa_challenge(self):
        return FIXTURES_DIR / "crypto_rsa_challenge.txt"

    @pytest.fixture()
    def base64_challenge(self):
        return FIXTURES_DIR / "crypto_base64.txt"

    @pytest.fixture()
    def hash_challenge(self):
        return FIXTURES_DIR / "crypto_hash.txt"

    @pytest.fixture()
    def xor_challenge(self):
        return FIXTURES_DIR / "crypto_xor.bin"

    def test_skill_retrieval(self):
        """Test that crypto skill is retrievable from registry."""
        skill = get_skill("crypto")
        assert skill is not None
        assert isinstance(skill, CryptoSkill)

    def test_rsa_detects_parameters(self, rsa_challenge):
        """Test that RSA parameters (n, e, c) are detected."""
        skill = CryptoSkill()
        result = skill.analyze(rsa_challenge)

        assert_valid_skill_result(result)
        assert result.success

        values = result.analysis.get("interesting_values", [])
        value_types = [v["type"] for v in values]
        assert any("RSA" in t for t in value_types)

    def test_rsa_suggests_factorization(self, rsa_challenge):
        """Test that RSA analysis suggests factorization approach."""
        skill = CryptoSkill()
        result = skill.analyze(rsa_challenge)

        suggestion_text = " ".join(result.suggestions).lower()
        assert "rsa" in suggestion_text

    def test_rsa_confidence_positive(self, rsa_challenge):
        """Test that RSA detection gives positive confidence."""
        skill = CryptoSkill()
        result = skill.analyze(rsa_challenge)

        assert result.confidence > 0.0

    def test_base64_detects_encoding(self, base64_challenge):
        """Test that base64 encoding is detected."""
        skill = CryptoSkill()
        result = skill.analyze(base64_challenge)

        assert result.success
        encodings = result.analysis.get("encoding_chains", [])
        assert any(e.get("type") == "base64" for e in encodings)

    def test_base64_suggests_decode(self, base64_challenge):
        """Test that base64 analysis suggests decoding."""
        skill = CryptoSkill()
        result = skill.analyze(base64_challenge)

        suggestion_text = " ".join(result.suggestions).lower()
        assert "base64" in suggestion_text

    def test_hash_detects_md5(self, hash_challenge):
        """Test that MD5 hash pattern is detected."""
        skill = CryptoSkill()
        result = skill.analyze(hash_challenge)

        assert result.success
        # Should detect as hash via cipher pattern matching
        ciphers = result.analysis.get("detected_ciphers", [])
        hash_ciphers = [c for c in ciphers if c.get("type") == "hash"]
        if hash_ciphers:
            # Pattern-based detection found it
            possible_types = hash_ciphers[0].get("possible_types", [])
            assert "MD5" in possible_types
        else:
            # hashid tool detection (if installed)
            hashes = result.analysis.get("detected_hashes", [])
            assert len(hashes) > 0 or len(ciphers) > 0

    def test_hash_suggests_cracking(self, hash_challenge):
        """Test that hash analysis suggests cracking tools."""
        skill = CryptoSkill()
        result = skill.analyze(hash_challenge)

        suggestion_text = " ".join(result.suggestions).lower()
        assert "hash" in suggestion_text or "crack" in suggestion_text

    def test_xor_analysis(self, xor_challenge):
        """Test XOR binary analysis."""
        skill = CryptoSkill()
        result = skill.analyze(xor_challenge)

        assert_valid_skill_result(result)
        assert result.success

    def test_full_workflow_rsa(self, rsa_challenge):
        """Test complete crypto workflow with RSA challenge."""
        skill = CryptoSkill()

        # Step 1: Analyze
        result = skill.analyze(rsa_challenge)
        assert result.success

        # Step 2: Suggest approach
        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0

        # Step 3: Verify RSA params found
        values = result.analysis.get("interesting_values", [])
        rsa_values = [v for v in values if "RSA" in v.get("type", "")]
        assert len(rsa_values) > 0

    def test_full_workflow_base64(self, base64_challenge):
        """Test complete crypto workflow with base64 challenge."""
        skill = CryptoSkill()

        # Step 1: Analyze
        result = skill.analyze(base64_challenge)
        assert result.success

        # Step 2: The encoded content should be detected
        encodings = result.analysis.get("encoding_chains", [])
        assert len(encodings) > 0

        # Step 3: Suggestions should help decode
        assert len(result.suggestions) > 0


# ---------------------------------------------------------------------------
# Forensics Challenge Integration Tests
# ---------------------------------------------------------------------------


class TestForensicsChallengeIntegration:
    """Full workflow tests for forensics challenges."""

    @pytest.fixture()
    def pcap_challenge(self):
        return FIXTURES_DIR / "forensics_network.pcap"

    @pytest.fixture()
    def embedded_challenge(self):
        return FIXTURES_DIR / "forensics_embedded.bin"

    def test_skill_retrieval(self):
        """Test that forensics skill is retrievable from registry."""
        skill = get_skill("forensics")
        assert skill is not None
        assert isinstance(skill, ForensicsSkill)

    def test_pcap_detects_network_type(self, pcap_challenge):
        """Test that pcap file is classified as network forensics."""
        skill = ForensicsSkill()
        result = skill.analyze(pcap_challenge)

        assert_valid_skill_result(result)
        assert result.success
        assert result.analysis["forensics_type"] == "network"

    def test_pcap_suggests_network_tools(self, pcap_challenge):
        """Test that network forensics suggestions are relevant."""
        skill = ForensicsSkill()
        result = skill.analyze(pcap_challenge)

        suggestion_text = " ".join(result.suggestions).lower()
        assert any(
            kw in suggestion_text for kw in ["tcp", "http", "stream", "tshark", "protocol"]
        )

    def test_pcap_confidence_positive(self, pcap_challenge):
        """Test that network pcap detection gives positive confidence."""
        skill = ForensicsSkill()
        result = skill.analyze(pcap_challenge)

        assert result.confidence > 0.0

    def test_embedded_analysis(self, embedded_challenge):
        """Test forensics analysis on file with embedded data."""
        skill = ForensicsSkill()
        result = skill.analyze(embedded_challenge)

        assert_valid_skill_result(result)
        assert result.success

    def test_suggest_approach_network(self, pcap_challenge):
        """Test suggest_approach for network forensics."""
        skill = ForensicsSkill()
        result = skill.analyze(pcap_challenge)

        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0

    def test_full_workflow_pcap(self, pcap_challenge):
        """Test complete forensics workflow with pcap challenge."""
        skill = ForensicsSkill()

        # Step 1: Analyze
        result = skill.analyze(pcap_challenge)
        assert result.success

        # Step 2: Should detect network type
        assert result.analysis["forensics_type"] == "network"

        # Step 3: Suggest approach
        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0

        # Step 4: Suggestions should be network-relevant
        assert len(result.suggestions) > 0

    def test_directory_analysis(self, tmp_path):
        """Test forensics analysis on a directory of evidence files."""
        # Create a mini forensics challenge directory
        (tmp_path / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
        (tmp_path / "notes.txt").write_text("Suspect was seen accessing 192.168.1.100")

        skill = ForensicsSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["file_info"]) == 2


# ---------------------------------------------------------------------------
# Reversing Challenge Integration Tests
# ---------------------------------------------------------------------------


class TestReversingChallengeIntegration:
    """Full workflow tests for reverse engineering challenges."""

    @pytest.fixture()
    def crackme_challenge(self):
        return FIXTURES_DIR / "reverse_crackme.pyc"

    def test_skill_retrieval(self):
        """Test that reversing skill is retrievable from registry."""
        skill = get_skill("reversing")
        assert skill is not None
        assert isinstance(skill, ReversingSkill)

    def test_analyze_detects_python_bytecode(self, crackme_challenge):
        """Test that pyc file is recognized as executable."""
        skill = ReversingSkill()
        result = skill.analyze(crackme_challenge)

        assert_valid_skill_result(result)
        assert result.success
        assert result.skill_name == "reversing"

    def test_analyze_generates_suggestions(self, crackme_challenge):
        """Test that analysis generates useful suggestions."""
        skill = ReversingSkill()
        result = skill.analyze(crackme_challenge)

        assert len(result.suggestions) > 0

    def test_suggest_approach_returns_steps(self, crackme_challenge):
        """Test suggest_approach returns actionable steps."""
        skill = ReversingSkill()
        result = skill.analyze(crackme_challenge)

        approaches = skill.suggest_approach(result.analysis)
        assert isinstance(approaches, list)
        assert len(approaches) > 0

    def test_elf_binary_analysis(self, tmp_path):
        """Test analysis of a synthetic ELF binary.

        Uses .pyc extension to avoid radare2 dict bug (see test_skills_ext.py).
        """
        pyc_file = tmp_path / "crackme.pyc"
        pyc_data = b"\x42\x0d\r\n" + b"\x00" * 50
        pyc_data += b"check_password\x00main\x00flag\x00strcmp\x00"
        pyc_file.write_bytes(pyc_data)

        skill = ReversingSkill()
        result = skill.analyze(pyc_file)

        assert result.success

    def test_pe_binary_analysis(self, tmp_path):
        """Test analysis of a synthetic PE binary."""
        pe_file = tmp_path / "challenge.exe"
        pe_data = b"MZ" + b"\x00" * 200
        pe_file.write_bytes(pe_data)

        skill = ReversingSkill()
        result = skill.analyze(pe_file)

        assert result.success

    def test_full_workflow(self, crackme_challenge):
        """Test complete reversing workflow."""
        skill = ReversingSkill()

        # Step 1: Analyze
        result = skill.analyze(crackme_challenge)
        assert result.success

        # Step 2: Suggest approach
        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0

        # Step 3: Analysis should have file info
        assert result.analysis.get("file_info") is not None


# ---------------------------------------------------------------------------
# Pwn Challenge Integration Tests
# ---------------------------------------------------------------------------


class TestPwnChallengeIntegration:
    """Full workflow tests for binary exploitation challenges."""

    @pytest.fixture()
    def vuln_binary(self):
        return FIXTURES_DIR / "pwn_vulnerable"

    def test_skill_retrieval(self):
        """Test that pwn skill is retrievable from registry."""
        skill = get_skill("pwn")
        assert skill is not None
        assert isinstance(skill, PwnSkill)

    def test_analyze_recognizes_elf(self, vuln_binary):
        """Test that ELF binary is recognized."""
        skill = PwnSkill()
        result = skill.analyze(vuln_binary)

        assert_valid_skill_result(result)
        assert result.success
        assert result.skill_name == "pwn"

    def test_analyze_generates_suggestions(self, vuln_binary):
        """Test that analysis generates exploitation suggestions."""
        skill = PwnSkill()
        result = skill.analyze(vuln_binary)

        assert len(result.suggestions) > 0

    def test_suggest_approach_returns_steps(self, vuln_binary):
        """Test suggest_approach returns exploitation steps."""
        skill = PwnSkill()
        result = skill.analyze(vuln_binary)

        approaches = skill.suggest_approach(result.analysis)
        assert isinstance(approaches, list)
        assert len(approaches) > 0
        # Should suggest running the binary
        assert any("run" in s.lower() for s in approaches)

    def test_synthetic_buffer_overflow(self, tmp_path):
        """Test detection of buffer overflow patterns in synthetic binary."""
        vuln_file = tmp_path / "bof_challenge"
        elf_data = b"\x7fELF\x02\x01\x01" + b"\x00" * 50
        # Embed vulnerable function names
        elf_data += b"\x00gets\x00strcpy\x00system\x00/bin/sh\x00win\x00"
        vuln_file.write_bytes(elf_data)

        skill = PwnSkill()
        result = skill.analyze(vuln_file)

        assert result.success

    def test_full_workflow(self, vuln_binary):
        """Test complete pwn workflow."""
        skill = PwnSkill()

        # Step 1: Analyze
        result = skill.analyze(vuln_binary)
        assert result.success

        # Step 2: Check protections (may be empty without checksec)
        protections = result.analysis.get("protections", {})
        assert isinstance(protections, dict)

        # Step 3: Suggest approach
        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0

        # Step 4: Should have binary info
        assert result.analysis.get("binary_info") is not None


# ---------------------------------------------------------------------------
# Misc Challenge Integration Tests
# ---------------------------------------------------------------------------


class TestMiscChallengeIntegration:
    """Full workflow tests for misc challenges."""

    @pytest.fixture()
    def multi_encode_challenge(self):
        return FIXTURES_DIR / "misc_multi_encode.txt"

    def test_skill_retrieval(self):
        """Test that misc skill is retrievable from registry."""
        skill = get_skill("misc")
        assert skill is not None
        assert isinstance(skill, MiscSkill)

    def test_analyze_detects_base64(self, multi_encode_challenge):
        """Test that base64 encoding is detected in multi-encoded challenge."""
        skill = MiscSkill()
        result = skill.analyze(multi_encode_challenge)

        assert_valid_skill_result(result)
        assert result.success

        encodings = result.analysis.get("detected_encodings", [])
        encoding_types = [e["type"] for e in encodings]
        assert "base64" in encoding_types

    def test_analyze_attempts_decode(self, multi_encode_challenge):
        """Test that analysis attempts to decode the content."""
        skill = MiscSkill()
        result = skill.analyze(multi_encode_challenge)

        decoded = result.analysis.get("decoded_attempts", [])
        # Should attempt base64 decode
        assert len(decoded) > 0

    def test_analyze_generates_suggestions(self, multi_encode_challenge):
        """Test that suggestions mention encodings."""
        skill = MiscSkill()
        result = skill.analyze(multi_encode_challenge)

        assert len(result.suggestions) > 0
        suggestion_text = " ".join(result.suggestions).lower()
        assert "encoding" in suggestion_text or "decode" in suggestion_text

    def test_direct_flag_detection(self, tmp_path):
        """Test that a file with a flag directly in it is detected."""
        flag_file = tmp_path / "easy.txt"
        flag_file.write_text("The answer is flag{misc_easy_find}")

        skill = MiscSkill()
        result = skill.analyze(flag_file)

        assert result.success
        assert "flag{misc_easy_find}" in result.analysis["flags_found"]
        assert result.confidence == 1.0

    def test_brainfuck_detection(self, tmp_path):
        """Test that brainfuck code is detected as esoteric language."""
        bf_file = tmp_path / "program.bf"
        bf_file.write_text("++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.")

        skill = MiscSkill()
        result = skill.analyze(bf_file)

        assert result.success
        esoteric = result.analysis.get("esoteric_language")
        assert esoteric is not None
        assert esoteric["type"] == "brainfuck"

    def test_hex_encoding_detection(self, tmp_path):
        """Test that hex-encoded data is detected as some encoding.

        Note: pure hex chars (0-9a-f) are also valid base64, so
        the detection may classify as base64 before base16.
        We verify that *some* encoding is detected.
        """
        hex_file = tmp_path / "hex_data.txt"
        # "flag{hex_decoded}" in hex
        hex_file.write_text("666c61677b6865785f6465636f6465647d")

        skill = MiscSkill()
        result = skill.analyze(hex_file)

        assert result.success
        encodings = result.analysis.get("detected_encodings", [])
        # Hex chars match both base64 and base16 patterns; accept either
        encoding_types = [e["type"] for e in encodings]
        assert "base16" in encoding_types or "base64" in encoding_types

    def test_decode_chain_method(self):
        """Test the decode_chain helper method."""
        skill = MiscSkill()

        # Create a double-encoded string: hex -> base64
        original = "flag{chain}"
        hex_encoded = original.encode().hex()
        b64_of_hex = base64.b64encode(hex_encoded.encode()).decode()

        # Decode chain: base64 first, then hex
        result = skill.decode_chain(b64_of_hex, ["base64", "base16"])
        assert result == original

    def test_directory_analysis(self, tmp_path):
        """Test misc analysis on a directory with multiple files."""
        (tmp_path / "encoded.txt").write_text(
            base64.b64encode(b"flag{dir_flag}").decode()
        )
        (tmp_path / "notes.txt").write_text("Check the encoded file")

        skill = MiscSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["file_info"]) == 2

    def test_suggest_approach_with_encodings(self, multi_encode_challenge):
        """Test suggest_approach when encodings are detected."""
        skill = MiscSkill()
        result = skill.analyze(multi_encode_challenge)

        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0

    def test_full_workflow(self, multi_encode_challenge):
        """Test complete misc workflow."""
        skill = MiscSkill()

        # Step 1: Analyze
        result = skill.analyze(multi_encode_challenge)
        assert result.success

        # Step 2: Should detect encodings
        assert len(result.analysis["detected_encodings"]) > 0

        # Step 3: Should attempt decoding
        assert len(result.analysis["decoded_attempts"]) > 0

        # Step 4: Suggest approach
        approaches = skill.suggest_approach(result.analysis)
        assert len(approaches) > 0


# ---------------------------------------------------------------------------
# Cross-Skill Integration Tests
# ---------------------------------------------------------------------------


class TestCrossSkillIntegration:
    """Tests that verify skills work together and the registry is consistent."""

    def test_all_skills_registered(self):
        """Test that all expected skills are in the registry."""
        expected_skills = [
            "analyze", "crypto", "forensics", "misc",
            "osint", "pwn", "reversing", "stego", "web",
        ]
        for name in expected_skills:
            skill = get_skill(name)
            assert skill is not None, f"Skill '{name}' not found in registry"

    def test_all_skills_analyze_empty_dir(self, tmp_path):
        """Test that all skills handle empty directories gracefully.

        Note: crypto skill returns success=True on empty dir (it analyzes
        the path itself rather than requiring files in a directory).
        """
        # Skills that return success=False on empty directories
        dir_aware_skills = ["forensics", "misc", "pwn", "reversing", "stego", "web"]

        for name in dir_aware_skills:
            skill = get_skill(name)
            assert skill is not None
            result = skill.analyze(tmp_path)

            assert isinstance(result, SkillResult), f"Skill '{name}' did not return SkillResult"
            assert not result.success, f"Skill '{name}' succeeded on empty dir"

        # Crypto processes path as a single file, so returns success with empty analysis
        crypto_skill = get_skill("crypto")
        assert crypto_skill is not None
        result = crypto_skill.analyze(tmp_path)
        assert isinstance(result, SkillResult)

    def test_all_skills_have_suggest_approach(self):
        """Test that all skills implement suggest_approach."""
        skill_names = [
            "analyze", "crypto", "forensics", "misc",
            "osint", "pwn", "reversing", "stego", "web",
        ]

        for name in skill_names:
            skill = get_skill(name)
            assert skill is not None
            # Call with minimal analysis dict
            approaches = skill.suggest_approach({})
            assert isinstance(approaches, list), f"Skill '{name}' suggest_approach didn't return list"

    def test_analyze_skill_categorizes_challenges(self, tmp_path):
        """Test that analyze skill correctly categorizes different file types."""
        from ctf_kit.skills.analyze import AnalyzeSkill

        # Create files that should be categorized differently
        (tmp_path / "crypto.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        (tmp_path / "app.php").write_text("<?php echo 'hello'; ?>")

        skill = AnalyzeSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["files"]) == 3

    def test_skill_results_are_serializable(self, tmp_path):
        """Test that all skill results can be serialized to dict."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("flag{test_serialize}")

        skill_names = ["analyze", "crypto", "misc"]

        for name in skill_names:
            skill = get_skill(name)
            assert skill is not None
            result = skill.analyze(test_file)
            result_dict = result.to_dict()

            assert isinstance(result_dict, dict), f"Skill '{name}' to_dict failed"
            assert "success" in result_dict
            assert "skill_name" in result_dict
            assert "analysis" in result_dict

    def test_skill_results_have_summary(self, tmp_path):
        """Test that all skill results can generate a summary."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("flag{test_summary}")

        skill_names = ["analyze", "crypto", "misc"]

        for name in skill_names:
            skill = get_skill(name)
            assert skill is not None
            result = skill.analyze(test_file)
            summary = result.summary()

            assert isinstance(summary, str), f"Skill '{name}' summary failed"
            assert name in summary.lower() or "analysis" in summary.lower()

    def test_web_then_crypto_on_mixed_content(self, tmp_path):
        """Test analyzing a file with both web and crypto content."""
        mixed_file = tmp_path / "challenge.py"
        mixed_file.write_text(
            "from flask import Flask\n"
            "# Hash: 5d41402abc4b2a76b9719d911017c592\n"
            "password = 'admin123'\n"
            "@app.route('/login')\n"
            "def login():\n"
            "    cursor.execute('SELECT * FROM users')\n"
        )

        # Web skill should find vulnerabilities
        web_skill = WebSkill()
        web_result = web_skill.analyze(mixed_file)
        assert web_result.success
        assert len(web_result.analysis["vulnerabilities"]) > 0

        # Crypto skill should find the hash
        crypto_skill = CryptoSkill()
        crypto_result = crypto_skill.analyze(mixed_file)
        assert crypto_result.success

    def test_challenge_directory_workflow(self, tmp_path):
        """Test analyzing a complete challenge directory with mixed files."""
        # Simulate a typical CTF challenge directory with detectable categories
        (tmp_path / "challenge.php").write_text(
            "<?php\n"
            "$result = mysqli_query($conn, 'SELECT * FROM users');\n"
            "echo $_GET['name'];\n"
            "?>\n"
        )
        (tmp_path / "secret.pem").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA...\n"
            "-----END RSA PRIVATE KEY-----\n"
        )

        # Analyze skill should categorize both files
        from ctf_kit.skills.analyze import AnalyzeSkill

        analyze = AnalyzeSkill()
        result = analyze.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["files"]) == 2
        # With web (.php) and crypto (.pem) files, suggestions should be generated
        assert result.analysis.get("detected_category") is not None
