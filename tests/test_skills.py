"""Tests for CTF Kit skills."""

from ctf_kit.skills.analyze import AnalyzeSkill
from ctf_kit.skills.base import (
    SkillResult,
    get_all_skills,
    get_skill,
)
from ctf_kit.skills.crypto import CryptoSkill


class TestSkillResult:
    """Tests for SkillResult dataclass."""

    def test_skill_result_creation(self):
        """Test creating a skill result."""
        result = SkillResult(
            success=True,
            skill_name="test",
            analysis={"key": "value"},
            suggestions=["suggestion1"],
            next_steps=["step1"],
            confidence=0.8,
        )

        assert result.success
        assert result.skill_name == "test"
        assert result.confidence == 0.8

    def test_skill_result_str(self):
        """Test string representation."""
        result = SkillResult(
            success=True,
            skill_name="test",
            analysis={},
            suggestions=["s1", "s2"],
        )

        str_repr = str(result)
        assert "test" in str_repr
        assert "2 suggestions" in str_repr

    def test_skill_result_to_dict(self):
        """Test conversion to dictionary."""
        result = SkillResult(
            success=True,
            skill_name="test",
            analysis={"key": "value"},
            suggestions=["s1"],
            next_steps=["n1"],
            confidence=0.5,
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["skill_name"] == "test"
        assert d["confidence"] == 0.5

    def test_skill_result_summary(self):
        """Test summary generation."""
        result = SkillResult(
            success=True,
            skill_name="test",
            analysis={"finding": "value"},
            suggestions=["try this"],
            next_steps=["do that"],
        )

        summary = result.summary()

        assert "## test Analysis" in summary
        assert "finding" in summary
        assert "try this" in summary
        assert "do that" in summary


class TestAnalyzeSkill:
    """Tests for AnalyzeSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = AnalyzeSkill()
        assert skill.name == "analyze"
        assert "file" in skill.tool_names
        assert "strings" in skill.tool_names

    def test_analyze_file(self, tmp_path):
        """Test analyzing a single file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello World flag{test}")

        skill = AnalyzeSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert result.skill_name == "analyze"
        assert "files" in result.analysis

    def test_analyze_directory(self, tmp_path):
        """Test analyzing a directory."""
        (tmp_path / "file1.txt").write_text("test1")
        (tmp_path / "file2.txt").write_text("test2")

        skill = AnalyzeSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["files"]) == 2

    def test_analyze_empty_directory(self, tmp_path):
        """Test analyzing empty directory."""
        skill = AnalyzeSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No files found" in result.suggestions[0]

    def test_analyze_generates_suggestions(self, tmp_path):
        """Test that analysis generates suggestions."""
        test_file = tmp_path / "test.png"
        # PNG magic bytes
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        skill = AnalyzeSkill()
        result = skill.analyze(test_file)

        assert result.suggestions  # Should have some suggestions

    def test_suggest_approach(self):
        """Test suggest_approach method."""
        skill = AnalyzeSkill()
        analysis = {"detected_category": "crypto"}

        approaches = skill.suggest_approach(analysis)

        assert isinstance(approaches, list)

    def test_available_tools(self):
        """Test available_tools property."""
        skill = AnalyzeSkill()
        available = skill.available_tools

        assert isinstance(available, list)

    def test_missing_tools(self):
        """Test missing_tools property."""
        skill = AnalyzeSkill()
        missing = skill.missing_tools

        assert isinstance(missing, list)


class TestCryptoSkill:
    """Tests for CryptoSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = CryptoSkill()
        assert skill.name == "crypto"
        assert skill.category == "crypto"
        assert "hashid" in skill.tool_names
        assert "xortool" in skill.tool_names

    def test_analyze_hash_file(self, tmp_path):
        """Test analyzing file with hash."""
        test_file = tmp_path / "hash.txt"
        # MD5 hash
        test_file.write_text("5d41402abc4b2a76b9719d911017c592")

        skill = CryptoSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert result.skill_name == "crypto"

    def test_analyze_base64_file(self, tmp_path):
        """Test analyzing file with base64."""
        test_file = tmp_path / "encoded.txt"
        # "Hello World! This is a longer string for testing base64 detection"
        test_file.write_text(
            "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nZXIgc3RyaW5nIGZvciB0ZXN0aW5nIGJhc2U2NCBkZXRlY3Rpb24="
        )

        skill = CryptoSkill()
        result = skill.analyze(test_file)

        assert result.success
        # Should detect base64 encoding
        assert any(
            enc.get("type") == "base64" for enc in result.analysis.get("encoding_chains", [])
        )

    def test_analyze_rsa_params(self, tmp_path):
        """Test detecting RSA parameters."""
        test_file = tmp_path / "rsa.txt"
        test_file.write_text("n = 123456789\ne = 65537\nc = 98765432")

        skill = CryptoSkill()
        result = skill.analyze(test_file)

        assert result.success
        # Should find RSA values
        values = result.analysis.get("interesting_values", [])
        assert any("RSA" in v.get("type", "") for v in values)

    def test_analyze_text_patterns(self):
        """Test _analyze_text method."""
        skill = CryptoSkill()

        content = "5d41402abc4b2a76b9719d911017c592\nSGVsbG8gV29ybGQh"
        result = skill._analyze_text(content)

        assert "ciphers" in result
        assert "encodings" in result

    def test_find_hash_candidates(self):
        """Test finding hash candidates in text."""
        skill = CryptoSkill()

        content = "The hash is 5d41402abc4b2a76b9719d911017c592 here"
        candidates = skill._find_hash_candidates(content)

        assert len(candidates) == 1
        assert "5d41402abc4b2a76b9719d911017c592" in candidates

    def test_looks_like_xor(self):
        """Test XOR detection heuristic."""
        skill = CryptoSkill()

        # Random bytes should look like XOR
        random_data = bytes(range(256)) * 4
        assert skill._looks_like_xor(random_data)

        # Short data should not
        assert not skill._looks_like_xor(b"short")

    def test_suggest_approach(self):
        """Test suggest_approach method."""
        skill = CryptoSkill()
        analysis = {"detected_hashes": [{"value": "test", "types": ["MD5"]}]}

        approaches = skill.suggest_approach(analysis)

        assert isinstance(approaches, list)
        assert len(approaches) > 0

    def test_identify_hash(self):
        """Test identify_hash helper method."""
        skill = CryptoSkill()

        # Without hashid installed, should return empty
        result = skill.identify_hash("5d41402abc4b2a76b9719d911017c592")

        assert "hash" in result
        assert "types" in result


class TestSkillRegistry:
    """Tests for skill registry functions."""

    def test_get_skill_analyze(self):
        """Test getting analyze skill."""
        skill = get_skill("analyze")
        assert skill is not None
        assert isinstance(skill, AnalyzeSkill)

    def test_get_skill_crypto(self):
        """Test getting crypto skill."""
        skill = get_skill("crypto")
        assert skill is not None
        assert isinstance(skill, CryptoSkill)

    def test_get_skill_nonexistent(self):
        """Test getting nonexistent skill."""
        skill = get_skill("nonexistent_skill")
        assert skill is None

    def test_get_all_skills(self):
        """Test getting all registered skills."""
        skills = get_all_skills()

        assert "analyze" in skills
        assert "crypto" in skills
        assert isinstance(skills["analyze"], AnalyzeSkill)
        assert isinstance(skills["crypto"], CryptoSkill)
