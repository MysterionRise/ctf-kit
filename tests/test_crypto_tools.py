"""Tests for crypto tool integrations."""

from unittest.mock import patch

from ctf_kit.integrations.crypto.hashid import HashIDTool
from ctf_kit.integrations.crypto.xortool import XortoolTool


class TestHashIDTool:
    """Tests for HashIDTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = HashIDTool()
        assert tool.name == "hashid"
        assert tool.description == "Identify hash types from input"
        assert "hashid" in tool.binary_names

    def test_install_commands(self):
        """Test install commands are set."""
        tool = HashIDTool()
        assert "darwin" in tool.install_commands
        assert "pip install hashid" in tool.install_commands["darwin"]

    @patch.object(HashIDTool, "_run_with_result")
    def test_run_basic(self, mock_run):
        """Test basic run with hash value."""
        from ctf_kit.integrations.base import ToolResult

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="hashid",
            command="hashid 5d41402abc4b2a76b9719d911017c592",
            stdout="[+] MD5\n[+] MD4",
            stderr="",
            parsed_data={"hash_types": [{"type": "MD5"}, {"type": "MD4"}]},
        )

        tool = HashIDTool()
        result = tool.run("5d41402abc4b2a76b9719d911017c592")

        assert result.success
        mock_run.assert_called_once()

    @patch.object(HashIDTool, "_run_with_result")
    def test_run_with_options(self, mock_run):
        """Test run with extended and hashcat options."""
        from ctf_kit.integrations.base import ToolResult

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="hashid",
            command="hashid -e -m hash",
            stdout="",
            stderr="",
        )

        tool = HashIDTool()
        tool.run("hash", extended=True, hashcat_mode=True)

        call_args = mock_run.call_args[0][0]
        assert "-e" in call_args
        assert "-m" in call_args

    def test_parse_output_md5(self):
        """Test parsing MD5 hash output."""
        tool = HashIDTool()
        stdout = "[+] MD5\n[+] MD4\n[+] Double MD5"
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "hash_types" in result
        assert len(result["hash_types"]) >= 1

    def test_parse_output_with_hashcat_mode(self):
        """Test parsing output with Hashcat mode."""
        tool = HashIDTool()
        stdout = "[+] MD5 [Hashcat Mode: 0]\n[+] MD4 [Hashcat Mode: 900]"
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "hash_types" in result
        # Should extract hashcat mode if present in expected format

    def test_get_suggestions_md5(self):
        """Test suggestions for MD5 hash."""
        tool = HashIDTool()
        hash_types = [{"type": "MD5"}]

        suggestions = tool._get_suggestions(hash_types)

        assert any("hashcat" in s.lower() or "md5" in s.lower() for s in suggestions)

    def test_get_suggestions_bcrypt(self):
        """Test suggestions for bcrypt hash."""
        tool = HashIDTool()
        hash_types = [{"type": "bcrypt"}]

        suggestions = tool._get_suggestions(hash_types)

        assert any("bcrypt" in s.lower() for s in suggestions)


class TestXortoolTool:
    """Tests for XortoolTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = XortoolTool()
        assert tool.name == "xortool"
        assert "xortool" in tool.binary_names

    def test_install_commands(self):
        """Test install commands are set."""
        tool = XortoolTool()
        assert "darwin" in tool.install_commands
        assert "pip install xortool" in tool.install_commands["darwin"]

    @patch.object(XortoolTool, "_run_with_result")
    def test_run_basic(self, mock_run, tmp_path):
        """Test basic run on file."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="xortool",
            command="xortool test.bin",
            stdout="The most probable key lengths are: 4, 8, 12",
            stderr="",
            parsed_data={"probable_key_lengths": [{"length": 4}]},
        )

        tool = XortoolTool()
        result = tool.run(test_file)

        assert result.success
        mock_run.assert_called_once()

    @patch.object(XortoolTool, "_run_with_result")
    def test_run_with_key_length(self, mock_run, tmp_path):
        """Test run with specified key length."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="xortool",
            command="xortool -l 4 test.bin",
            stdout="",
            stderr="",
        )

        tool = XortoolTool()
        tool.run(test_file, key_length=4)

        call_args = mock_run.call_args[0][0]
        assert "-l" in call_args
        assert "4" in call_args

    @patch.object(XortoolTool, "_run_with_result")
    def test_run_with_most_frequent(self, mock_run, tmp_path):
        """Test run with most frequent char specified."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="xortool",
            command="xortool -c 20 test.bin",
            stdout="",
            stderr="",
        )

        tool = XortoolTool()
        tool.run(test_file, most_frequent="20")

        call_args = mock_run.call_args[0][0]
        assert "-c" in call_args
        assert "20" in call_args

    def test_parse_output_key_lengths(self):
        """Test parsing key length output."""
        tool = XortoolTool()
        stdout = "Key-length can be 4*1 with 95.5% confidence\nKey-length can be 8*1 with 85.0% confidence"
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "probable_key_lengths" in result
        assert len(result["probable_key_lengths"]) >= 1

    def test_parse_output_found_key(self):
        """Test parsing when key is found."""
        tool = XortoolTool()
        stdout = "Key: secret\nKey (hex): 73 65 63 72 65 74"
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert result.get("key") == "secret"

    def test_get_suggestions_with_key(self):
        """Test suggestions when key is found."""
        tool = XortoolTool()
        parsed = {"key": "secret", "probable_key_lengths": []}

        suggestions = tool._get_suggestions(parsed)

        assert any("secret" in s for s in suggestions)
        assert any("decrypt" in s.lower() for s in suggestions)

    def test_get_suggestions_without_key(self):
        """Test suggestions when only key lengths found."""
        tool = XortoolTool()
        parsed = {
            "key": None,
            "probable_key_lengths": [{"length": 4, "confidence": 95.0}],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("4" in s for s in suggestions)
