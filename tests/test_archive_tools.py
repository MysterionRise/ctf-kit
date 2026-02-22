"""Tests for archive tool integrations."""

from pathlib import Path
from unittest.mock import patch

from ctf_kit.integrations.archive.bkcrack import KNOWN_HEADERS, BkcrackTool
from ctf_kit.integrations.base import ToolResult


class TestBkcrackTool:
    """Tests for BkcrackTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = BkcrackTool()
        assert tool.name == "bkcrack"
        assert tool.description == "ZIP known-plaintext attack (ZipCrypto)"
        assert "bkcrack" in tool.binary_names

    def test_install_commands(self):
        """Test install commands are set."""
        tool = BkcrackTool()
        assert "darwin" in tool.install_commands
        assert "brew install bkcrack" in tool.install_commands["darwin"]
        assert "linux" in tool.install_commands

    def test_known_headers(self):
        """Test known plaintext headers are defined."""
        assert "png" in KNOWN_HEADERS
        assert KNOWN_HEADERS["png"].startswith(b"\x89PNG")
        assert "jpeg" in KNOWN_HEADERS
        assert "pdf" in KNOWN_HEADERS
        assert "zip" in KNOWN_HEADERS

    @patch.object(BkcrackTool, "_run_with_result")
    def test_list_entries(self, mock_run):
        """Test listing ZIP entries."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="bkcrack",
            command="bkcrack -L test.zip",
            stdout=(
                "Index Offset Size  Crc32    Encrypted  Entry\n"
                "----- ------ ----- -----    ---------  -----\n"
                "0     0      1024  abc123   ZipCrypto  flag.txt\n"
                "1     1024   2048  def456   ZipCrypto  image.png\n"
            ),
            stderr="",
        )

        tool = BkcrackTool()
        result = tool.run("test.zip", list_entries=True)

        assert result.success
        assert result.parsed_data is not None
        assert len(result.parsed_data["entries"]) == 2
        assert result.parsed_data["entries"][0]["name"] == "flag.txt"
        assert result.parsed_data["entries"][0]["encrypted"] is True
        mock_run.assert_called_once()

    @patch.object(BkcrackTool, "_run_with_result")
    def test_attack_with_keys_found(self, mock_run):
        """Test attack that successfully finds keys."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="bkcrack",
            command="bkcrack -C test.zip -c flag.txt -p plain.bin",
            stdout="Keys: 12345678 9abcdef0 11223344\n",
            stderr="",
            parsed_data={
                "raw_stdout": "Keys: 12345678 9abcdef0 11223344\n",
                "raw_stderr": "",
            },
        )

        tool = BkcrackTool()
        result = tool.run(
            "test.zip",
            cipher_entry="flag.txt",
            plain_file="plain.bin",
        )

        assert result.success
        assert result.parsed_data["key_found"] is True
        assert result.parsed_data["keys"] == (0x12345678, 0x9ABCDEF0, 0x11223344)

    @patch.object(BkcrackTool, "_run_with_result")
    def test_attack_no_keys(self, mock_run):
        """Test attack that does not find keys."""
        mock_run.return_value = ToolResult(
            success=False,
            tool_name="bkcrack",
            command="bkcrack -C test.zip -c flag.txt -p plain.bin",
            stdout="Could not find the keys.\n",
            stderr="",
            parsed_data={
                "raw_stdout": "Could not find the keys.\n",
                "raw_stderr": "",
            },
        )

        tool = BkcrackTool()
        result = tool.run(
            "test.zip",
            cipher_entry="flag.txt",
            plain_file="plain.bin",
        )

        assert not result.success
        assert result.parsed_data["key_found"] is False

    @patch.object(BkcrackTool, "_run_with_result")
    def test_decrypt_with_keys(self, mock_run):
        """Test decrypting with recovered keys."""
        output_zip = Path("/tmp/test_decrypted.zip")
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="bkcrack",
            command="bkcrack -C test.zip -k 0x12345678 0x9abcdef0 0x11223344 -D /tmp/test_decrypted.zip",
            stdout="Decrypted archive written.\n",
            stderr="",
        )

        tool = BkcrackTool()
        # Patch Path.exists to return True
        with patch.object(Path, "exists", return_value=True):
            result = tool.decrypt("test.zip", (0x12345678, 0x9ABCDEF0, 0x11223344), output_zip)

        assert result.success
        assert result.artifacts is not None

    def test_parse_list_output(self):
        """Test parsing list output."""
        tool = BkcrackTool()
        stdout = (
            "Index Offset Size  Crc32    Encrypted  Entry\n"
            "----- ------ ----- -----    ---------  -----\n"
            "0     0      1024  abc123   ZipCrypto  secret.txt\n"
            "1     1024   2048  def456              public.txt\n"
        )
        parsed = tool._parse_list_output(stdout)
        assert len(parsed["entries"]) == 2
        assert parsed["entries"][0]["encrypted"] is True
        assert parsed["entries"][1]["encrypted"] is False

    def test_parse_attack_output_with_keys(self):
        """Test parsing attack output with keys found."""
        tool = BkcrackTool()
        stdout = "Keys: aabbccdd 11223344 55667788\n"
        parsed = tool._parse_attack_output(stdout)
        assert parsed["key_found"] is True
        assert parsed["keys"] == (0xAABBCCDD, 0x11223344, 0x55667788)

    def test_parse_attack_output_no_keys(self):
        """Test parsing attack output with no keys."""
        tool = BkcrackTool()
        stdout = "Could not find the keys.\n"
        parsed = tool._parse_attack_output(stdout)
        assert parsed["key_found"] is False
        assert parsed["keys"] is None

    def test_parse_password_output(self):
        """Test parsing password recovery output."""
        tool = BkcrackTool()
        stdout = "Password: secret123\n"
        parsed = tool._parse_password_output(stdout)
        assert parsed["password_found"] is True
        assert parsed["password"] == "secret123"

    def test_list_suggestions_encrypted(self):
        """Test suggestions for encrypted entries."""
        tool = BkcrackTool()
        parsed = {"entries": [{"name": "file.txt", "encrypted": True}]}
        suggestions = tool._get_list_suggestions(parsed)
        assert any("ZipCrypto" in s for s in suggestions)
        assert any("12 bytes" in s for s in suggestions)

    def test_list_suggestions_no_encryption(self):
        """Test suggestions when no encrypted entries found."""
        tool = BkcrackTool()
        parsed = {"entries": [{"name": "file.txt", "encrypted": False}]}
        suggestions = tool._get_list_suggestions(parsed)
        assert any("No ZipCrypto" in s for s in suggestions)

    def test_convenience_methods_exist(self):
        """Test convenience methods are accessible."""
        tool = BkcrackTool()
        assert hasattr(tool, "list_zip")
        assert hasattr(tool, "attack_with_file")
        assert hasattr(tool, "attack_with_bytes")
        assert hasattr(tool, "decrypt")
