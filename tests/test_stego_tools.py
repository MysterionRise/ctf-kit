"""Tests for steganography tool integrations."""

from unittest.mock import patch

from ctf_kit.integrations.stego.exiftool import ExiftoolTool
from ctf_kit.integrations.stego.zsteg import ZstegTool


class TestExiftoolTool:
    """Tests for ExiftoolTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = ExiftoolTool()
        assert tool.name == "exiftool"
        assert tool.description == "Read and write metadata in images and media files"
        assert "exiftool" in tool.binary_names

    def test_install_commands(self):
        """Test install commands for different platforms."""
        tool = ExiftoolTool()
        assert "darwin" in tool.install_commands
        assert "brew install exiftool" in tool.install_commands["darwin"]
        assert "linux" in tool.install_commands

    @patch.object(ExiftoolTool, "_run_with_result")
    def test_run_basic(self, mock_run, tmp_path):
        """Test basic run on file."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="exiftool",
            command="exiftool -j -a test.png",
            stdout='[{"FileName": "test.png", "FileType": "PNG"}]',
            stderr="",
            parsed_data={"metadata": {"FileName": "test.png"}},
        )

        tool = ExiftoolTool()
        result = tool.run(test_file)

        assert result.success
        mock_run.assert_called_once()

    @patch.object(ExiftoolTool, "_run_with_result")
    def test_run_with_options(self, mock_run, tmp_path):
        """Test run with JSON and all_tags options."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.jpg"
        test_file.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="exiftool",
            command="exiftool -j -a test.jpg",
            stdout="[]",
            stderr="",
        )

        tool = ExiftoolTool()
        tool.run(test_file, json_output=True, all_tags=True)

        call_args = mock_run.call_args[0][0]
        assert "-j" in call_args
        assert "-a" in call_args

    def test_parse_output_json(self):
        """Test parsing JSON output."""
        tool = ExiftoolTool()
        stdout = '[{"FileName": "test.png", "Comment": "flag{hidden}"}]'
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "metadata" in result
        assert result["metadata"].get("FileName") == "test.png"
        assert result["metadata"].get("Comment") == "flag{hidden}"

    def test_parse_output_text(self):
        """Test parsing text output when JSON fails."""
        tool = ExiftoolTool()
        stdout = "File Name: test.png\nComment: flag{hidden}"
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "metadata" in result

    def test_find_interesting_fields(self):
        """Test finding CTF-relevant fields."""
        tool = ExiftoolTool()
        metadata = {
            "FileName": "test.png",
            "Comment": "flag{hidden_in_metadata}",
            "Author": "CTF Creator",
            "GPSLatitude": "40.7128 N",
        }

        interesting = tool._find_interesting_fields(metadata)

        # Should find comment and GPS
        assert len(interesting) > 0
        assert any("Comment" in f["field"] for f in interesting)

    def test_get_suggestions_with_gps(self):
        """Test suggestions when GPS data found."""
        tool = ExiftoolTool()
        parsed = {
            "metadata": {"GPSLatitude": "40.7128"},
            "interesting_fields": [],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("gps" in s.lower() or "location" in s.lower() for s in suggestions)

    def test_parse_gps_decimal(self):
        """Test parsing decimal GPS coordinates."""
        tool = ExiftoolTool()

        result = tool._parse_gps("40.7128")
        assert abs(result - 40.7128) < 0.001

    def test_parse_gps_dms(self):
        """Test parsing DMS GPS coordinates."""
        tool = ExiftoolTool()

        result = tool._parse_gps("40 deg 42' 46.08\" N")
        assert result > 40.7  # Should be around 40.7128


class TestZstegTool:
    """Tests for ZstegTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = ZstegTool()
        assert tool.name == "zsteg"
        assert tool.description == "Detect LSB steganography in PNG and BMP images"
        assert "zsteg" in tool.binary_names

    def test_install_commands(self):
        """Test install commands use gem."""
        tool = ZstegTool()
        assert "darwin" in tool.install_commands
        assert "gem install zsteg" in tool.install_commands["darwin"]

    @patch.object(ZstegTool, "_run_with_result")
    def test_run_basic(self, mock_run, tmp_path):
        """Test basic run on PNG file."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="zsteg",
            command="zsteg -a test.png",
            stdout='b1,lsb,xy .. text: "hidden message"',
            stderr="",
            parsed_data={"findings": [], "has_hidden_data": True},
        )

        tool = ZstegTool()
        result = tool.run(test_file)

        assert result.success
        mock_run.assert_called_once()

    @patch.object(ZstegTool, "_run_with_result")
    def test_run_with_all_methods(self, mock_run, tmp_path):
        """Test run with all methods flag."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="zsteg",
            command="zsteg -a test.png",
            stdout="",
            stderr="",
        )

        tool = ZstegTool()
        tool.run(test_file, all_methods=True)

        call_args = mock_run.call_args[0][0]
        assert "-a" in call_args

    def test_parse_output_text_finding(self):
        """Test parsing text finding."""
        tool = ZstegTool()
        stdout = 'b1,lsb,xy .. text: "flag{stego_hidden}"'
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "findings" in result
        assert result.get("has_hidden_data") is True

    def test_parse_output_file_finding(self):
        """Test parsing file finding."""
        tool = ZstegTool()
        stdout = "b1,rgb,lsb,xy .. file: PNG image data"
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "findings" in result

    def test_parse_output_finds_flags(self):
        """Test that flags are detected in output."""
        tool = ZstegTool()
        stdout = 'b1,lsb,xy .. text: "flag{found_it}"'
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "possible_flags" in result
        assert any("flag{found_it}" in f for f in result["possible_flags"])

    def test_get_suggestions_with_hidden_data(self):
        """Test suggestions when hidden data found."""
        tool = ZstegTool()
        parsed = {
            "findings": [{"type": "text", "channel": "b1,lsb,xy", "content": "hidden"}],
            "has_hidden_data": True,
            "possible_flags": [],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("text" in s.lower() or "hidden" in s.lower() for s in suggestions)

    def test_get_suggestions_no_data(self):
        """Test suggestions when no hidden data found."""
        tool = ZstegTool()
        parsed = {
            "findings": [],
            "has_hidden_data": False,
            "possible_flags": [],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("steghide" in s.lower() or "other" in s.lower() for s in suggestions)

    def test_get_suggestions_with_flags(self):
        """Test suggestions when flags are found."""
        tool = ZstegTool()
        parsed = {
            "findings": [],
            "has_hidden_data": True,
            "possible_flags": ["flag{test}"],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("flag" in s.lower() for s in suggestions)
