"""Tests for forensics tool integrations."""

from unittest.mock import patch

from ctf_kit.integrations.forensics.binwalk import BinwalkTool


class TestBinwalkTool:
    """Tests for BinwalkTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = BinwalkTool()
        assert tool.name == "binwalk"
        assert tool.description == "Scan and extract firmware images and embedded files"
        assert "binwalk" in tool.binary_names

    def test_install_commands(self):
        """Test install commands are set."""
        tool = BinwalkTool()
        assert "darwin" in tool.install_commands
        assert "pip install binwalk" in tool.install_commands["darwin"]

    @patch.object(BinwalkTool, "_run_with_result")
    def test_run_basic(self, mock_run, tmp_path):
        """Test basic run on file."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "firmware.bin"
        test_file.write_bytes(b"\x00" * 1000)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="binwalk",
            command="binwalk firmware.bin",
            stdout="DECIMAL       HEXADECIMAL     DESCRIPTION\n0             0x0             ELF, 64-bit",
            stderr="",
            parsed_data={"signatures": [{"offset": 0, "description": "ELF"}]},
        )

        tool = BinwalkTool()
        result = tool.run(test_file)

        assert result.success
        mock_run.assert_called_once()

    @patch.object(BinwalkTool, "_run_with_result")
    def test_run_with_extract(self, mock_run, tmp_path):
        """Test run with extraction flag."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "firmware.bin"
        test_file.write_bytes(b"\x00" * 1000)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="binwalk",
            command="binwalk -e firmware.bin",
            stdout="",
            stderr="",
        )

        tool = BinwalkTool()
        tool.run(test_file, extract=True)

        call_args = mock_run.call_args[0][0]
        assert "-e" in call_args

    @patch.object(BinwalkTool, "_run_with_result")
    def test_run_with_entropy(self, mock_run, tmp_path):
        """Test run with entropy analysis."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "firmware.bin"
        test_file.write_bytes(b"\x00" * 1000)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="binwalk",
            command="binwalk -E firmware.bin",
            stdout="",
            stderr="",
        )

        tool = BinwalkTool()
        tool.run(test_file, entropy=True, signature=False)

        call_args = mock_run.call_args[0][0]
        assert "-E" in call_args

    @patch.object(BinwalkTool, "_run_with_result")
    def test_run_with_matryoshka(self, mock_run, tmp_path):
        """Test run with recursive extraction."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "firmware.bin"
        test_file.write_bytes(b"\x00" * 1000)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="binwalk",
            command="binwalk -e -M firmware.bin",
            stdout="",
            stderr="",
        )

        tool = BinwalkTool()
        tool.run(test_file, extract=True, matryoshka=True)

        call_args = mock_run.call_args[0][0]
        assert "-e" in call_args
        assert "-M" in call_args

    def test_parse_output_signatures(self):
        """Test parsing signature scan output."""
        tool = BinwalkTool()
        stdout = """DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v2.0 to extract
1024          0x400           PNG image data, 100 x 100"""
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "signatures" in result
        assert len(result["signatures"]) >= 2
        assert result["signatures"][0]["offset"] == 0

    def test_parse_output_file_types(self):
        """Test that file types are extracted."""
        tool = BinwalkTool()
        stdout = """DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Zip archive data
1024          0x400           PNG image data"""
        stderr = ""

        result = tool.parse_output(stdout, stderr)

        assert "file_types" in result
        assert "zip" in result["file_types"]
        assert "png" in result["file_types"]

    def test_extract_file_type(self):
        """Test file type extraction from description."""
        tool = BinwalkTool()

        assert tool._extract_file_type("Zip archive data") == "zip"
        assert tool._extract_file_type("PNG image data, 100x100") == "png"
        assert tool._extract_file_type("gzip compressed data") == "gzip"
        assert tool._extract_file_type("ELF, 64-bit LSB executable") == "elf"
        assert tool._extract_file_type("unknown data") is None

    def test_get_suggestions_with_archive(self):
        """Test suggestions when archive found."""
        tool = BinwalkTool()
        parsed = {
            "signatures": [{"offset": 0, "description": "Zip archive"}],
            "file_types": ["zip"],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("extract" in s.lower() for s in suggestions)

    def test_get_suggestions_with_image(self):
        """Test suggestions when image found."""
        tool = BinwalkTool()
        parsed = {
            "signatures": [{"offset": 0, "description": "PNG image"}],
            "file_types": ["png"],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("steg" in s.lower() for s in suggestions)

    def test_get_suggestions_no_signatures(self):
        """Test suggestions when no signatures found."""
        tool = BinwalkTool()
        parsed = {
            "signatures": [],
            "file_types": [],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("entropy" in s.lower() for s in suggestions)

    def test_get_suggestions_multiple_files(self):
        """Test suggestions for multiple embedded files."""
        tool = BinwalkTool()
        parsed = {
            "signatures": [
                {"offset": 0, "description": "Zip"},
                {"offset": 1000, "description": "PNG"},
            ],
            "file_types": ["zip", "png"],
        }

        suggestions = tool._get_suggestions(parsed)

        assert any("-M" in s or "recursive" in s.lower() for s in suggestions)

    @patch.object(BinwalkTool, "run")
    def test_quick_scan(self, mock_run, tmp_path):
        """Test quick_scan helper method."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="binwalk",
            command="binwalk test.bin",
            stdout="",
            stderr="",
            parsed_data={
                "signatures": [
                    {"offset": 0, "description": "ELF"},
                ]
            },
        )

        tool = BinwalkTool()
        result = tool.quick_scan(test_file)

        assert len(result) == 1
        assert result[0]["description"] == "ELF"

    @patch.object(BinwalkTool, "run")
    def test_entropy_scan(self, mock_run, tmp_path):
        """Test entropy_scan helper method."""
        from ctf_kit.integrations.base import ToolResult

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="binwalk",
            command="binwalk -E test.bin",
            stdout="",
            stderr="",
        )

        tool = BinwalkTool()
        tool.entropy_scan(test_file)

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("entropy") is True
        assert call_kwargs.get("signature") is False
