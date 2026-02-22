"""Tests for miscellaneous tool integrations."""

from unittest.mock import patch

from ctf_kit.integrations.base import ToolCategory, ToolResult
from ctf_kit.integrations.misc.qrencode import QrencodeTool
from ctf_kit.integrations.misc.zbarimg import ZbarimgTool


class TestZbarimgTool:
    """Tests for ZbarimgTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = ZbarimgTool()
        assert tool.name == "zbarimg"
        assert tool.category == ToolCategory.MISC
        assert "zbarimg" in tool.binary_names

    def test_install_commands(self):
        """Test install commands for different platforms."""
        tool = ZbarimgTool()
        assert "darwin" in tool.install_commands
        assert "brew install zbar" in tool.install_commands["darwin"]
        assert "linux" in tool.install_commands

    @patch.object(ZbarimgTool, "_run_with_result")
    def test_run_basic(self, mock_run, tmp_path):
        """Test basic QR code scan."""
        test_file = tmp_path / "qr.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="zbarimg",
            command="zbarimg --quiet qr.png",
            stdout="QR-Code:flag{qr_hidden}",
            stderr="",
            parsed_data={
                "codes": [{"type": "QR-Code", "data": "flag{qr_hidden}"}],
                "qr_codes": [{"type": "QR-Code", "data": "flag{qr_hidden}"}],
                "barcodes": [],
            },
        )

        tool = ZbarimgTool()
        result = tool.run(str(test_file))

        assert result.success
        mock_run.assert_called_once()

    @patch.object(ZbarimgTool, "_run_with_result")
    def test_run_with_options(self, mock_run, tmp_path):
        """Test run with quiet and raw flags."""
        test_file = tmp_path / "qr.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="zbarimg",
            command="zbarimg --quiet --raw qr.png",
            stdout="flag{data}",
            stderr="",
        )

        tool = ZbarimgTool()
        tool.run(str(test_file), quiet=True, raw=True)

        args = mock_run.call_args[0][0]
        assert "--quiet" in args
        assert "--raw" in args

    def test_parse_output_qr_code(self):
        """Test parsing QR code output."""
        tool = ZbarimgTool()
        stdout = "QR-Code:https://example.com/flag"
        parsed = tool.parse_output(stdout, "")

        assert len(parsed["codes"]) == 1
        assert parsed["codes"][0]["type"] == "QR-Code"
        assert parsed["codes"][0]["data"] == "https://example.com/flag"
        assert len(parsed["qr_codes"]) == 1
        assert len(parsed["barcodes"]) == 0

    def test_parse_output_barcode(self):
        """Test parsing barcode output."""
        tool = ZbarimgTool()
        stdout = "EAN-13:1234567890123"
        parsed = tool.parse_output(stdout, "")

        assert len(parsed["codes"]) == 1
        assert parsed["codes"][0]["type"] == "EAN-13"
        assert len(parsed["barcodes"]) == 1
        assert len(parsed["qr_codes"]) == 0

    def test_parse_output_multiple_codes(self):
        """Test parsing multiple codes in one image."""
        tool = ZbarimgTool()
        stdout = "QR-Code:data1\nQR-Code:data2\nEAN-13:1234567890123"
        parsed = tool.parse_output(stdout, "")

        assert len(parsed["codes"]) == 3
        assert len(parsed["qr_codes"]) == 2
        assert len(parsed["barcodes"]) == 1

    def test_parse_output_empty(self):
        """Test parsing empty output."""
        tool = ZbarimgTool()
        parsed = tool.parse_output("", "")

        assert len(parsed["codes"]) == 0
        assert len(parsed["qr_codes"]) == 0

    def test_get_suggestions_with_flag(self):
        """Test suggestions when flag found in QR data."""
        tool = ZbarimgTool()
        parsed = {
            "codes": [{"type": "QR-Code", "data": "flag{qr_ctf}"}],
            "qr_codes": [{"type": "QR-Code", "data": "flag{qr_ctf}"}],
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("FLAG" in s or "flag" in s for s in suggestions)

    def test_get_suggestions_with_url(self):
        """Test suggestions when URL found in QR data."""
        tool = ZbarimgTool()
        parsed = {
            "codes": [{"type": "QR-Code", "data": "https://ctf.example.com/next"}],
            "qr_codes": [{"type": "QR-Code", "data": "https://ctf.example.com/next"}],
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("URL" in s or "url" in s.lower() for s in suggestions)

    def test_get_suggestions_no_codes(self):
        """Test suggestions when no codes found."""
        tool = ZbarimgTool()
        parsed = {"codes": [], "qr_codes": []}
        suggestions = tool._get_suggestions(parsed)

        assert any("no" in s.lower() for s in suggestions)

    def test_get_suggestions_base64(self):
        """Test suggestions when base64-like data found."""
        tool = ZbarimgTool()
        parsed = {
            "codes": [{"type": "QR-Code", "data": "SGVsbG8gV29ybGQ="}],
            "qr_codes": [{"type": "QR-Code", "data": "SGVsbG8gV29ybGQ="}],
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("base64" in s.lower() for s in suggestions)


class TestQrencodeTool:
    """Tests for QrencodeTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = QrencodeTool()
        assert tool.name == "qrencode"
        assert tool.category == ToolCategory.MISC
        assert "qrencode" in tool.binary_names

    def test_install_commands(self):
        """Test install commands."""
        tool = QrencodeTool()
        assert "darwin" in tool.install_commands
        assert "brew install qrencode" in tool.install_commands["darwin"]
        assert "linux" in tool.install_commands

    @patch.object(QrencodeTool, "_run_with_result")
    def test_run_basic(self, mock_run, tmp_path):
        """Test basic QR code generation."""
        output = str(tmp_path / "output.png")

        mock_run.return_value = ToolResult(
            success=True,
            tool_name="qrencode",
            command="qrencode -s 10 -t PNG -l L -o output.png",
            stdout="",
            stderr="",
            parsed_data={"generated": True},
        )

        tool = QrencodeTool()
        result = tool.run("test data", output=output)

        assert result.success
        mock_run.assert_called_once()
        # Check that input_data was passed
        assert mock_run.call_args[1]["input_data"] == "test data"

    @patch.object(QrencodeTool, "_run_with_result")
    def test_run_with_options(self, mock_run):
        """Test run with custom options."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="qrencode",
            command="qrencode -s 20 -t SVG -l H",
            stdout="",
            stderr="",
        )

        tool = QrencodeTool()
        tool.run("data", size=20, output_type="SVG", level="H")

        args = mock_run.call_args[0][0]
        assert "-s" in args
        idx = args.index("-s")
        assert args[idx + 1] == "20"
        assert "-t" in args
        idx = args.index("-t")
        assert args[idx + 1] == "SVG"
        assert "-l" in args
        idx = args.index("-l")
        assert args[idx + 1] == "H"

    @patch.object(QrencodeTool, "_run_with_result")
    def test_run_to_terminal(self, mock_run):
        """Test terminal QR code output."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="qrencode",
            command="qrencode -s 10 -t UTF8 -l L",
            stdout="[QR code art here]",
            stderr="",
        )

        tool = QrencodeTool()
        result = tool.encode_to_terminal("hello")

        assert result.success

    def test_parse_output_success(self):
        """Test parsing successful output."""
        tool = QrencodeTool()
        parsed = tool.parse_output("", "")

        assert parsed["generated"] is True

    def test_parse_output_error(self):
        """Test parsing error output."""
        tool = QrencodeTool()
        parsed = tool.parse_output("", "error: invalid input")

        assert parsed["generated"] is False

    def test_get_suggestions_with_output(self):
        """Test suggestions when output file specified."""
        tool = QrencodeTool()
        suggestions = tool._get_suggestions("output.png", "PNG")

        assert any("output.png" in s for s in suggestions)
        assert any("zbarimg" in s.lower() for s in suggestions)

    def test_get_suggestions_no_output(self):
        """Test suggestions when output to stdout."""
        tool = QrencodeTool()
        suggestions = tool._get_suggestions(None, "UTF8")

        assert any("stdout" in s.lower() for s in suggestions)
