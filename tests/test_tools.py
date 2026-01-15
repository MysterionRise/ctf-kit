"""
Tests for tool integrations.
"""

from pathlib import Path
import tempfile

import pytest

from ctf_kit.integrations.base import (
    ToolCategory,
    get_all_tools,
    get_tool,
    get_tools_by_category,
)
from ctf_kit.integrations.basic import FileTool, StringsTool


class TestFileTool:
    """Test FileTool integration."""

    def test_file_tool_exists(self) -> None:
        """Test FileTool can be instantiated."""
        tool = FileTool()
        # Just verify the tool object exists
        assert tool is not None

    def test_file_tool_attributes(self) -> None:
        """Test FileTool class attributes."""
        tool = FileTool()
        assert tool.name == "file"
        assert tool.category == ToolCategory.MISC
        assert "file" in tool.binary_names

    @pytest.mark.skipif(
        not FileTool().is_installed,
        reason="file command not installed",
    )
    def test_file_tool_run_text(self) -> None:
        """Test running file on a text file."""
        tool = FileTool()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello, World!")
            f.flush()
            path = Path(f.name)

        try:
            result = tool.run(path)
            assert result.success
            assert "text" in result.stdout.lower() or "ascii" in result.stdout.lower()
        finally:
            path.unlink()

    @pytest.mark.skipif(
        not FileTool().is_installed,
        reason="file command not installed",
    )
    def test_file_tool_mime_type(self) -> None:
        """Test getting MIME type."""
        tool = FileTool()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello, World!")
            f.flush()
            path = Path(f.name)

        try:
            mime = tool.get_mime_type(path)
            assert mime is not None
            assert "text" in mime.lower()
        finally:
            path.unlink()

    def test_parse_elf_output(self) -> None:
        """Test parsing ELF file output."""
        tool = FileTool()
        parsed = tool.parse_output(
            "ELF 64-bit LSB executable, x86-64, not stripped",
            "",
        )
        assert parsed["is_elf"] is True
        assert parsed["is_executable"] is True
        assert parsed["architecture"] == "64-bit"
        assert parsed["stripped"] is False

    def test_parse_pe_output(self) -> None:
        """Test parsing PE file output."""
        tool = FileTool()
        parsed = tool.parse_output(
            "PE32+ executable (console) x86-64",
            "",
        )
        assert parsed["is_executable"] is True
        assert parsed["architecture"] == "64-bit"

    def test_parse_image_output(self) -> None:
        """Test parsing image file output."""
        tool = FileTool()
        parsed = tool.parse_output(
            "PNG image data, 800 x 600, 8-bit/color RGBA",
            "",
        )
        assert parsed["is_image"] is True
        assert parsed["width"] == 800
        assert parsed["height"] == 600


class TestStringsTool:
    """Test StringsTool integration."""

    def test_strings_tool_exists(self) -> None:
        """Test StringsTool can be instantiated."""
        tool = StringsTool()
        assert tool is not None

    def test_strings_tool_attributes(self) -> None:
        """Test StringsTool class attributes."""
        tool = StringsTool()
        assert tool.name == "strings"
        assert tool.category == ToolCategory.MISC
        assert "strings" in tool.binary_names

    @pytest.mark.skipif(
        not StringsTool().is_installed,
        reason="strings command not installed",
    )
    def test_strings_tool_run(self) -> None:
        """Test running strings on a binary file."""
        tool = StringsTool()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write some binary data with embedded strings
            f.write(b"\x00\x00\x00Hello World!\x00\x00\x00")
            f.write(b"\x00flag{test_flag}\x00")
            f.flush()
            path = Path(f.name)

        try:
            result = tool.run(path)
            assert result.success
            assert "Hello World" in result.stdout
        finally:
            path.unlink()

    @pytest.mark.skipif(
        not StringsTool().is_installed,
        reason="strings command not installed",
    )
    def test_strings_find_flags(self) -> None:
        """Test finding flag patterns."""
        tool = StringsTool()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x00flag{found_it}\x00\x00")
            f.write(b"\x00\x00CTF{another_flag}\x00\x00")
            f.flush()
            path = Path(f.name)

        try:
            flags = tool.find_flags(path)
            assert "flag{found_it}" in flags
            assert "CTF{another_flag}" in flags
        finally:
            path.unlink()

    def test_parse_output_with_flags(self) -> None:
        """Test parsing output that contains flags."""
        tool = StringsTool()
        stdout = "random data\nflag{test}\nmore data\n"
        parsed = tool.parse_output(stdout, "")
        assert "flag{test}" in parsed["flags"]

    def test_parse_output_with_urls(self) -> None:
        """Test parsing output that contains URLs."""
        tool = StringsTool()
        stdout = "some text\nhttps://example.com/path\nmore text\n"
        parsed = tool.parse_output(stdout, "")
        assert any("https://example.com/path" in url for url in parsed["urls"])


class TestToolRegistry:
    """Test tool registry functions."""

    def test_get_all_tools(self) -> None:
        """Test getting all registered tools."""
        # Import to register tools
        from ctf_kit.integrations import basic  # noqa: F401

        tools = get_all_tools()
        assert "file" in tools
        assert "strings" in tools

    def test_get_tool_by_name(self) -> None:
        """Test getting a specific tool."""
        from ctf_kit.integrations import basic  # noqa: F401

        tool = get_tool("file")
        assert tool is not None
        assert tool.name == "file"

    def test_get_nonexistent_tool(self) -> None:
        """Test getting a tool that doesn't exist."""
        tool = get_tool("nonexistent_tool_xyz")
        assert tool is None

    def test_get_tools_by_category(self) -> None:
        """Test getting tools by category."""
        from ctf_kit.integrations import basic  # noqa: F401

        misc_tools = get_tools_by_category(ToolCategory.MISC)
        assert "file" in misc_tools
        assert "strings" in misc_tools
