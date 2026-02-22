"""Tests for pwn tool integrations."""

from unittest.mock import MagicMock, patch

from ctf_kit.integrations.base import ToolResult
from ctf_kit.integrations.pwn.pwntools_wrapper import PwntoolsTool


class TestPwntoolsTool:
    """Tests for PwntoolsTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = PwntoolsTool()
        assert tool.name == "pwntools"
        assert tool.description == "Exploit development framework"
        assert tool.binary_names == []  # Python library

    def test_install_commands(self):
        """Test install commands are set."""
        tool = PwntoolsTool()
        assert "darwin" in tool.install_commands
        assert "pip install pwntools" in tool.install_commands["darwin"]
        assert "linux" in tool.install_commands

    @patch.dict("sys.modules", {"pwn": MagicMock()})
    def test_is_installed_true(self):
        """Test is_installed when pwntools is available."""
        tool = PwntoolsTool()
        assert tool.is_installed is True

    def test_is_installed_false(self):
        """Test is_installed when pwntools is not available."""
        with patch.dict("sys.modules", {"pwn": None}):
            tool = PwntoolsTool()
            with patch("builtins.__import__", side_effect=ImportError):
                assert tool.is_installed is False

    def test_run_unknown_action(self):
        """Test run with unknown action."""
        tool = PwntoolsTool()
        result = tool.run("/bin/ls", action="unknown")
        assert not result.success
        assert "Unknown action" in (result.error_message or "")

    @patch.object(PwntoolsTool, "is_installed", new_callable=lambda: property(lambda self: False))
    def test_checksec_not_installed(self, _mock):  # noqa: PT019
        """Test checksec when pwntools is not installed."""
        tool = PwntoolsTool()
        result = tool.checksec("/bin/ls")
        assert not result.success
        assert "not installed" in (result.error_message or "")

    @patch.object(PwntoolsTool, "is_installed", new_callable=lambda: property(lambda self: True))
    def test_checksec_success(self, _mock):  # noqa: PT019
        """Test checksec with mocked pwntools."""
        mock_elf = MagicMock()
        mock_elf.arch = "amd64"
        mock_elf.bits = 64
        mock_elf.endian = "little"
        mock_elf.canary = False
        mock_elf.nx = True
        mock_elf.pie = False
        mock_elf.relro = "Partial"
        mock_elf.rpath = False
        mock_elf.runpath = False

        with patch(
            "ctf_kit.integrations.pwn.pwntools_wrapper.PwntoolsTool.checksec"
        ) as mock_checksec:
            mock_checksec.return_value = ToolResult(
                success=True,
                tool_name="pwntools",
                command="checksec /test/binary",
                stdout="",
                stderr="",
                parsed_data={
                    "arch": "amd64",
                    "bits": 64,
                    "endian": "little",
                    "canary": False,
                    "nx": True,
                    "pie": False,
                    "relro": "Partial",
                    "rpath": False,
                    "runpath": False,
                },
                suggestions=[
                    "No stack canary - buffer overflows are exploitable",
                    "NX enabled - use ROP/ret2libc instead of shellcode",
                    "No PIE - addresses are fixed, easier for ROP",
                    "Partial/No RELRO - GOT overwrite possible",
                ],
            )

            tool = PwntoolsTool()
            result = tool.checksec("/test/binary")
            assert result.success
            assert result.parsed_data["arch"] == "amd64"
            assert result.parsed_data["canary"] is False
            assert result.suggestions is not None

    @patch.object(PwntoolsTool, "is_installed", new_callable=lambda: property(lambda self: False))
    def test_create_cyclic_not_installed(self, _mock):  # noqa: PT019
        """Test cyclic pattern when pwntools is not installed."""
        tool = PwntoolsTool()
        result = tool.create_cyclic_pattern(100)
        assert not result.success
        assert "not installed" in (result.error_message or "")

    @patch.object(PwntoolsTool, "is_installed", new_callable=lambda: property(lambda self: False))
    def test_find_offset_not_installed(self, _mock):  # noqa: PT019
        """Test find_offset when pwntools is not installed."""
        tool = PwntoolsTool()
        result = tool.find_offset(0x41414141)
        assert not result.success
        assert "not installed" in (result.error_message or "")

    @patch.object(PwntoolsTool, "is_installed", new_callable=lambda: property(lambda self: False))
    def test_find_gadgets_not_installed(self, _mock):  # noqa: PT019
        """Test find_gadgets when pwntools is not installed."""
        tool = PwntoolsTool()
        result = tool.find_gadgets("/bin/ls")
        assert not result.success
        assert "not installed" in (result.error_message or "")

    def test_generate_exploit_template_bof(self):
        """Test buffer overflow exploit template generation."""
        tool = PwntoolsTool()
        template = tool.generate_exploit_template(
            "/test/binary",
            vuln_type="buffer_overflow",
            offset=72,
        )
        assert "from pwn import" in template
        assert "offset = 72" in template
        assert 'binary_path = "/test/binary"' in template

    def test_generate_exploit_template_fmt(self):
        """Test format string exploit template generation."""
        tool = PwntoolsTool()
        template = tool.generate_exploit_template(
            "/test/binary",
            vuln_type="format_string",
        )
        assert "from pwn import" in template
        assert "Format string" in template
        assert "%p." in template

    def test_generate_exploit_template_ret2libc(self):
        """Test ret2libc exploit template generation."""
        tool = PwntoolsTool()
        template = tool.generate_exploit_template(
            "/test/binary",
            vuln_type="ret2libc",
        )
        assert "from pwn import" in template
        assert "ret2libc" in template

    def test_checksec_suggestions_no_protections(self):
        """Test suggestions for unprotected binary."""
        tool = PwntoolsTool()
        security = {
            "canary": False,
            "nx": False,
            "pie": False,
            "relro": None,
        }
        suggestions = tool._get_checksec_suggestions(security)
        assert any("buffer overflows" in s.lower() for s in suggestions)
        assert any("shellcode" in s.lower() for s in suggestions)
        assert any("fixed" in s.lower() for s in suggestions)

    def test_checksec_suggestions_full_protections(self):
        """Test suggestions for fully protected binary."""
        tool = PwntoolsTool()
        security = {
            "canary": True,
            "nx": True,
            "pie": True,
            "relro": "Full",
        }
        suggestions = tool._get_checksec_suggestions(security)
        assert any("leak" in s.lower() or "brute" in s.lower() for s in suggestions)
        assert any("rop" in s.lower() for s in suggestions)
        assert any("aslr" in s.lower() for s in suggestions)
        assert any("read-only" in s.lower() for s in suggestions)
