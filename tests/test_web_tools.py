"""Tests for web tool integrations."""

from unittest.mock import patch

from ctf_kit.integrations.base import ToolResult
from ctf_kit.integrations.web.nikto import NiktoTool


class TestNiktoTool:
    """Tests for NiktoTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = NiktoTool()
        assert tool.name == "nikto"
        assert tool.description == "Web server vulnerability scanner"
        assert "nikto" in tool.binary_names

    def test_install_commands(self):
        """Test install commands are set."""
        tool = NiktoTool()
        assert "darwin" in tool.install_commands
        assert "brew install nikto" in tool.install_commands["darwin"]
        assert "linux" in tool.install_commands

    @patch.object(NiktoTool, "_run_with_result")
    def test_run_basic(self, mock_run):
        """Test basic scan."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="nikto",
            command="nikto -h http://target",
            stdout=(
                "+ Target IP: 192.168.1.1\n"
                "+ Target Hostname: target\n"
                "+ Target Port: 80\n"
                "+ Server: Apache/2.4.41\n"
                "+ OSVDB-1234: /admin/: Admin directory found\n"
                "+ OSVDB-5678: /robots.txt: Robots file found\n"
            ),
            stderr="",
            parsed_data={
                "raw_stdout": "",
                "raw_stderr": "",
                "vulnerabilities": [
                    {"id": "OSVDB-1234", "path": "/admin/", "description": "Admin directory found"},
                    {"id": "OSVDB-5678", "path": "/robots.txt", "description": "Robots file found"},
                ],
                "server_info": {
                    "server": "Apache/2.4.41",
                    "ip": "192.168.1.1",
                    "hostname": "target",
                    "port": 80,
                },
                "interesting_findings": [
                    {"id": "OSVDB-5678", "path": "/robots.txt", "description": "Robots file found"},
                ],
                "total_items_found": 2,
            },
        )

        tool = NiktoTool()
        result = tool.run("http://target")

        assert result.success
        assert result.suggestions is not None
        mock_run.assert_called_once()

    @patch.object(NiktoTool, "_run_with_result")
    def test_run_with_options(self, mock_run):
        """Test run with SSL and port options."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="nikto",
            command="nikto -h target -p 443 -ssl",
            stdout="",
            stderr="",
        )

        tool = NiktoTool()
        tool.run("target", port=443, ssl=True)

        call_args = mock_run.call_args[0][0]
        assert "-h" in call_args
        assert "-p" in call_args
        assert "443" in call_args
        assert "-ssl" in call_args

    @patch.object(NiktoTool, "_run_with_result")
    def test_run_with_tuning(self, mock_run):
        """Test run with tuning options."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="nikto",
            command="nikto -h target -Tuning 9",
            stdout="",
            stderr="",
        )

        tool = NiktoTool()
        tool.run("target", tuning="9")

        call_args = mock_run.call_args[0][0]
        assert "-Tuning" in call_args
        assert "9" in call_args

    def test_parse_output_server_info(self):
        """Test parsing server info from output."""
        tool = NiktoTool()
        stdout = (
            "+ Target IP: 10.0.0.1\n"
            "+ Target Hostname: example.com\n"
            "+ Target Port: 8080\n"
            "+ Server: nginx/1.18.0\n"
        )
        parsed = tool.parse_output(stdout, "")
        assert parsed["server_info"]["ip"] == "10.0.0.1"
        assert parsed["server_info"]["hostname"] == "example.com"
        assert parsed["server_info"]["port"] == 8080
        assert parsed["server_info"]["server"] == "nginx/1.18.0"

    def test_parse_output_vulnerabilities(self):
        """Test parsing vulnerability entries."""
        tool = NiktoTool()
        stdout = (
            "+ OSVDB-1234: /admin/: Admin directory found\n"
            "+ OSVDB-5678: /backup/: Backup directory listing\n"
        )
        parsed = tool.parse_output(stdout, "")
        assert len(parsed["vulnerabilities"]) >= 2

    def test_parse_output_interesting_findings(self):
        """Test interesting findings are categorized."""
        tool = NiktoTool()
        stdout = (
            "+ OSVDB-1234: /robots.txt: Robots file found\n"
            "+ OSVDB-5678: /.git/: Git repository found\n"
            "+ OSVDB-9999: /index.html: Default index page\n"
        )
        parsed = tool.parse_output(stdout, "")
        # robots.txt and .git should be interesting
        assert len(parsed["interesting_findings"]) >= 2

    def test_suggestions_with_vulns(self):
        """Test suggestions when vulnerabilities found."""
        tool = NiktoTool()
        parsed = {
            "vulnerabilities": [
                {"id": "OSVDB-1", "path": "/admin/", "description": "Admin found"},
            ],
            "interesting_findings": [
                {"id": "OSVDB-1", "path": "/admin/", "description": "Admin found"},
            ],
            "server_info": {"server": "Apache/2.4.41"},
        }
        suggestions = tool._get_suggestions(parsed)
        assert any("1 items" in s for s in suggestions)
        assert any("Apache" in s for s in suggestions)

    def test_suggestions_no_vulns(self):
        """Test suggestions when no vulnerabilities found."""
        tool = NiktoTool()
        parsed = {
            "vulnerabilities": [],
            "interesting_findings": [],
            "server_info": {},
        }
        suggestions = tool._get_suggestions(parsed)
        assert any("No vulnerabilities" in s for s in suggestions)

    def test_convenience_methods_exist(self):
        """Test convenience methods are accessible."""
        tool = NiktoTool()
        assert hasattr(tool, "quick_scan")
        assert hasattr(tool, "full_scan")
        assert hasattr(tool, "scan_for_sqli")
