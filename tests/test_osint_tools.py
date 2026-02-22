"""Tests for OSINT tool integrations."""

from unittest.mock import patch

from ctf_kit.integrations.base import ToolCategory, ToolResult
from ctf_kit.integrations.osint.dig import DigTool
from ctf_kit.integrations.osint.shodan_tool import ShodanTool
from ctf_kit.integrations.osint.whois import WhoisTool


class TestWhoisTool:
    """Tests for WhoisTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = WhoisTool()
        assert tool.name == "whois"
        assert tool.category == ToolCategory.OSINT
        assert "whois" in tool.binary_names

    def test_install_commands(self):
        """Test install commands for different platforms."""
        tool = WhoisTool()
        assert "darwin" in tool.install_commands
        assert "linux" in tool.install_commands

    @patch.object(WhoisTool, "_run_with_result")
    def test_run_basic(self, mock_run):
        """Test basic WHOIS lookup."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="whois",
            command="whois example.com",
            stdout="Registrar: Example Registrar\nCreation Date: 2020-01-01",
            stderr="",
            parsed_data={"registrar": "Example Registrar"},
        )

        tool = WhoisTool()
        result = tool.run("example.com")

        assert result.success
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "example.com" in args

    @patch.object(WhoisTool, "_run_with_result")
    def test_run_with_server(self, mock_run):
        """Test WHOIS lookup with specific server."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="whois",
            command="whois -h whois.iana.org example.com",
            stdout="",
            stderr="",
        )

        tool = WhoisTool()
        tool.run("example.com", server="whois.iana.org")

        args = mock_run.call_args[0][0]
        assert "-h" in args
        assert "whois.iana.org" in args

    def test_parse_output_registrar(self):
        """Test parsing registrar from WHOIS output."""
        tool = WhoisTool()
        stdout = "Registrar: GoDaddy.com LLC\nCreation Date: 2020-01-15"
        parsed = tool.parse_output(stdout, "")

        assert parsed["registrar"] == "GoDaddy.com LLC"
        assert parsed["creation_date"] == "2020-01-15"

    def test_parse_output_nameservers(self):
        """Test parsing nameservers."""
        tool = WhoisTool()
        stdout = "Name Server: ns1.example.com\nName Server: ns2.example.com"
        parsed = tool.parse_output(stdout, "")

        assert len(parsed["nameservers"]) == 2
        assert "ns1.example.com" in parsed["nameservers"]

    def test_parse_output_emails(self):
        """Test extracting emails from WHOIS output."""
        tool = WhoisTool()
        stdout = "Registrant Email: admin@example.com\nTech Email: tech@example.com"
        parsed = tool.parse_output(stdout, "")

        assert "admin@example.com" in parsed["emails"]
        assert "tech@example.com" in parsed["emails"]

    def test_parse_output_expiration(self):
        """Test parsing expiration date."""
        tool = WhoisTool()
        stdout = "Expiration Date: 2025-12-31"
        parsed = tool.parse_output(stdout, "")

        assert parsed["expiration_date"] == "2025-12-31"

    def test_get_suggestions_with_data(self):
        """Test suggestions when data found."""
        tool = WhoisTool()
        parsed = {
            "registrar": "Namecheap",
            "creation_date": "2020-01-01",
            "nameservers": ["ns1.example.com"],
            "emails": ["admin@example.com"],
            "registrant": {"name": "John Doe"},
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("Namecheap" in s for s in suggestions)
        assert any("2020" in s for s in suggestions)

    def test_get_suggestions_empty(self):
        """Test suggestions when no data found."""
        tool = WhoisTool()
        parsed = {
            "registrar": None,
            "creation_date": None,
            "nameservers": [],
            "emails": [],
            "registrant": {},
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("no" in s.lower() or "privacy" in s.lower() for s in suggestions)


class TestDigTool:
    """Tests for DigTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = DigTool()
        assert tool.name == "dig"
        assert tool.category == ToolCategory.OSINT
        assert "dig" in tool.binary_names

    def test_install_commands(self):
        """Test install commands."""
        tool = DigTool()
        assert "darwin" in tool.install_commands
        assert "linux" in tool.install_commands

    @patch.object(DigTool, "_run_with_result")
    def test_run_basic(self, mock_run):
        """Test basic DNS lookup."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="dig",
            command="dig example.com ANY",
            stdout="",
            stderr="",
            parsed_data={"records": []},
        )

        tool = DigTool()
        result = tool.run("example.com")

        assert result.success
        args = mock_run.call_args[0][0]
        assert "example.com" in args
        assert "ANY" in args

    @patch.object(DigTool, "_run_with_result")
    def test_run_with_server(self, mock_run):
        """Test DNS lookup with specific server."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="dig",
            command="dig @8.8.8.8 example.com A",
            stdout="",
            stderr="",
        )

        tool = DigTool()
        tool.run("example.com", record_type="A", server="8.8.8.8")

        args = mock_run.call_args[0][0]
        assert "@8.8.8.8" in args
        assert "A" in args

    @patch.object(DigTool, "_run_with_result")
    def test_run_short_mode(self, mock_run):
        """Test short output mode."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="dig",
            command="dig example.com A +short",
            stdout="93.184.216.34",
            stderr="",
        )

        tool = DigTool()
        tool.run("example.com", record_type="A", short=True)

        args = mock_run.call_args[0][0]
        assert "+short" in args

    def test_parse_output_a_record(self):
        """Test parsing A record output."""
        tool = DigTool()
        stdout = """;; ANSWER SECTION:
example.com.    3600    IN    A    93.184.216.34

;; Query time: 42 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
"""
        parsed = tool.parse_output(stdout, "")

        assert len(parsed["records"]) == 1
        assert parsed["records"][0]["type"] == "A"
        assert parsed["records"][0]["value"] == "93.184.216.34"
        assert parsed["query_time"] == 42
        assert parsed["server"] == "8.8.8.8"

    def test_parse_output_mx_records(self):
        """Test parsing MX records."""
        tool = DigTool()
        stdout = """;; ANSWER SECTION:
example.com.    3600    IN    MX    10 mail.example.com.
example.com.    3600    IN    MX    20 mail2.example.com.
"""
        parsed = tool.parse_output(stdout, "")

        assert len(parsed["records"]) == 2
        assert parsed["records"][0]["type"] == "MX"

    def test_parse_output_txt_records(self):
        """Test parsing TXT records."""
        tool = DigTool()
        stdout = """;; ANSWER SECTION:
example.com.    3600    IN    TXT    "v=spf1 include:_spf.google.com ~all"
"""
        parsed = tool.parse_output(stdout, "")

        assert len(parsed["records"]) == 1
        assert parsed["records"][0]["type"] == "TXT"
        assert "spf1" in parsed["records"][0]["value"]

    def test_parse_output_nxdomain(self):
        """Test parsing NXDOMAIN response."""
        tool = DigTool()
        stdout = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 12345"
        parsed = tool.parse_output(stdout, "")

        assert parsed["status"] == "NXDOMAIN"

    def test_get_suggestions_nxdomain(self):
        """Test suggestions for NXDOMAIN."""
        tool = DigTool()
        parsed = {"records": [], "status": "NXDOMAIN"}
        suggestions = tool._get_suggestions(parsed)

        assert any("NXDOMAIN" in s for s in suggestions)

    def test_get_suggestions_with_records(self):
        """Test suggestions when records found."""
        tool = DigTool()
        parsed = {
            "records": [
                {"type": "A", "value": "1.2.3.4", "name": "example.com.", "ttl": 3600},
                {"type": "TXT", "value": "v=spf1", "name": "example.com.", "ttl": 3600},
            ],
            "status": "NOERROR",
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("IP" in s or "1.2.3.4" in s for s in suggestions)
        assert any("TXT" in s for s in suggestions)

    def test_get_suggestions_empty(self):
        """Test suggestions when no records found."""
        tool = DigTool()
        parsed = {"records": [], "status": "NOERROR"}
        suggestions = tool._get_suggestions(parsed)

        assert any("no records" in s.lower() or "axfr" in s.lower() for s in suggestions)


class TestShodanTool:
    """Tests for ShodanTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = ShodanTool()
        assert tool.name == "shodan"
        assert tool.category == ToolCategory.OSINT
        assert "shodan" in tool.binary_names

    def test_install_commands(self):
        """Test install commands use pip."""
        tool = ShodanTool()
        assert "pip install shodan" in tool.install_commands["darwin"]
        assert "pip install shodan" in tool.install_commands["linux"]

    @patch.object(ShodanTool, "_run_with_result")
    def test_run_host(self, mock_run):
        """Test host info lookup."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="shodan",
            command="shodan host 1.2.3.4",
            stdout="IP: 1.2.3.4\nPorts: 80, 443",
            stderr="",
            parsed_data={"ip": "1.2.3.4", "ports": [80, 443]},
        )

        tool = ShodanTool()
        result = tool.run("host", target="1.2.3.4")

        assert result.success
        args = mock_run.call_args[0][0]
        assert "host" in args
        assert "1.2.3.4" in args

    @patch.object(ShodanTool, "_run_with_result")
    def test_run_search(self, mock_run):
        """Test search command."""
        mock_run.return_value = ToolResult(
            success=True,
            tool_name="shodan",
            command="shodan search apache",
            stdout="",
            stderr="",
            parsed_data={},
        )

        tool = ShodanTool()
        tool.run("search", query="apache")

        args = mock_run.call_args[0][0]
        assert "search" in args
        assert "apache" in args

    def test_parse_output_text(self):
        """Test parsing text host output."""
        tool = ShodanTool()
        stdout = """IP: 1.2.3.4
Hostnames: example.com, www.example.com
Ports: 80, 443, 8080
OS: Linux
Organization: Example Corp
Country: United States
80/tcp Apache/2.4
443/tcp nginx"""

        parsed = tool.parse_output(stdout, "")

        assert parsed["ip"] == "1.2.3.4"
        assert "example.com" in parsed["hostnames"]
        assert 80 in parsed["ports"]
        assert 443 in parsed["ports"]
        assert parsed["os"] == "Linux"
        assert parsed["org"] == "Example Corp"

    def test_parse_output_json(self):
        """Test parsing JSON output."""
        tool = ShodanTool()
        import json

        data = {
            "ip_str": "1.2.3.4",
            "hostnames": ["example.com"],
            "ports": [80, 443],
            "os": "Linux",
            "org": "Example Corp",
            "vulns": ["CVE-2021-44228"],
        }
        stdout = json.dumps(data)

        parsed = tool.parse_output(stdout, "")

        assert parsed["ip"] == "1.2.3.4"
        assert "example.com" in parsed["hostnames"]
        assert 80 in parsed["ports"]
        assert "CVE-2021-44228" in parsed["vulns"]

    def test_get_suggestions_with_data(self):
        """Test suggestions when host data found."""
        tool = ShodanTool()
        parsed = {
            "ip": "1.2.3.4",
            "org": "Example Corp",
            "hostnames": ["example.com"],
            "ports": [80, 443, 22],
            "vulns": ["CVE-2021-44228"],
            "services": [
                {"port": 80, "protocol": "tcp", "banner": "Apache/2.4"},
            ],
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("1.2.3.4" in s for s in suggestions)
        assert any("CVE" in s for s in suggestions)

    def test_get_suggestions_empty(self):
        """Test suggestions when no data found."""
        tool = ShodanTool()
        parsed = {
            "ip": None,
            "ports": [],
            "services": [],
            "hostnames": [],
            "org": None,
            "vulns": [],
        }
        suggestions = tool._get_suggestions(parsed)

        assert any("api key" in s.lower() or "no data" in s.lower() for s in suggestions)
