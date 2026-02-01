"""
SQLMap wrapper for CTF Kit.

SQLMap is an automated SQL injection and database takeover tool.
"""

import re
from typing import Any, ClassVar

from ctf_kit.integrations.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    register_tool,
)


@register_tool
class SqlmapTool(BaseTool):
    """
    Wrapper for the 'sqlmap' command.

    SQLMap automates the detection and exploitation of SQL injection
    vulnerabilities.
    """

    name: ClassVar[str] = "sqlmap"
    description: ClassVar[str] = "Automated SQL injection and database takeover"
    category: ClassVar[ToolCategory] = ToolCategory.WEB
    binary_names: ClassVar[list[str]] = ["sqlmap", "sqlmap.py"]
    install_commands: ClassVar[dict[str, str]] = {
        "darwin": "pip install sqlmap",
        "linux": "pip install sqlmap",
        "windows": "pip install sqlmap",
    }

    def run(  # noqa: PLR0913
        self,
        url: str | None = None,
        data: str | None = None,
        cookie: str | None = None,
        param: str | None = None,
        dbs: bool = False,
        tables: bool = False,
        columns: bool = False,
        dump: bool = False,
        database: str | None = None,
        table: str | None = None,
        batch: bool = True,
        level: int = 1,
        risk: int = 1,
        timeout: int = 300,
    ) -> ToolResult:
        """
        Run SQL injection testing.

        Args:
            url: Target URL with injection point
            data: POST data
            cookie: Cookie header value
            param: Parameter to test
            dbs: Enumerate databases
            tables: Enumerate tables
            columns: Enumerate columns
            dump: Dump table contents
            database: Database name for enumeration
            table: Table name for enumeration
            batch: Non-interactive mode
            level: Level of tests (1-5)
            risk: Risk of tests (1-3)
            timeout: Timeout in seconds

        Returns:
            ToolResult with injection findings
        """
        args: list[str] = []

        if url:
            args.extend(["-u", url])

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        if param:
            args.extend(["-p", param])

        if dbs:
            args.append("--dbs")

        if tables:
            args.append("--tables")
            if database:
                args.extend(["-D", database])

        if columns:
            args.append("--columns")
            if database:
                args.extend(["-D", database])
            if table:
                args.extend(["-T", table])

        if dump:
            args.append("--dump")
            if database:
                args.extend(["-D", database])
            if table:
                args.extend(["-T", table])

        args.extend(["--level", str(level)])
        args.extend(["--risk", str(risk)])

        if batch:
            args.append("--batch")

        result = self._run_with_result(args, timeout=timeout)

        # Add suggestions
        if result.success:
            result.suggestions = self._get_suggestions(result.parsed_data or {})

        return result

    def parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse sqlmap output into structured data."""
        combined = stdout + stderr
        parsed: dict[str, Any] = {
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "vulnerable": False,
            "injection_type": None,
            "databases": [],
            "tables": [],
            "columns": [],
            "data": [],
        }

        # Check if vulnerable
        if "is vulnerable" in combined.lower() or "injectable" in combined.lower():
            parsed["vulnerable"] = True

        # Parse injection type
        injection_types = [
            "boolean-based blind",
            "time-based blind",
            "UNION query",
            "error-based",
            "stacked queries",
        ]
        for inj_type in injection_types:
            if inj_type.lower() in combined.lower():
                parsed["injection_type"] = inj_type
                break

        # Parse databases
        db_pattern = re.compile(r"\[\*\]\s+(\w+)")
        if "available databases" in combined.lower():
            dbs = db_pattern.findall(combined)
            parsed["databases"] = dbs

        # Parse tables
        table_pattern = re.compile(r"\[\*\]\s+(\w+)")
        if "tables:" in combined.lower():
            tables = table_pattern.findall(combined)
            parsed["tables"] = tables

        return parsed

    def _get_suggestions(self, parsed_data: dict[str, Any]) -> list[str]:
        """Get suggestions based on results."""
        suggestions: list[str] = []

        if parsed_data.get("vulnerable"):
            suggestions.append("SQL injection confirmed!")
            if parsed_data.get("injection_type"):
                suggestions.append(f"Type: {parsed_data['injection_type']}")
            suggestions.extend(
                [
                    "Enumerate databases: --dbs",
                    "Enumerate tables: --tables -D <database>",
                    "Dump data: --dump -D <database> -T <table>",
                ]
            )
        else:
            suggestions.extend(
                [
                    "No SQL injection found with current settings",
                    "Try higher level: --level=5",
                    "Try higher risk: --risk=3",
                    "Check if parameter is correct: -p <param>",
                ]
            )

        if parsed_data.get("databases"):
            dbs = parsed_data["databases"]
            suggestions.append(f"Found databases: {', '.join(dbs[:5])}")

        return suggestions

    def test_url(self, url: str, level: int = 1) -> ToolResult:
        """Test a URL for SQL injection."""
        return self.run(url=url, level=level)

    def enumerate_dbs(self, url: str) -> ToolResult:
        """Enumerate databases."""
        return self.run(url=url, dbs=True)

    def enumerate_tables(self, url: str, database: str) -> ToolResult:
        """Enumerate tables in a database."""
        return self.run(url=url, tables=True, database=database)

    def dump_table(self, url: str, database: str, table: str) -> ToolResult:
        """Dump contents of a table."""
        return self.run(url=url, dump=True, database=database, table=table)
