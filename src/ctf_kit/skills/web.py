"""
Web skill for CTF Kit.

Orchestrates web security tools for analyzing web challenges,
detecting vulnerabilities, and exploiting web applications.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, ClassVar

from ctf_kit.skills.base import BaseSkill, SkillResult, register_skill
from ctf_kit.utils.file_detection import (
    FileInfo,
    detect_file_type,
)

if TYPE_CHECKING:
    from ctf_kit.integrations.base import ToolResult


@register_skill
class WebSkill(BaseSkill):
    """
    Skill for web security challenge analysis.

    Identifies web vulnerabilities, analyzes source code,
    and orchestrates tools like sqlmap, gobuster, ffuf,
    and burp suite helpers.
    """

    name: ClassVar[str] = "web"
    description: ClassVar[str] = (
        "Analyze web security challenges including SQL injection, XSS, "
        "authentication bypass, and other web vulnerabilities"
    )
    category: ClassVar[str] = "web"
    tool_names: ClassVar[list[str]] = [
        "sqlmap",
        "gobuster",
        "ffuf",
        "strings",
        "file",
    ]

    # Common vulnerability patterns
    VULN_PATTERNS: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "sqli": [
            (r"SELECT\s+.+\s+FROM", "SQL SELECT statement"),
            (r"INSERT\s+INTO", "SQL INSERT statement"),
            (r"UNION\s+SELECT", "UNION-based SQL injection"),
            (r"ORDER\s+BY\s+\d+", "ORDER BY injection"),
            (r"'.*OR.*'.*=.*'", "OR-based SQL injection"),
            (r"mysqli?_query\s*\(", "Direct SQL query execution"),
            (r"cursor\.execute\s*\(", "Python SQL execution"),
        ],
        "xss": [
            (r"<script[^>]*>", "Script tag"),
            (r"javascript:", "JavaScript protocol"),
            (r"on\w+\s*=", "Event handler attribute"),
            (r"document\.cookie", "Cookie access"),
            (r"innerHTML\s*=", "innerHTML assignment"),
            (r"\.html\s*\(", "jQuery html() method"),
        ],
        "command_injection": [
            (r"exec\s*\(", "exec() function"),
            (r"system\s*\(", "system() function"),
            (r"shell_exec\s*\(", "shell_exec() function"),
            (r"passthru\s*\(", "passthru() function"),
            (r"subprocess\.", "Python subprocess"),
            (r"os\.system\s*\(", "Python os.system()"),
            (r"`.*\$.*`", "Backtick command execution"),
        ],
        "path_traversal": [
            (r"\.\./", "Directory traversal"),
            (r"file_get_contents\s*\(", "File read function"),
            (r"include\s*\(", "PHP include"),
            (r"require\s*\(", "PHP require"),
            (r"open\s*\([^)]*\+", "Python file open"),
        ],
        "ssti": [
            (r"\{\{.*\}\}", "Template expression"),
            (r"\{%.*%\}", "Template tag"),
            (r"\$\{.*\}", "Expression language"),
            (r"render_template_string", "Flask render_template_string"),
        ],
        "auth": [
            (r"password\s*[=:]\s*['\"]", "Hardcoded password"),
            (r"admin\s*[=:]\s*['\"]", "Hardcoded admin"),
            (r"jwt\.decode\s*\(", "JWT decoding"),
            (r"session\[", "Session manipulation"),
            (r"pickle\.loads", "Pickle deserialization"),
        ],
    }

    # Common web file types
    WEB_EXTENSIONS: ClassVar[list[str]] = [
        ".php",
        ".html",
        ".htm",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".py",
        ".rb",
        ".sql",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".env",
        ".config",
    ]

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze a web security challenge.

        Args:
            path: Path to challenge file, directory, or URL file

        Returns:
            SkillResult with web security analysis
        """
        analysis: dict[str, Any] = {
            "file_type": None,
            "vulnerabilities": [],
            "interesting_patterns": [],
            "endpoints": [],
            "credentials": [],
            "technology_stack": [],
            "source_findings": {},
        }
        tool_results: list[ToolResult] = []
        suggestions: list[str] = []
        artifacts: list[Path] = []

        # Handle directory vs file
        if path.is_dir():
            files = self._find_web_files(path)
        else:
            files = [path]

        if not files:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis=analysis,
                suggestions=["No web-related files found to analyze"],
                confidence=0.0,
            )

        # Analyze each file
        for file_path in files:
            file_analysis = self._analyze_web_file(file_path)

            # Aggregate findings
            analysis["vulnerabilities"].extend(file_analysis.get("vulnerabilities", []))
            analysis["interesting_patterns"].extend(file_analysis.get("patterns", []))
            analysis["endpoints"].extend(file_analysis.get("endpoints", []))
            analysis["credentials"].extend(file_analysis.get("credentials", []))
            analysis["technology_stack"].extend(file_analysis.get("technologies", []))
            analysis["source_findings"][str(file_path)] = file_analysis

            tool_results.extend(file_analysis.get("tool_results", []))

        # Deduplicate
        analysis["vulnerabilities"] = list(
            {v["type"]: v for v in analysis["vulnerabilities"]}.values()
        )
        analysis["technology_stack"] = list(set(analysis["technology_stack"]))
        analysis["endpoints"] = list(set(analysis["endpoints"]))

        # Generate suggestions
        suggestions = self._generate_suggestions(analysis)
        next_steps = self._generate_next_steps(analysis)

        # Calculate confidence
        confidence = self._calculate_confidence(analysis)

        return SkillResult(
            success=True,
            skill_name=self.name,
            analysis=analysis,
            suggestions=suggestions,
            next_steps=next_steps,
            tool_results=tool_results,
            artifacts=artifacts,
            confidence=confidence,
        )

    def _find_web_files(self, directory: Path) -> list[Path]:
        """Find web-related files in a directory."""
        web_files: list[Path] = []
        for ext in self.WEB_EXTENSIONS:
            web_files.extend(directory.rglob(f"*{ext}"))

        # Also check for files without extensions that might be interesting
        for file_path in directory.iterdir():
            if file_path.is_file() and not file_path.name.startswith("."):
                name_lower = file_path.name.lower()
                if any(kw in name_lower for kw in ["flag", "config", "secret", "admin", "index"]):
                    if file_path not in web_files:
                        web_files.append(file_path)

        return web_files[:50]  # Limit to prevent overwhelming analysis

    def _analyze_web_file(self, path: Path) -> dict[str, Any]:
        """Analyze a single web file for vulnerabilities."""
        file_analysis: dict[str, Any] = {
            "path": str(path),
            "vulnerabilities": [],
            "patterns": [],
            "endpoints": [],
            "credentials": [],
            "technologies": [],
            "tool_results": [],
        }

        # Get file info
        try:
            file_info: FileInfo = detect_file_type(path)
            file_analysis["file_type"] = file_info.file_type
        except Exception:  # noqa: BLE001
            pass

        # Read file content
        try:
            content = path.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            return file_analysis

        # Detect technology stack
        file_analysis["technologies"] = self._detect_technologies(path, content)

        # Scan for vulnerabilities
        for vuln_type, patterns in self.VULN_PATTERNS.items():
            for pattern, description in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    file_analysis["vulnerabilities"].append(
                        {
                            "type": vuln_type,
                            "pattern": description,
                            "file": str(path),
                            "count": len(matches),
                            "samples": matches[:3],
                        }
                    )

        # Extract endpoints/routes
        file_analysis["endpoints"] = self._extract_endpoints(content)

        # Look for credentials
        file_analysis["credentials"] = self._extract_credentials(content)

        # Look for interesting patterns
        file_analysis["patterns"] = self._find_interesting_patterns(content)

        return file_analysis

    def _detect_technologies(self, path: Path, content: str) -> list[str]:
        """Detect web technologies used."""
        technologies: list[str] = []
        content_lower = content.lower()

        # PHP
        if path.suffix == ".php" or "<?php" in content:
            technologies.append("PHP")

        # Python frameworks
        if "flask" in content_lower:
            technologies.append("Flask")
        if "django" in content_lower:
            technologies.append("Django")
        if "fastapi" in content_lower:
            technologies.append("FastAPI")

        # JavaScript frameworks
        if "express" in content_lower:
            technologies.append("Express.js")
        if "react" in content_lower:
            technologies.append("React")
        if "vue" in content_lower:
            technologies.append("Vue.js")
        if "angular" in content_lower:
            technologies.append("Angular")

        # Databases
        if "mysql" in content_lower or "mysqli" in content_lower:
            technologies.append("MySQL")
        if "sqlite" in content_lower:
            technologies.append("SQLite")
        if "postgres" in content_lower:
            technologies.append("PostgreSQL")
        if "mongodb" in content_lower:
            technologies.append("MongoDB")

        # Auth
        if "jwt" in content_lower:
            technologies.append("JWT")
        if "oauth" in content_lower:
            technologies.append("OAuth")

        return technologies

    def _extract_endpoints(self, content: str) -> list[str]:
        """Extract API endpoints and routes from code."""
        endpoints: list[str] = []

        # Flask/Express routes
        route_patterns = [
            r'@app\.route\s*\(\s*["\']([^"\']+)["\']',  # Flask
            r'app\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',  # Express
            r'path\s*\(\s*["\']([^"\']+)["\']',  # Django
            r'router\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',  # Express router
        ]

        for pattern in route_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoints.append(match[-1])  # Get the path part
                else:
                    endpoints.append(match)

        return list(set(endpoints))[:20]

    def _extract_credentials(self, content: str) -> list[dict[str, str]]:
        """Extract potential credentials from code."""
        credentials: list[dict[str, str]] = []

        cred_patterns = [
            (r'password\s*[=:]\s*["\']([^"\']+)["\']', "password"),
            (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "api_key"),
            (r'secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "secret_key"),
            (r'token\s*[=:]\s*["\']([^"\']+)["\']', "token"),
            (r'username\s*[=:]\s*["\']([^"\']+)["\']', "username"),
            (r'admin\s*[=:]\s*["\']([^"\']+)["\']', "admin"),
        ]

        for pattern, cred_type in cred_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 3:  # Filter out very short matches
                    credentials.append(
                        {
                            "type": cred_type,
                            "value": match[:50] + "..." if len(match) > 50 else match,
                        }
                    )

        return credentials[:10]

    def _find_interesting_patterns(self, content: str) -> list[str]:
        """Find other interesting patterns in web code."""
        patterns_found: list[str] = []

        interesting = [
            (r'flag\s*[=:]\s*["\']([^"\']+)["\']', "Flag value found"),
            (r"DEBUG\s*=\s*True", "Debug mode enabled"),
            (r"verify\s*=\s*False", "SSL verification disabled"),
            (r"eval\s*\(", "eval() function used"),
            (r"unserialize\s*\(", "PHP unserialize used"),
            (r"render_template_string", "SSTI-vulnerable function"),
            (r"safe\s*filter", "Jinja2 safe filter"),
            (r"innerHTML", "innerHTML used (XSS risk)"),
            (r"\$_GET\s*\[", "Direct $_GET usage"),
            (r"\$_POST\s*\[", "Direct $_POST usage"),
        ]

        for pattern, description in interesting:
            if re.search(pattern, content, re.IGNORECASE):
                patterns_found.append(description)

        return patterns_found

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on web analysis."""
        suggestions: list[str] = []

        # Vulnerability-specific suggestions
        vuln_types = {v["type"] for v in analysis.get("vulnerabilities", [])}

        if "sqli" in vuln_types:
            suggestions.extend(
                [
                    "SQL injection detected - try sqlmap: sqlmap -u 'URL' --dbs",
                    "Test UNION-based injection: ' UNION SELECT 1,2,3--",
                    "Try time-based blind SQLi: ' AND SLEEP(5)--",
                ]
            )

        if "xss" in vuln_types:
            suggestions.extend(
                [
                    "XSS vulnerability detected",
                    "Test with: <script>alert(1)</script>",
                    "Try event handlers: <img src=x onerror=alert(1)>",
                ]
            )

        if "command_injection" in vuln_types:
            suggestions.extend(
                [
                    "Command injection possible",
                    "Test with: ; id, | id, $(id), `id`",
                    "Try to read files: ; cat /etc/passwd",
                ]
            )

        if "ssti" in vuln_types:
            suggestions.extend(
                [
                    "Server-Side Template Injection detected",
                    "Test with: {{7*7}}, ${7*7}, <%= 7*7 %>",
                    "Python SSTI: {{config}}, {{self.__class__.__mro__}}",
                ]
            )

        if "path_traversal" in vuln_types:
            suggestions.extend(
                [
                    "Path traversal possible",
                    "Try: ../../../etc/passwd",
                    "Windows: ..\\..\\..\\windows\\win.ini",
                ]
            )

        if "auth" in vuln_types:
            suggestions.extend(
                [
                    "Authentication weaknesses found",
                    "Check for hardcoded credentials",
                    "Test JWT token manipulation",
                ]
            )

        # Add technology-specific suggestions
        technologies = analysis.get("technology_stack", [])
        if "Flask" in technologies:
            suggestions.append("Flask app - check for debug mode and SSTI")
        if "PHP" in technologies:
            suggestions.append("PHP app - check for type juggling and deserialization")
        if "JWT" in technologies:
            suggestions.append("JWT found - try 'none' algorithm attack")

        # Endpoint suggestions
        if analysis.get("endpoints"):
            count = len(analysis["endpoints"])
            suggestions.append(f"Found {count} endpoints - test each for vulnerabilities")

        # Credential suggestions
        if analysis.get("credentials"):
            suggestions.insert(0, "Credentials/secrets found in source code!")

        if not suggestions:
            suggestions = [
                "No obvious vulnerabilities detected",
                "Try directory enumeration with gobuster/ffuf",
                "Check for robots.txt and .git exposure",
                "Test authentication mechanisms manually",
            ]

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []

        steps.append("Review source code for vulnerabilities")

        if analysis.get("credentials"):
            steps.insert(0, "Try found credentials to authenticate")

        if analysis.get("vulnerabilities"):
            steps.append("Exploit identified vulnerabilities")

        steps.extend(
            [
                "Enumerate directories and files",
                "Check for sensitive file exposure (.git, .env, backup files)",
                "Test input validation on all parameters",
                "Inspect cookies and session handling",
                "Check for IDOR vulnerabilities",
            ]
        )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        if analysis.get("vulnerabilities"):
            confidence += 0.3 + (0.05 * min(len(analysis["vulnerabilities"]), 4))

        if analysis.get("technology_stack"):
            confidence += 0.15

        if analysis.get("endpoints"):
            confidence += 0.1

        if analysis.get("credentials"):
            confidence += 0.2

        if analysis.get("interesting_patterns"):
            confidence += 0.1

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def scan_url(self, url: str, wordlist: str | None = None) -> SkillResult:
        """Scan a URL for common vulnerabilities."""
        gobuster = self.get_tool("gobuster")
        results: list[ToolResult] = []

        if gobuster and gobuster.is_installed:
            result = gobuster.run(url, wordlist=wordlist)
            results.append(result)

        return SkillResult(
            success=len(results) > 0,
            skill_name=self.name,
            analysis={
                "url": url,
                "scan_results": [r.parsed_data for r in results if r.parsed_data],
            },
            tool_results=results,
            suggestions=["Review discovered paths", "Test each endpoint for vulnerabilities"],
        )
