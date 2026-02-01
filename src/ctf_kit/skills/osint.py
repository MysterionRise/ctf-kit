"""
OSINT skill for CTF Kit.

Orchestrates Open Source Intelligence tools for gathering
information about targets, usernames, domains, and more.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, ClassVar

from ctf_kit.skills.base import BaseSkill, SkillResult, register_skill

if TYPE_CHECKING:
    from ctf_kit.integrations.base import ToolResult


@register_skill
class OSINTSkill(BaseSkill):
    """
    Skill for OSINT (Open Source Intelligence) challenges.

    Gathers information about usernames, domains, social media,
    geolocation, and other publicly available data.
    Orchestrates tools like sherlock, theharvester, and web APIs.
    """

    name: ClassVar[str] = "osint"
    description: ClassVar[str] = (
        "Gather open source intelligence including username enumeration, "
        "domain reconnaissance, geolocation, and social media analysis"
    )
    category: ClassVar[str] = "osint"
    tool_names: ClassVar[list[str]] = [
        "sherlock",
        "theharvester",
        "whois",
        "dig",
        "exiftool",
    ]

    # Username patterns for different platforms
    USERNAME_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"@([A-Za-z0-9_]{1,15})\b", "Twitter/X handle"),
        (r"(?:instagram\.com|ig:?\s*)/?([A-Za-z0-9_.]{1,30})", "Instagram"),
        (r"(?:github\.com/|gh:?\s*)([A-Za-z0-9-]{1,39})", "GitHub"),
        (r"(?:linkedin\.com/in/)([A-Za-z0-9-]{1,100})", "LinkedIn"),
        (r"(?:reddit\.com/u(?:ser)?/)([A-Za-z0-9_-]{3,20})", "Reddit"),
        (r"(?:t\.me/)([A-Za-z0-9_]{5,32})", "Telegram"),
    ]

    # Domain/URL patterns
    DOMAIN_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", "URL with domain"),
        (r"\b([a-zA-Z0-9.-]+\.(com|org|net|io|co|info|biz|gov|edu))\b", "Domain"),
        (r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", "IP address"),
    ]

    # Email patterns
    EMAIL_PATTERN: ClassVar[str] = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

    # Geolocation indicators
    GEO_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (
            r"(?:lat(?:itude)?[:\s=]+)?(-?\d{1,3}\.\d+)[,\s]+(?:lon(?:gitude)?[:\s=]+)?(-?\d{1,3}\.\d+)",
            "GPS coordinates",
        ),
        (r"(exif|gps|location|geo)", "Geolocation metadata hint"),
    ]

    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze an OSINT challenge.

        Args:
            path: Path to challenge file (image, text, etc.) or directory

        Returns:
            SkillResult with OSINT findings
        """
        analysis: dict[str, Any] = {
            "usernames": [],
            "domains": [],
            "emails": [],
            "ips": [],
            "social_profiles": [],
            "geolocation": [],
            "metadata": {},
            "keywords": [],
        }
        tool_results: list[ToolResult] = []
        suggestions: list[str] = []
        artifacts: list[Path] = []

        # Handle directory vs file
        if path.is_dir():
            files = [f for f in path.iterdir() if f.is_file() and not f.name.startswith(".")]
        else:
            files = [path]

        if not files:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis=analysis,
                suggestions=["No files found to analyze"],
                confidence=0.0,
            )

        # Analyze each file
        for file_path in files:
            file_analysis = self._analyze_file(file_path)

            # Aggregate findings
            analysis["usernames"].extend(file_analysis.get("usernames", []))
            analysis["domains"].extend(file_analysis.get("domains", []))
            analysis["emails"].extend(file_analysis.get("emails", []))
            analysis["ips"].extend(file_analysis.get("ips", []))
            analysis["social_profiles"].extend(file_analysis.get("social_profiles", []))
            analysis["geolocation"].extend(file_analysis.get("geolocation", []))

            if file_analysis.get("metadata"):
                analysis["metadata"][str(file_path)] = file_analysis["metadata"]

            tool_results.extend(file_analysis.get("tool_results", []))

        # Deduplicate
        analysis["usernames"] = list(set(analysis["usernames"]))
        analysis["domains"] = list(set(analysis["domains"]))
        analysis["emails"] = list(set(analysis["emails"]))
        analysis["ips"] = list(set(analysis["ips"]))

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

    def _analyze_file(self, path: Path) -> dict[str, Any]:
        """Analyze a single file for OSINT data."""
        file_analysis: dict[str, Any] = {
            "path": str(path),
            "usernames": [],
            "domains": [],
            "emails": [],
            "ips": [],
            "social_profiles": [],
            "geolocation": [],
            "metadata": {},
            "tool_results": [],
        }

        # Check if image - analyze metadata
        suffix = path.suffix.lower()
        if suffix in [".jpg", ".jpeg", ".png", ".gif", ".tiff", ".heic"]:
            self._analyze_image_metadata(path, file_analysis)
        else:
            # Analyze as text
            self._analyze_text_content(path, file_analysis)

        return file_analysis

    def _analyze_image_metadata(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Analyze image metadata for OSINT data."""
        exiftool = self.get_tool("exiftool")
        if exiftool and exiftool.is_installed:
            result = exiftool.run(path)
            file_analysis["tool_results"].append(result)

            if result.parsed_data:
                metadata = result.parsed_data.get("metadata", {})
                file_analysis["metadata"] = metadata

                # Extract GPS coordinates
                if "GPSLatitude" in metadata and "GPSLongitude" in metadata:
                    lat = metadata.get("GPSLatitude", "")
                    lon = metadata.get("GPSLongitude", "")
                    file_analysis["geolocation"].append(
                        {
                            "type": "GPS coordinates",
                            "latitude": lat,
                            "longitude": lon,
                            "source": "EXIF",
                        }
                    )

                # Look for other interesting fields
                interesting_fields = [
                    "Artist",
                    "Author",
                    "Creator",
                    "Copyright",
                    "Software",
                    "Make",
                    "Model",
                    "Comment",
                ]
                for field in interesting_fields:
                    if field in metadata:
                        value = str(metadata[field])
                        # Check if value contains usernames/emails
                        self._extract_identifiers(value, file_analysis)

    def _analyze_text_content(self, path: Path, file_analysis: dict[str, Any]) -> None:
        """Analyze text content for OSINT data."""
        try:
            content = path.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            return

        self._extract_identifiers(content, file_analysis)

    def _extract_identifiers(self, content: str, file_analysis: dict[str, Any]) -> None:
        """Extract usernames, emails, domains, etc. from text."""
        # Extract usernames/social profiles
        for pattern, platform in self.USERNAME_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                file_analysis["social_profiles"].append(
                    {
                        "platform": platform,
                        "username": match,
                    }
                )
                file_analysis["usernames"].append(match)

        # Extract emails
        emails = re.findall(self.EMAIL_PATTERN, content)
        file_analysis["emails"].extend(emails)
        # Extract username from email
        for email in emails:
            username = email.split("@")[0]
            if username not in file_analysis["usernames"]:
                file_analysis["usernames"].append(username)

        # Extract domains and IPs
        for pattern, pattern_type in self.DOMAIN_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]

                if pattern_type == "IP address":
                    file_analysis["ips"].append(match)
                else:
                    file_analysis["domains"].append(match)

        # Extract geolocation
        for pattern, geo_type in self.GEO_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if geo_type == "GPS coordinates" and isinstance(match, tuple):
                    file_analysis["geolocation"].append(
                        {
                            "type": geo_type,
                            "latitude": match[0],
                            "longitude": match[1],
                        }
                    )

    def _generate_suggestions(self, analysis: dict[str, Any]) -> list[str]:
        """Generate suggestions based on OSINT analysis."""
        suggestions: list[str] = []

        # Username suggestions
        if analysis.get("usernames"):
            usernames = analysis["usernames"][:5]
            suggestions.append(
                f"Found {len(analysis['usernames'])} usernames: {', '.join(usernames)}"
            )
            suggestions.append("Run sherlock to find accounts: sherlock <username>")

        # Social profile suggestions
        if analysis.get("social_profiles"):
            platforms = {p["platform"] for p in analysis["social_profiles"]}
            suggestions.append(f"Social profiles found on: {', '.join(platforms)}")
            suggestions.append("Visit profiles to find more information")

        # Email suggestions
        if analysis.get("emails"):
            suggestions.append(f"Found {len(analysis['emails'])} email addresses")
            suggestions.append("Check email with haveibeenpwned.com")
            suggestions.append("Try email OSINT tools like holehe")

        # Domain suggestions
        if analysis.get("domains"):
            suggestions.append(f"Found {len(analysis['domains'])} domains")
            suggestions.append("Run whois and DNS enumeration")
            suggestions.append("Check web archive: web.archive.org")

        # IP suggestions
        if analysis.get("ips"):
            suggestions.append(f"Found {len(analysis['ips'])} IP addresses")
            suggestions.append("Geolocate IPs with ip-api.com or ipinfo.io")
            suggestions.append("Check Shodan for exposed services")

        # Geolocation suggestions
        if analysis.get("geolocation"):
            for geo in analysis["geolocation"][:2]:
                lat = geo.get("latitude")
                lon = geo.get("longitude")
                if lat and lon:
                    suggestions.append(f"GPS coordinates found: {lat}, {lon}")
                    suggestions.append(f"View on map: https://maps.google.com/?q={lat},{lon}")

        # Metadata suggestions
        if analysis.get("metadata"):
            suggestions.append("Image metadata found - check for camera info and timestamps")

        if not suggestions:
            suggestions = [
                "No obvious OSINT data found in files",
                "Try analyzing images for hidden metadata",
                "Look for usernames in challenge description",
                "Check if challenge name is a username",
            ]

        return suggestions

    def _generate_next_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate ordered next steps for solving."""
        steps: list[str] = []

        if analysis.get("usernames"):
            steps.append("Run username enumeration with sherlock")
            steps.append("Check discovered social profiles")

        if analysis.get("emails"):
            steps.append("Check emails on haveibeenpwned and similar services")

        if analysis.get("domains"):
            steps.append("Run whois on domains")
            steps.append("Check DNS records with dig/nslookup")
            steps.append("Look for web archive snapshots")

        if analysis.get("geolocation"):
            steps.append("Map coordinates and identify location")
            steps.append("Search for nearby landmarks")

        if analysis.get("ips"):
            steps.append("Geolocate IP addresses")
            steps.append("Check Shodan/Censys for services")

        steps.extend(
            [
                "Cross-reference findings across platforms",
                "Look for flag in discovered information",
            ]
        )

        return steps

    def _calculate_confidence(self, analysis: dict[str, Any]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0

        if analysis.get("usernames"):
            confidence += 0.2 + (0.02 * min(len(analysis["usernames"]), 5))

        if analysis.get("social_profiles"):
            confidence += 0.15

        if analysis.get("emails"):
            confidence += 0.15

        if analysis.get("domains") or analysis.get("ips"):
            confidence += 0.15

        if analysis.get("geolocation"):
            confidence += 0.2

        if analysis.get("metadata"):
            confidence += 0.1

        return min(confidence, 1.0)

    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """Suggest approaches based on analysis."""
        return self._generate_next_steps(analysis)

    def search_username(self, username: str) -> SkillResult:
        """Search for a username across platforms."""
        sherlock = self.get_tool("sherlock")
        if not sherlock or not sherlock.is_installed:
            return SkillResult(
                success=False,
                skill_name=self.name,
                analysis={"error": "sherlock not installed"},
                suggestions=["Install sherlock: pip install sherlock-project"],
            )

        result = sherlock.run(username)

        return SkillResult(
            success=result.success,
            skill_name=self.name,
            analysis={
                "username": username,
                "found_profiles": result.parsed_data.get("profiles", [])
                if result.parsed_data
                else [],
            },
            tool_results=[result],
            suggestions=["Review discovered profiles for information"],
        )

    def lookup_domain(self, domain: str) -> SkillResult:
        """Perform domain reconnaissance."""
        results: list[ToolResult] = []
        analysis: dict[str, Any] = {"domain": domain}

        # Run theharvester
        harvester = self.get_tool("theharvester")
        if harvester and harvester.is_installed:
            result = harvester.run(domain)
            results.append(result)
            if result.parsed_data:
                analysis["emails"] = result.parsed_data.get("emails", [])
                analysis["subdomains"] = result.parsed_data.get("subdomains", [])

        return SkillResult(
            success=len(results) > 0,
            skill_name=self.name,
            analysis=analysis,
            tool_results=results,
            suggestions=[
                "Check discovered subdomains",
                "Verify email addresses",
                "Run additional DNS enumeration",
            ],
        )
