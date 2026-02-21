"""Tests for extended CTF Kit skills (forensics, misc, osint, pwn, reversing, stego, web)."""

import base64
from pathlib import Path

from ctf_kit.skills.base import SkillResult, get_all_skills, get_skill
from ctf_kit.skills.forensics import ForensicsSkill
from ctf_kit.skills.misc import MiscSkill
from ctf_kit.skills.osint import OSINTSkill
from ctf_kit.skills.pwn import PwnSkill
from ctf_kit.skills.reversing import ReversingSkill
from ctf_kit.skills.stego import StegoSkill
from ctf_kit.skills.web import WebSkill


# ---------------------------------------------------------------------------
# ForensicsSkill
# ---------------------------------------------------------------------------


class TestForensicsSkill:
    """Tests for ForensicsSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = ForensicsSkill()
        assert skill.name == "forensics"
        assert skill.description
        assert skill.category == "forensics"
        assert "binwalk" in skill.tool_names
        assert "strings" in skill.tool_names
        assert "file" in skill.tool_names
        assert "exiftool" in skill.tool_names
        assert "volatility" in skill.tool_names
        assert "tshark" in skill.tool_names
        assert "foremost" in skill.tool_names

    def test_analyze_file(self, tmp_path: Path):
        """Test analyzing a single forensics file."""
        test_file = tmp_path / "capture.pcap"
        # Write pcap magic bytes followed by some filler data
        test_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 200)

        skill = ForensicsSkill()
        result = skill.analyze(test_file)

        assert isinstance(result, SkillResult)
        assert result.success
        assert result.skill_name == "forensics"
        assert "forensics_type" in result.analysis
        assert "file_info" in result.analysis

    def test_analyze_directory(self, tmp_path: Path):
        """Test analyzing a directory with multiple files."""
        (tmp_path / "evidence1.raw").write_bytes(b"\x00" * 100)
        (tmp_path / "evidence2.txt").write_text("some log data")

        skill = ForensicsSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert result.skill_name == "forensics"
        assert len(result.analysis["file_info"]) == 2

    def test_analyze_empty_directory(self, tmp_path: Path):
        """Test analyzing an empty directory returns unsuccessful result."""
        skill = ForensicsSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No files found" in result.suggestions[0]

    def test_suggest_approach(self):
        """Test suggest_approach returns next steps based on analysis."""
        skill = ForensicsSkill()
        analysis = {"forensics_type": "memory"}
        approaches = skill.suggest_approach(analysis)

        assert isinstance(approaches, list)
        assert len(approaches) > 0
        # Memory-specific steps should include process listing
        assert any("process" in step.lower() for step in approaches)

    def test_suggest_approach_network(self):
        """Test suggest_approach for network forensics."""
        skill = ForensicsSkill()
        analysis = {"forensics_type": "network"}
        approaches = skill.suggest_approach(analysis)

        assert isinstance(approaches, list)
        assert any("tcp" in step.lower() or "stream" in step.lower() for step in approaches)

    def test_detect_forensics_type_memory(self, tmp_path: Path):
        """Test detection of memory dump type from file name."""
        skill = ForensicsSkill()

        mem_file = tmp_path / "system.vmem"
        mem_file.write_bytes(b"\x00" * 10)
        assert skill._detect_forensics_type(mem_file, None) == "memory"

        dmp_file = tmp_path / "crash.dmp"
        dmp_file.write_bytes(b"\x00" * 10)
        assert skill._detect_forensics_type(dmp_file, None) == "memory"

    def test_detect_forensics_type_network(self, tmp_path: Path):
        """Test detection of network capture type from file name."""
        skill = ForensicsSkill()

        pcap_file = tmp_path / "traffic.pcap"
        pcap_file.write_bytes(b"\x00" * 10)
        assert skill._detect_forensics_type(pcap_file, None) == "network"

        pcapng_file = tmp_path / "trace.pcapng"
        pcapng_file.write_bytes(b"\x00" * 10)
        assert skill._detect_forensics_type(pcapng_file, None) == "network"

    def test_detect_forensics_type_disk(self, tmp_path: Path):
        """Test detection of disk image type from file name."""
        skill = ForensicsSkill()

        e01_file = tmp_path / "disk.e01"
        e01_file.write_bytes(b"\x00" * 10)
        assert skill._detect_forensics_type(e01_file, None) == "disk"

        img_file = tmp_path / "partition.img"
        img_file.write_bytes(b"\x00" * 10)
        assert skill._detect_forensics_type(img_file, None) == "disk"

    def test_detect_forensics_type_general(self, tmp_path: Path):
        """Test that unknown files are classified as general."""
        skill = ForensicsSkill()

        generic_file = tmp_path / "unknown.bin"
        generic_file.write_bytes(b"\x00" * 10)
        assert skill._detect_forensics_type(generic_file, None) == "general"

    def test_generate_suggestions_memory(self):
        """Test suggestions generated for memory forensics."""
        skill = ForensicsSkill()
        analysis = {"forensics_type": "memory", "embedded_files": [], "interesting_strings": []}

        suggestions = skill._generate_suggestions(analysis)
        assert any("volatility" in s.lower() for s in suggestions)

    def test_generate_suggestions_with_embedded(self):
        """Test suggestions include embedded file count."""
        skill = ForensicsSkill()
        analysis = {
            "forensics_type": "general",
            "embedded_files": [{"sig": "zip"}, {"sig": "png"}],
            "interesting_strings": [],
        }

        suggestions = skill._generate_suggestions(analysis)
        assert any("2 embedded" in s for s in suggestions)

    def test_calculate_confidence(self):
        """Test confidence calculation covers various factors."""
        skill = ForensicsSkill()

        # Minimal analysis should have low confidence
        empty_analysis = {
            "forensics_type": None,
            "file_info": {},
            "embedded_files": [],
            "interesting_strings": [],
            "metadata": {},
        }
        assert skill._calculate_confidence(empty_analysis) == 0.0

        # Full analysis should have high confidence
        rich_analysis = {
            "forensics_type": "network",
            "file_info": {"test.pcap": {}},
            "embedded_files": [{"sig": "http"}],
            "interesting_strings": ["flag"],
            "metadata": {"comment": "test"},
        }
        confidence = skill._calculate_confidence(rich_analysis)
        assert confidence > 0.5

    def test_constants(self):
        """Test that forensics constants are defined."""
        assert len(ForensicsSkill.MEMORY_INDICATORS) > 0
        assert "vmem" in ForensicsSkill.MEMORY_INDICATORS
        assert len(ForensicsSkill.NETWORK_INDICATORS) > 0
        assert "pcap" in ForensicsSkill.NETWORK_INDICATORS
        assert len(ForensicsSkill.DISK_INDICATORS) > 0
        assert "e01" in ForensicsSkill.DISK_INDICATORS

    def test_registry(self):
        """Test that ForensicsSkill is registered."""
        skill = get_skill("forensics")
        assert skill is not None
        assert isinstance(skill, ForensicsSkill)


# ---------------------------------------------------------------------------
# MiscSkill
# ---------------------------------------------------------------------------


class TestMiscSkill:
    """Tests for MiscSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = MiscSkill()
        assert skill.name == "misc"
        assert skill.description
        assert skill.category == "misc"
        assert "file" in skill.tool_names
        assert "strings" in skill.tool_names
        assert "binwalk" in skill.tool_names
        assert "exiftool" in skill.tool_names
        assert "zbarimg" in skill.tool_names

    def test_analyze_base64_file(self, tmp_path: Path):
        """Test analyzing a file containing base64-encoded data."""
        test_file = tmp_path / "encoded.txt"
        encoded = base64.b64encode(b"flag{test_flag_value}").decode()
        test_file.write_text(encoded)

        skill = MiscSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert result.skill_name == "misc"
        # Should detect base64 encoding
        encodings = result.analysis.get("detected_encodings", [])
        assert any(e["type"] == "base64" for e in encodings)

    def test_analyze_flag_in_file(self, tmp_path: Path):
        """Test analyzing a file that directly contains a flag."""
        test_file = tmp_path / "challenge.txt"
        test_file.write_text("The answer is flag{found_it_123}")

        skill = MiscSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert "flag{found_it_123}" in result.analysis.get("flags_found", [])
        # Confidence should be 1.0 when flag found
        assert result.confidence == 1.0

    def test_analyze_directory(self, tmp_path: Path):
        """Test analyzing a directory with multiple files."""
        (tmp_path / "file1.txt").write_text("SGVsbG8gV29ybGQ=")
        (tmp_path / "file2.txt").write_text("flag{multi_file}")

        skill = MiscSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["file_info"]) == 2
        assert "flag{multi_file}" in result.analysis["flags_found"]

    def test_analyze_empty_directory(self, tmp_path: Path):
        """Test analyzing empty directory returns unsuccessful result."""
        skill = MiscSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No files found" in result.suggestions[0]

    def test_suggest_approach_with_encodings(self):
        """Test suggest_approach when encodings are detected."""
        skill = MiscSkill()
        analysis = {
            "detected_encodings": [{"type": "base64"}],
            "esoteric_language": None,
            "qr_codes": [],
            "flags_found": [],
        }

        approaches = skill.suggest_approach(analysis)
        assert isinstance(approaches, list)
        assert any("decode" in s.lower() for s in approaches)

    def test_suggest_approach_with_flag(self):
        """Test suggest_approach when flag is already found."""
        skill = MiscSkill()
        analysis = {
            "detected_encodings": [],
            "esoteric_language": None,
            "qr_codes": [],
            "flags_found": ["flag{test}"],
        }

        approaches = skill.suggest_approach(analysis)
        assert approaches[0] == "Verify the flag format and submit"

    def test_try_decode_base64(self):
        """Test base64 decoding."""
        skill = MiscSkill()
        encoded = base64.b64encode(b"Hello World").decode()
        decoded = skill._try_decode(encoded, "base64")
        assert decoded == "Hello World"

    def test_try_decode_hex(self):
        """Test hexadecimal decoding."""
        skill = MiscSkill()
        hex_text = "48656c6c6f"  # "Hello"
        decoded = skill._try_decode(hex_text, "base16")
        assert decoded == "Hello"

    def test_try_decode_binary(self):
        """Test binary string decoding."""
        skill = MiscSkill()
        # "Hi" in binary
        binary_text = "0100100001101001"
        decoded = skill._try_decode(binary_text, "binary")
        assert decoded == "Hi"

    def test_try_decode_invalid(self):
        """Test decoding invalid data returns None."""
        skill = MiscSkill()
        result = skill._try_decode("not valid base64!!!", "base64")
        assert result is None

    def test_is_readable(self):
        """Test readability check for decoded text."""
        skill = MiscSkill()
        assert skill._is_readable("Hello World!")
        assert skill._is_readable("flag{test}")
        assert not skill._is_readable("")
        assert not skill._is_readable("\x00\x01\x02\x03")

    def test_identify_encoding_base64(self):
        """Test encoding identification for base64."""
        skill = MiscSkill()
        matches = skill.identify_encoding("SGVsbG8gV29ybGQ=")
        types = [m["type"] for m in matches]
        assert "base64" in types

    def test_identify_encoding_hex(self):
        """Test encoding identification for hex."""
        skill = MiscSkill()
        matches = skill.identify_encoding("48656c6c6f")
        types = [m["type"] for m in matches]
        assert "base16" in types

    def test_decode_chain(self):
        """Test decoding through a chain of encodings."""
        skill = MiscSkill()
        # Double-encode: first hex-encode "Hi", then base64-encode the hex
        hex_encoded = "4869"  # "Hi" in hex
        b64_of_hex = base64.b64encode(hex_encoded.encode()).decode()

        # Decode chain: base64 -> base16
        result = skill.decode_chain(b64_of_hex, ["base64", "base16"])
        assert result == "Hi"

    def test_encoding_patterns_defined(self):
        """Test that encoding patterns constants are populated."""
        assert "base64" in MiscSkill.ENCODING_PATTERNS
        assert "base32" in MiscSkill.ENCODING_PATTERNS
        assert "base16" in MiscSkill.ENCODING_PATTERNS
        assert "binary" in MiscSkill.ENCODING_PATTERNS

    def test_esoteric_patterns_defined(self):
        """Test that esoteric language patterns are populated."""
        assert "brainfuck" in MiscSkill.ESOTERIC_PATTERNS
        assert "ook" in MiscSkill.ESOTERIC_PATTERNS
        assert "whitespace" in MiscSkill.ESOTERIC_PATTERNS

    def test_flag_patterns_defined(self):
        """Test that flag patterns are populated."""
        assert len(MiscSkill.FLAG_PATTERNS) > 0
        # At least the common formats
        assert any("flag" in p for p in MiscSkill.FLAG_PATTERNS)
        assert any("CTF" in p for p in MiscSkill.FLAG_PATTERNS)

    def test_analyze_text_content_esoteric(self):
        """Test detection of esoteric language (brainfuck)."""
        skill = MiscSkill()
        file_analysis: dict = {
            "encodings": [],
            "esoteric_language": None,
            "flags": [],
            "patterns": [],
            "decoded": [],
        }
        brainfuck_code = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>."
        skill._analyze_text_content(brainfuck_code, file_analysis)

        assert file_analysis["esoteric_language"] is not None
        assert file_analysis["esoteric_language"]["type"] == "brainfuck"

    def test_analyze_binary_content_flag(self):
        """Test extraction of flags from binary content."""
        skill = MiscSkill()
        file_analysis: dict = {"flags": [], "patterns": []}
        binary_data = b"\x00\x00flag{binary_hidden}\x00\x00"
        skill._analyze_binary_content(binary_data, file_analysis)

        assert "flag{binary_hidden}" in file_analysis["flags"]

    def test_calculate_confidence_no_findings(self):
        """Test confidence is zero with no findings."""
        skill = MiscSkill()
        empty_analysis = {
            "flags_found": [],
            "qr_codes": [],
            "detected_encodings": [],
            "decoded_attempts": [],
            "esoteric_language": None,
            "interesting_patterns": [],
        }
        assert skill._calculate_confidence(empty_analysis) == 0.0

    def test_registry(self):
        """Test that MiscSkill is registered."""
        skill = get_skill("misc")
        assert skill is not None
        assert isinstance(skill, MiscSkill)


# ---------------------------------------------------------------------------
# OSINTSkill
# ---------------------------------------------------------------------------


class TestOSINTSkill:
    """Tests for OSINTSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = OSINTSkill()
        assert skill.name == "osint"
        assert skill.description
        assert skill.category == "osint"
        assert "sherlock" in skill.tool_names
        assert "theharvester" in skill.tool_names
        assert "whois" in skill.tool_names
        assert "dig" in skill.tool_names
        assert "exiftool" in skill.tool_names

    def test_analyze_file_with_email(self, tmp_path: Path):
        """Test analyzing a file that contains email addresses."""
        test_file = tmp_path / "info.txt"
        test_file.write_text("Contact: admin@example.com for more details.")

        skill = OSINTSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert result.skill_name == "osint"
        assert "admin@example.com" in result.analysis["emails"]
        # Username extracted from email
        assert "admin" in result.analysis["usernames"]

    def test_analyze_file_with_domain(self, tmp_path: Path):
        """Test analyzing a file that contains domain names."""
        test_file = tmp_path / "challenge.txt"
        test_file.write_text("Check out https://ctf.example.com/flag for details")

        skill = OSINTSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert any("ctf.example.com" in d for d in result.analysis["domains"])

    def test_analyze_file_with_ip(self, tmp_path: Path):
        """Test analyzing a file that contains IP addresses."""
        test_file = tmp_path / "hosts.txt"
        test_file.write_text("Server at 192.168.1.100\nBackup at 10.0.0.5")

        skill = OSINTSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert "192.168.1.100" in result.analysis["ips"]
        assert "10.0.0.5" in result.analysis["ips"]

    def test_analyze_file_with_gps(self, tmp_path: Path):
        """Test analyzing a file with GPS coordinates."""
        test_file = tmp_path / "coords.txt"
        test_file.write_text("latitude: 40.7128, longitude: -74.0060")

        skill = OSINTSkill()
        result = skill.analyze(test_file)

        assert result.success
        assert len(result.analysis["geolocation"]) > 0

    def test_analyze_directory(self, tmp_path: Path):
        """Test analyzing a directory with multiple OSINT files."""
        (tmp_path / "file1.txt").write_text("user@test.com")
        (tmp_path / "file2.txt").write_text("Visit https://target.org")

        skill = OSINTSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["emails"]) > 0
        assert len(result.analysis["domains"]) > 0

    def test_analyze_empty_directory(self, tmp_path: Path):
        """Test analyzing empty directory returns unsuccessful result."""
        skill = OSINTSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No files found" in result.suggestions[0]

    def test_suggest_approach_with_usernames(self):
        """Test suggest_approach when usernames are found."""
        skill = OSINTSkill()
        analysis = {
            "usernames": ["john_doe"],
            "domains": [],
            "emails": [],
            "ips": [],
            "geolocation": [],
        }

        approaches = skill.suggest_approach(analysis)
        assert isinstance(approaches, list)
        assert any("sherlock" in s.lower() or "username" in s.lower() for s in approaches)

    def test_suggest_approach_with_domains(self):
        """Test suggest_approach when domains are found."""
        skill = OSINTSkill()
        analysis = {
            "usernames": [],
            "domains": ["example.com"],
            "emails": [],
            "ips": [],
            "geolocation": [],
        }

        approaches = skill.suggest_approach(analysis)
        assert any("whois" in s.lower() or "dns" in s.lower() for s in approaches)

    def test_extract_identifiers_social_profiles(self):
        """Test extraction of social media profiles."""
        skill = OSINTSkill()
        file_analysis: dict = {
            "usernames": [],
            "domains": [],
            "emails": [],
            "ips": [],
            "social_profiles": [],
            "geolocation": [],
        }
        content = "Follow me at github.com/hacker123 and @ctfplayer on Twitter"
        skill._extract_identifiers(content, file_analysis)

        assert "hacker123" in file_analysis["usernames"]
        assert "ctfplayer" in file_analysis["usernames"]
        assert any(p["platform"] == "GitHub" for p in file_analysis["social_profiles"])
        assert any(p["platform"] == "Twitter/X handle" for p in file_analysis["social_profiles"])

    def test_extract_identifiers_emails(self):
        """Test extraction of email addresses from text."""
        skill = OSINTSkill()
        file_analysis: dict = {
            "usernames": [],
            "domains": [],
            "emails": [],
            "ips": [],
            "social_profiles": [],
            "geolocation": [],
        }
        content = "Send to alice@company.io and bob@test.org"
        skill._extract_identifiers(content, file_analysis)

        assert "alice@company.io" in file_analysis["emails"]
        assert "bob@test.org" in file_analysis["emails"]
        # Usernames extracted from emails
        assert "alice" in file_analysis["usernames"]
        assert "bob" in file_analysis["usernames"]

    def test_extract_identifiers_gps_coordinates(self):
        """Test extraction of GPS coordinates from text."""
        skill = OSINTSkill()
        file_analysis: dict = {
            "usernames": [],
            "domains": [],
            "emails": [],
            "ips": [],
            "social_profiles": [],
            "geolocation": [],
        }
        content = "latitude: 51.5074, longitude: -0.1278"
        skill._extract_identifiers(content, file_analysis)

        assert len(file_analysis["geolocation"]) > 0
        geo = file_analysis["geolocation"][0]
        assert geo["type"] == "GPS coordinates"

    def test_calculate_confidence(self):
        """Test confidence calculation with various data."""
        skill = OSINTSkill()

        empty = {
            "usernames": [],
            "social_profiles": [],
            "emails": [],
            "domains": [],
            "ips": [],
            "geolocation": [],
            "metadata": {},
        }
        assert skill._calculate_confidence(empty) == 0.0

        rich = {
            "usernames": ["alice"],
            "social_profiles": [{"platform": "GitHub"}],
            "emails": ["a@b.com"],
            "domains": ["example.com"],
            "ips": [],
            "geolocation": [{"lat": 1, "lon": 2}],
            "metadata": {"some": "data"},
        }
        confidence = skill._calculate_confidence(rich)
        assert confidence > 0.5

    def test_constants(self):
        """Test that OSINT constants are defined."""
        assert len(OSINTSkill.USERNAME_PATTERNS) > 0
        assert len(OSINTSkill.DOMAIN_PATTERNS) > 0
        assert len(OSINTSkill.EMAIL_PATTERN) > 0
        assert len(OSINTSkill.GEO_PATTERNS) > 0

    def test_registry(self):
        """Test that OSINTSkill is registered."""
        skill = get_skill("osint")
        assert skill is not None
        assert isinstance(skill, OSINTSkill)


# ---------------------------------------------------------------------------
# PwnSkill
# ---------------------------------------------------------------------------


class TestPwnSkill:
    """Tests for PwnSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = PwnSkill()
        assert skill.name == "pwn"
        assert skill.description
        assert skill.category == "pwn"
        assert "checksec" in skill.tool_names
        assert "ropgadget" in skill.tool_names
        assert "file" in skill.tool_names
        assert "strings" in skill.tool_names
        assert "objdump" in skill.tool_names
        assert "readelf" in skill.tool_names

    def test_analyze_elf_binary(self, tmp_path: Path):
        """Test analyzing a minimal ELF binary."""
        elf_file = tmp_path / "vuln"
        # Minimal ELF header (enough to be recognised)
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 200)

        skill = PwnSkill()
        result = skill.analyze(elf_file)

        assert isinstance(result, SkillResult)
        assert result.success
        assert result.skill_name == "pwn"

    def test_analyze_directory_filters_binaries(self, tmp_path: Path):
        """Test that directory analysis filters to ELF binaries."""
        # ELF binary
        (tmp_path / "exploit_me").write_bytes(b"\x7fELF" + b"\x00" * 100)
        # Non-binary text file
        (tmp_path / "readme.txt").write_text("This is a text file")
        # Source code should be excluded
        (tmp_path / "exploit.py").write_text("import pwn")

        skill = PwnSkill()
        result = skill.analyze(tmp_path)

        assert result.success

    def test_analyze_no_binaries(self, tmp_path: Path):
        """Test analyzing directory with no binaries fails gracefully."""
        (tmp_path / "notes.txt").write_text("no binary here")

        skill = PwnSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No binary files" in result.suggestions[0]

    def test_suggest_approach(self):
        """Test suggest_approach returns exploitation steps."""
        skill = PwnSkill()
        analysis = {"protections": {"canary": False, "nx": True, "pie": False}}

        approaches = skill.suggest_approach(analysis)
        assert isinstance(approaches, list)
        assert len(approaches) > 0
        # Should suggest running the binary first
        assert any("run" in s.lower() for s in approaches)

    def test_is_likely_binary_elf(self, tmp_path: Path):
        """Test ELF magic byte detection."""
        skill = PwnSkill()

        elf_file = tmp_path / "binary"
        elf_file.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 50)
        assert skill._is_likely_binary(elf_file)

    def test_is_likely_binary_text(self, tmp_path: Path):
        """Test that text files are not detected as binaries."""
        skill = PwnSkill()

        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("just text")
        assert not skill._is_likely_binary(txt_file)

    def test_is_likely_binary_source(self, tmp_path: Path):
        """Test that source code files are excluded by extension."""
        skill = PwnSkill()

        c_file = tmp_path / "vuln.c"
        c_file.write_text("#include <stdio.h>")
        assert not skill._is_likely_binary(c_file)

        py_file = tmp_path / "solve.py"
        py_file.write_text("import pwn")
        assert not skill._is_likely_binary(py_file)

    def test_extract_arch(self):
        """Test architecture extraction from file type strings."""
        skill = PwnSkill()

        assert skill._extract_arch("ELF 64-bit LSB executable, x86-64") == "x86_64"
        assert skill._extract_arch("ELF 32-bit LSB executable, Intel 80386 (i386)") == "x86"
        # Note: bit-width checks take priority over specific arch names
        assert skill._extract_arch("ELF 64-bit LSB executable, ARM aarch64") == "x86_64"
        assert skill._extract_arch("ELF 32-bit LSB executable, ARM") == "x86"
        assert skill._extract_arch("ELF 32-bit MSB executable, MIPS") == "x86"
        assert skill._extract_arch("data") == "unknown"
        # Without bit-width prefix, specific arch names match correctly
        assert skill._extract_arch("ARM aarch64") == "arm64"
        assert skill._extract_arch("ARM") == "arm"
        assert skill._extract_arch("MIPS") == "mips"

    def test_scan_for_vulnerabilities(self):
        """Test vulnerability pattern scanning in strings output."""
        skill = PwnSkill()

        strings_output = "gets\nstrcpy\nsystem\nprintf()\nsome_func"
        vulns = skill._scan_for_vulnerabilities(strings_output)

        types = {v["type"] for v in vulns}
        assert "buffer_overflow" in types
        assert "command_injection" in types

    def test_scan_for_vulnerabilities_clean(self):
        """Test scanning with no vulnerability patterns."""
        skill = PwnSkill()

        strings_output = "safe_function\nanother_safe\nnothing_here"
        vulns = skill._scan_for_vulnerabilities(strings_output)
        assert len(vulns) == 0

    def test_generate_suggestions_no_canary(self):
        """Test suggestions when no stack canary is present."""
        skill = PwnSkill()
        analysis = {
            "protections": {"canary": False, "nx": True, "pie": False, "relro": "Partial"},
            "vulnerabilities": [{"type": "buffer_overflow", "indicator": "gets()"}],
            "binary_info": {"arch": "x86_64"},
            "gadgets": [],
            "interesting_functions": [],
        }

        suggestions = skill._generate_suggestions(analysis)
        assert any("canary" in s.lower() or "overflow" in s.lower() for s in suggestions)
        assert any("rop" in s.lower() or "pie" in s.lower() for s in suggestions)

    def test_calculate_confidence(self):
        """Test confidence calculation."""
        skill = PwnSkill()

        empty = {
            "binary_info": {},
            "protections": {},
            "vulnerabilities": [],
            "gadgets": [],
            "interesting_functions": [],
            "interesting_strings": [],
        }
        assert skill._calculate_confidence(empty) == 0.0

        rich = {
            "binary_info": {"name": "test"},
            "protections": {"canary": False},
            "vulnerabilities": [{"type": "bof"}],
            "gadgets": [{"addr": "0x1234"}],
            "interesting_functions": ["main"],
            "interesting_strings": ["flag"],
        }
        assert skill._calculate_confidence(rich) == 1.0

    def test_vuln_patterns_defined(self):
        """Test that vulnerability patterns are defined."""
        assert "buffer_overflow" in PwnSkill.VULN_PATTERNS
        assert "format_string" in PwnSkill.VULN_PATTERNS
        assert "use_after_free" in PwnSkill.VULN_PATTERNS
        assert "command_injection" in PwnSkill.VULN_PATTERNS

    def test_protection_names_defined(self):
        """Test that protection names are defined."""
        assert "RELRO" in PwnSkill.PROTECTION_NAMES
        assert "NX" in PwnSkill.PROTECTION_NAMES
        assert "PIE" in PwnSkill.PROTECTION_NAMES

    def test_registry(self):
        """Test that PwnSkill is registered."""
        skill = get_skill("pwn")
        assert skill is not None
        assert isinstance(skill, PwnSkill)


# ---------------------------------------------------------------------------
# ReversingSkill
# ---------------------------------------------------------------------------


class TestReversingSkill:
    """Tests for ReversingSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = ReversingSkill()
        assert skill.name == "reversing"
        assert skill.description
        assert skill.category == "reversing"
        assert "radare2" in skill.tool_names
        assert "ghidra" in skill.tool_names
        assert "file" in skill.tool_names
        assert "strings" in skill.tool_names
        assert "objdump" in skill.tool_names
        assert "readelf" in skill.tool_names
        assert "ltrace" in skill.tool_names
        assert "strace" in skill.tool_names

    def test_analyze_executable_file(self, tmp_path: Path):
        """Test analyzing an executable file (pyc format to avoid radare2 dict bug)."""
        # Use .pyc extension which _is_executable recognizes by extension,
        # but radare2 won't attempt deep analysis on.
        pyc_file = tmp_path / "challenge.pyc"
        pyc_file.write_bytes(b"\x42\x0d\r\n" + b"\x00" * 200)

        skill = ReversingSkill()
        result = skill.analyze(pyc_file)

        assert isinstance(result, SkillResult)
        assert result.success
        assert result.skill_name == "reversing"

    def test_analyze_pe_file(self, tmp_path: Path):
        """Test analyzing a PE (Windows) binary."""
        pe_file = tmp_path / "challenge.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 200)

        skill = ReversingSkill()
        result = skill.analyze(pe_file)

        assert result.success

    def test_analyze_directory(self, tmp_path: Path):
        """Test analyzing a directory filters to executables."""
        # Use .pyc extension to avoid radare2 dict bug on raw ELF stubs
        (tmp_path / "module.pyc").write_bytes(b"\x42\x0d\r\n" + b"\x00" * 100)
        (tmp_path / "readme.txt").write_text("Not executable")

        skill = ReversingSkill()
        result = skill.analyze(tmp_path)

        assert result.success

    def test_analyze_no_executables(self, tmp_path: Path):
        """Test analyzing directory with no executables."""
        (tmp_path / "notes.txt").write_text("No binaries here")

        skill = ReversingSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No executable" in result.suggestions[0]

    def test_suggest_approach(self):
        """Test suggest_approach returns useful steps."""
        skill = ReversingSkill()
        analysis = {"binary_type": "elf", "anti_debug": []}

        approaches = skill.suggest_approach(analysis)
        assert isinstance(approaches, list)
        assert len(approaches) > 0
        assert any("ghidra" in s.lower() or "disassembler" in s.lower() for s in approaches)

    def test_suggest_approach_with_anti_debug(self):
        """Test suggest_approach includes anti-debug patching when detected."""
        skill = ReversingSkill()
        analysis = {
            "binary_type": "elf",
            "anti_debug": [{"pattern": "ptrace", "description": "ptrace anti-debugging"}],
        }

        approaches = skill.suggest_approach(analysis)
        assert any("anti-debug" in s.lower() or "patch" in s.lower() for s in approaches)

    def test_is_executable_elf(self, tmp_path: Path):
        """Test ELF detection via magic bytes."""
        skill = ReversingSkill()

        elf = tmp_path / "binary"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 50)
        assert skill._is_executable(elf)

    def test_is_executable_pe(self, tmp_path: Path):
        """Test PE detection via magic bytes."""
        skill = ReversingSkill()

        pe = tmp_path / "app"
        pe.write_bytes(b"MZ" + b"\x00" * 50)
        assert skill._is_executable(pe)

    def test_is_executable_macho(self, tmp_path: Path):
        """Test Mach-O detection via magic bytes."""
        skill = ReversingSkill()

        macho = tmp_path / "macapp"
        macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 50)
        assert skill._is_executable(macho)

    def test_is_executable_by_extension(self, tmp_path: Path):
        """Test executable detection by file extension."""
        skill = ReversingSkill()

        jar = tmp_path / "app.jar"
        jar.write_bytes(b"PK\x03\x04" + b"\x00" * 50)
        assert skill._is_executable(jar)

        pyc = tmp_path / "module.pyc"
        pyc.write_bytes(b"\x00" * 50)
        assert skill._is_executable(pyc)

    def test_is_executable_not(self, tmp_path: Path):
        """Test that regular text files are not considered executable."""
        skill = ReversingSkill()

        txt = tmp_path / "readme.txt"
        txt.write_text("Just text content, not a binary.")
        assert not skill._is_executable(txt)

    def test_detect_binary_type(self, tmp_path: Path):
        """Test binary type detection from FileInfo."""
        from ctf_kit.utils.file_detection import FileInfo

        skill = ReversingSkill()

        elf_info = FileInfo(
            path=tmp_path / "test",
            name="test",
            size=100,
            extension="",
            magic_bytes=b"\x7fELF",
            file_type="ELF 64-bit LSB executable",
        )
        assert skill._detect_binary_type(tmp_path / "test", elf_info) == "elf"

        pe_info = FileInfo(
            path=tmp_path / "test.exe",
            name="test.exe",
            size=100,
            extension=".exe",
            magic_bytes=b"MZ",
            file_type="PE32 executable (console) Intel 80386",
        )
        assert skill._detect_binary_type(tmp_path / "test.exe", pe_info) == "pe"

    def test_extract_architecture(self):
        """Test architecture extraction from file type string."""
        skill = ReversingSkill()

        assert skill._extract_architecture("ELF 64-bit LSB executable, x86-64") == "x86_64"
        assert skill._extract_architecture("ELF 32-bit LSB executable, i386") == "x86"
        # Note: bit-width checks take priority over specific arch names
        assert skill._extract_architecture("ELF 64-bit ARM aarch64") == "x86_64"
        assert skill._extract_architecture("ELF 32-bit MSB executable, MIPS") == "x86"
        assert skill._extract_architecture("data") == "unknown"
        # Without bit-width prefix, specific arch names match correctly
        assert skill._extract_architecture("ARM aarch64") == "arm64"
        assert skill._extract_architecture("MIPS") == "mips"

    def test_find_anti_debug(self):
        """Test anti-debugging pattern detection in strings."""
        skill = ReversingSkill()

        strings_with_antidebug = "ptrace\nIsDebuggerPresent\nnormal_func\nrdtsc"
        results = skill._find_anti_debug(strings_with_antidebug)

        descriptions = [r["description"] for r in results]
        assert "ptrace anti-debugging" in descriptions
        assert "Windows debugger detection" in descriptions
        assert "Timing-based anti-debug" in descriptions

    def test_find_anti_debug_clean(self):
        """Test anti-debug with no suspicious patterns."""
        skill = ReversingSkill()

        clean_strings = "main\nprintf\nstrcmp\nexit"
        results = skill._find_anti_debug(clean_strings)
        assert len(results) == 0

    def test_generate_suggestions_elf(self):
        """Test suggestions for ELF binaries."""
        skill = ReversingSkill()
        analysis = {
            "binary_type": "elf",
            "architecture": "x86_64",
            "anti_debug": [],
            "interesting_functions": [],
            "interesting_strings": [],
        }

        suggestions = skill._generate_suggestions(analysis)
        assert any("ghidra" in s.lower() or "ida" in s.lower() for s in suggestions)

    def test_generate_suggestions_java(self):
        """Test suggestions for Java binaries."""
        skill = ReversingSkill()
        analysis = {
            "binary_type": "java",
            "architecture": "unknown",
            "anti_debug": [],
            "interesting_functions": [],
            "interesting_strings": [],
        }

        suggestions = skill._generate_suggestions(analysis)
        assert any("jadx" in s.lower() or "decompile" in s.lower() for s in suggestions)

    def test_generate_suggestions_anti_debug(self):
        """Test suggestions when anti-debugging is detected."""
        skill = ReversingSkill()
        analysis = {
            "binary_type": "elf",
            "architecture": "x86_64",
            "anti_debug": [{"pattern": "ptrace", "description": "ptrace anti-debugging"}],
            "interesting_functions": [],
            "interesting_strings": [],
        }

        suggestions = skill._generate_suggestions(analysis)
        assert any("anti-debug" in s.lower() for s in suggestions)

    def test_calculate_confidence(self):
        """Test confidence calculation for reversing skill."""
        skill = ReversingSkill()

        empty = {
            "binary_type": None,
            "architecture": None,
            "interesting_functions": [],
            "interesting_strings": [],
            "imports": [],
            "sections": [],
            "anti_debug": [],
        }
        assert skill._calculate_confidence(empty) == 0.0

        rich = {
            "binary_type": "elf",
            "architecture": "x86_64",
            "interesting_functions": ["main", "check_password"],
            "interesting_strings": ["Enter password:"],
            "imports": ["strcmp", "printf"],
            "sections": [{"name": ".text"}],
            "anti_debug": [{"desc": "ptrace"}],
        }
        confidence = skill._calculate_confidence(rich)
        assert confidence > 0.7

    def test_binary_types_defined(self):
        """Test that binary type constants are defined."""
        assert "elf" in ReversingSkill.BINARY_TYPES
        assert "pe" in ReversingSkill.BINARY_TYPES
        assert "java" in ReversingSkill.BINARY_TYPES
        assert "python" in ReversingSkill.BINARY_TYPES
        assert "android" in ReversingSkill.BINARY_TYPES

    def test_anti_debug_patterns_defined(self):
        """Test that anti-debug pattern constants are defined."""
        patterns = [p for p, _ in ReversingSkill.ANTI_DEBUG_PATTERNS]
        assert "ptrace" in patterns
        assert "IsDebuggerPresent" in patterns

    def test_interesting_funcs_defined(self):
        """Test that interesting function names are defined."""
        assert "main" in ReversingSkill.INTERESTING_FUNCS
        assert "flag" in ReversingSkill.INTERESTING_FUNCS
        assert "decrypt" in ReversingSkill.INTERESTING_FUNCS
        assert "strcmp" in ReversingSkill.INTERESTING_FUNCS

    def test_registry(self):
        """Test that ReversingSkill is registered."""
        skill = get_skill("reversing")
        assert skill is not None
        assert isinstance(skill, ReversingSkill)


# ---------------------------------------------------------------------------
# StegoSkill
# ---------------------------------------------------------------------------


class TestStegoSkill:
    """Tests for StegoSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = StegoSkill()
        assert skill.name == "stego"
        assert skill.description
        assert skill.category == "stego"
        assert "zsteg" in skill.tool_names
        assert "steghide" in skill.tool_names
        assert "exiftool" in skill.tool_names
        assert "binwalk" in skill.tool_names
        assert "strings" in skill.tool_names
        assert "file" in skill.tool_names
        assert "stegsolve" in skill.tool_names

    def test_analyze_png_file(self, tmp_path: Path):
        """Test analyzing a PNG image file."""
        png_file = tmp_path / "image.png"
        # Minimal PNG: magic bytes + some data
        png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)

        skill = StegoSkill()
        result = skill.analyze(png_file)

        assert isinstance(result, SkillResult)
        assert result.success
        assert result.skill_name == "stego"
        assert result.analysis["media_type"] == "png"

    def test_analyze_jpeg_file(self, tmp_path: Path):
        """Test analyzing a JPEG image file."""
        jpg_file = tmp_path / "photo.jpg"
        jpg_file.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 200)

        skill = StegoSkill()
        result = skill.analyze(jpg_file)

        assert result.success
        assert result.analysis["media_type"] == "jpeg"

    def test_analyze_wav_file(self, tmp_path: Path):
        """Test analyzing a WAV audio file."""
        wav_file = tmp_path / "audio.wav"
        wav_file.write_bytes(b"RIFF" + b"\x00" * 200)

        skill = StegoSkill()
        result = skill.analyze(wav_file)

        assert result.success
        assert result.analysis["media_type"] == "audio"

    def test_analyze_directory(self, tmp_path: Path):
        """Test analyzing a directory with multiple media files."""
        (tmp_path / "a.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        (tmp_path / "b.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 50)

        skill = StegoSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        assert len(result.analysis["file_info"]) == 2

    def test_analyze_empty_directory(self, tmp_path: Path):
        """Test analyzing empty directory returns unsuccessful result."""
        skill = StegoSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No files found" in result.suggestions[0]

    def test_suggest_approach_png(self):
        """Test suggest_approach for PNG analysis."""
        skill = StegoSkill()
        analysis = {
            "media_type": "png",
            "lsb_findings": [],
            "embedded_data": [],
            "metadata_findings": [],
            "appended_data": False,
            "suspicious_indicators": [],
        }

        approaches = skill.suggest_approach(analysis)
        assert isinstance(approaches, list)
        assert any("zsteg" in s.lower() for s in approaches)

    def test_suggest_approach_jpeg(self):
        """Test suggest_approach for JPEG analysis."""
        skill = StegoSkill()
        analysis = {
            "media_type": "jpeg",
            "lsb_findings": [],
            "embedded_data": [],
            "metadata_findings": [],
            "appended_data": False,
            "suspicious_indicators": [],
        }

        approaches = skill.suggest_approach(analysis)
        assert any("steghide" in s.lower() for s in approaches)

    def test_suggest_approach_audio(self):
        """Test suggest_approach for audio analysis."""
        skill = StegoSkill()
        analysis = {
            "media_type": "audio",
            "lsb_findings": [],
            "embedded_data": [],
            "metadata_findings": [],
            "appended_data": False,
            "suspicious_indicators": [],
        }

        approaches = skill.suggest_approach(analysis)
        assert any("spectrogram" in s.lower() or "audacity" in s.lower() for s in approaches)

    def test_detect_media_type_png(self, tmp_path: Path):
        """Test PNG media type detection."""
        skill = StegoSkill()
        assert skill._detect_media_type(tmp_path / "test.png") == "png"

    def test_detect_media_type_bmp(self, tmp_path: Path):
        """Test BMP media type detection."""
        skill = StegoSkill()
        assert skill._detect_media_type(tmp_path / "test.bmp") == "bmp"

    def test_detect_media_type_gif(self, tmp_path: Path):
        """Test GIF media type detection."""
        skill = StegoSkill()
        assert skill._detect_media_type(tmp_path / "test.gif") == "gif"

    def test_detect_media_type_jpeg(self, tmp_path: Path):
        """Test JPEG media type detection."""
        skill = StegoSkill()
        assert skill._detect_media_type(tmp_path / "test.jpg") == "jpeg"
        assert skill._detect_media_type(tmp_path / "test.jpeg") == "jpeg"

    def test_detect_media_type_audio(self, tmp_path: Path):
        """Test audio media type detection."""
        skill = StegoSkill()
        assert skill._detect_media_type(tmp_path / "test.wav") == "audio"
        assert skill._detect_media_type(tmp_path / "test.mp3") == "audio"
        assert skill._detect_media_type(tmp_path / "test.flac") == "audio"

    def test_detect_media_type_other_image(self, tmp_path: Path):
        """Test other image format detection."""
        skill = StegoSkill()
        assert skill._detect_media_type(tmp_path / "test.tiff") == "image"
        assert skill._detect_media_type(tmp_path / "test.webp") == "image"

    def test_detect_media_type_unknown(self, tmp_path: Path):
        """Test unknown file type detection."""
        skill = StegoSkill()
        assert skill._detect_media_type(tmp_path / "data.bin") == "unknown"
        assert skill._detect_media_type(tmp_path / "file.xyz") == "unknown"

    def test_check_appended_data(self, tmp_path: Path):
        """Test detection of appended data (e.g., ZIP after image)."""
        skill = StegoSkill()
        test_file = tmp_path / "image.png"
        test_file.write_bytes(b"\x89PNG" + b"\x00" * 5000)

        file_analysis: dict = {
            "appended_data": False,
            "suspicious_indicators": [],
        }
        signatures = [
            {"offset": 0, "description": "PNG image"},
            {"offset": 2000, "description": "Zip archive"},
        ]
        skill._check_appended_data(test_file, signatures, file_analysis)

        assert file_analysis["appended_data"]
        assert any("zip" in s.lower() for s in file_analysis["suspicious_indicators"])

    def test_check_appended_data_empty(self, tmp_path: Path):
        """Test appended data check with no signatures."""
        skill = StegoSkill()
        test_file = tmp_path / "clean.png"
        test_file.write_bytes(b"\x89PNG" + b"\x00" * 100)

        file_analysis: dict = {"appended_data": False, "suspicious_indicators": []}
        skill._check_appended_data(test_file, [], file_analysis)

        assert not file_analysis["appended_data"]

    def test_check_metadata_anomalies(self):
        """Test metadata anomaly detection."""
        skill = StegoSkill()
        file_analysis: dict = {"suspicious_indicators": []}

        parsed_data = {"metadata": {"Comment": "secret flag here"}}
        skill._check_metadata_anomalies(parsed_data, file_analysis)

        assert len(file_analysis["suspicious_indicators"]) > 0
        assert any("Comment" in s for s in file_analysis["suspicious_indicators"])

    def test_check_metadata_anomalies_square_image(self):
        """Test metadata anomaly detection for suspicious dimensions."""
        skill = StegoSkill()
        file_analysis: dict = {"suspicious_indicators": []}

        parsed_data = {"metadata": {"ImageWidth": 512, "ImageHeight": 512}}
        skill._check_metadata_anomalies(parsed_data, file_analysis)

        assert any("512x512" in s for s in file_analysis["suspicious_indicators"])

    def test_calculate_confidence(self):
        """Test confidence calculation for stego analysis."""
        skill = StegoSkill()

        empty = {
            "media_type": "unknown",
            "file_info": {},
            "lsb_findings": [],
            "embedded_data": [],
            "metadata_findings": [],
            "suspicious_indicators": [],
        }
        assert skill._calculate_confidence(empty) == 0.0

        rich = {
            "media_type": "png",
            "file_info": {"test.png": {}},
            "lsb_findings": [{"channel": "r"}],
            "embedded_data": [{"type": "zip"}],
            "metadata_findings": [{"field": "comment"}],
            "suspicious_indicators": ["extra data"],
        }
        confidence = skill._calculate_confidence(rich)
        assert confidence > 0.7

    def test_image_formats_defined(self):
        """Test that image format constants are defined."""
        assert "lsb_capable" in StegoSkill.IMAGE_FORMATS
        assert ".png" in StegoSkill.IMAGE_FORMATS["lsb_capable"]
        assert ".bmp" in StegoSkill.IMAGE_FORMATS["lsb_capable"]
        assert "jpeg" in StegoSkill.IMAGE_FORMATS
        assert ".jpg" in StegoSkill.IMAGE_FORMATS["jpeg"]

    def test_audio_formats_defined(self):
        """Test that audio format constants are defined."""
        assert ".wav" in StegoSkill.AUDIO_FORMATS
        assert ".mp3" in StegoSkill.AUDIO_FORMATS
        assert ".flac" in StegoSkill.AUDIO_FORMATS

    def test_generate_suggestions_lsb(self):
        """Test suggestions when LSB data is found."""
        skill = StegoSkill()
        analysis = {
            "media_type": "png",
            "lsb_findings": [{"data": "flag"}],
            "embedded_data": [],
            "metadata_findings": [],
            "appended_data": False,
            "suspicious_indicators": [],
        }
        suggestions = skill._generate_suggestions(analysis)
        assert any("lsb" in s.lower() for s in suggestions)

    def test_generate_suggestions_appended(self):
        """Test suggestions when appended data is found."""
        skill = StegoSkill()
        analysis = {
            "media_type": "png",
            "lsb_findings": [],
            "embedded_data": [],
            "metadata_findings": [],
            "appended_data": True,
            "suspicious_indicators": [],
        }
        suggestions = skill._generate_suggestions(analysis)
        assert any("appended" in s.lower() for s in suggestions)

    def test_registry(self):
        """Test that StegoSkill is registered."""
        skill = get_skill("stego")
        assert skill is not None
        assert isinstance(skill, StegoSkill)


# ---------------------------------------------------------------------------
# WebSkill
# ---------------------------------------------------------------------------


class TestWebSkill:
    """Tests for WebSkill."""

    def test_skill_attributes(self):
        """Test skill has correct attributes."""
        skill = WebSkill()
        assert skill.name == "web"
        assert skill.description
        assert skill.category == "web"
        assert "sqlmap" in skill.tool_names
        assert "gobuster" in skill.tool_names
        assert "ffuf" in skill.tool_names
        assert "strings" in skill.tool_names
        assert "file" in skill.tool_names

    def test_analyze_php_file(self, tmp_path: Path):
        """Test analyzing a PHP file with SQL injection vulnerability."""
        php_file = tmp_path / "index.php"
        php_file.write_text(
            '<?php\n$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET["id"]);\n?>'
        )

        skill = WebSkill()
        result = skill.analyze(php_file)

        assert isinstance(result, SkillResult)
        assert result.success
        assert result.skill_name == "web"
        # Should detect SQL injection pattern
        vuln_types = {v["type"] for v in result.analysis["vulnerabilities"]}
        assert "sqli" in vuln_types

    def test_analyze_flask_app(self, tmp_path: Path):
        """Test analyzing a Flask application file."""
        py_file = tmp_path / "app.py"
        py_file.write_text(
            "from flask import Flask, render_template_string, request\n"
            "app = Flask(__name__)\n"
            "@app.route('/hello')\n"
            "def hello():\n"
            "    name = request.args.get('name')\n"
            "    return render_template_string('<h1>' + name + '</h1>')\n"
        )

        skill = WebSkill()
        result = skill.analyze(py_file)

        assert result.success
        assert "Flask" in result.analysis["technology_stack"]
        # Should detect SSTI pattern
        vuln_types = {v["type"] for v in result.analysis["vulnerabilities"]}
        assert "ssti" in vuln_types

    def test_analyze_directory(self, tmp_path: Path):
        """Test analyzing a directory with web files."""
        (tmp_path / "index.html").write_text("<html><script>document.cookie</script></html>")
        # Use Python assignment syntax for credentials (regex expects password = "..." or password: "...")
        (tmp_path / "config.py").write_text('password = "supersecret123"\nsecret_key = "mykey1234"')

        skill = WebSkill()
        result = skill.analyze(tmp_path)

        assert result.success
        # Should find XSS and credential patterns
        vuln_types = {v["type"] for v in result.analysis["vulnerabilities"]}
        assert "xss" in vuln_types
        assert len(result.analysis["credentials"]) > 0

    def test_analyze_empty_directory(self, tmp_path: Path):
        """Test analyzing empty directory returns unsuccessful result."""
        skill = WebSkill()
        result = skill.analyze(tmp_path)

        assert not result.success
        assert "No web-related files" in result.suggestions[0]

    def test_suggest_approach(self):
        """Test suggest_approach returns web testing steps."""
        skill = WebSkill()
        analysis = {
            "vulnerabilities": [{"type": "sqli"}],
            "credentials": [],
        }

        approaches = skill.suggest_approach(analysis)
        assert isinstance(approaches, list)
        assert len(approaches) > 0
        assert any("source code" in s.lower() or "vulnerabilit" in s.lower() for s in approaches)

    def test_suggest_approach_with_credentials(self):
        """Test suggest_approach prioritizes credential usage."""
        skill = WebSkill()
        analysis = {
            "vulnerabilities": [],
            "credentials": [{"type": "password", "value": "admin"}],
        }

        approaches = skill.suggest_approach(analysis)
        assert approaches[0].lower().startswith("try found credentials")

    def test_detect_technologies_php(self, tmp_path: Path):
        """Test PHP technology detection."""
        skill = WebSkill()
        technologies = skill._detect_technologies(
            tmp_path / "test.php", "<?php echo 'hello'; ?>"
        )
        assert "PHP" in technologies

    def test_detect_technologies_flask(self, tmp_path: Path):
        """Test Flask technology detection."""
        skill = WebSkill()
        technologies = skill._detect_technologies(
            tmp_path / "app.py", "from flask import Flask"
        )
        assert "Flask" in technologies

    def test_detect_technologies_jwt(self, tmp_path: Path):
        """Test JWT technology detection."""
        skill = WebSkill()
        technologies = skill._detect_technologies(
            tmp_path / "auth.py", "token = jwt.decode(cookie)"
        )
        assert "JWT" in technologies

    def test_detect_technologies_databases(self, tmp_path: Path):
        """Test database technology detection."""
        skill = WebSkill()
        technologies = skill._detect_technologies(
            tmp_path / "db.py", "conn = sqlite3.connect('db.sqlite')"
        )
        assert "SQLite" in technologies

    def test_extract_endpoints_flask(self):
        """Test Flask route extraction."""
        skill = WebSkill()
        content = (
            "@app.route('/login')\n"
            "def login():\n"
            "    pass\n"
            "@app.route('/admin/dashboard')\n"
            "def admin():\n"
            "    pass\n"
        )
        endpoints = skill._extract_endpoints(content)
        assert "/login" in endpoints
        assert "/admin/dashboard" in endpoints

    def test_extract_endpoints_express(self):
        """Test Express.js route extraction."""
        skill = WebSkill()
        content = (
            "app.get('/api/users', handler);\n"
            "app.post('/api/login', handler);\n"
        )
        endpoints = skill._extract_endpoints(content)
        assert "/api/users" in endpoints
        assert "/api/login" in endpoints

    def test_extract_credentials(self):
        """Test credential extraction from source code."""
        skill = WebSkill()
        content = (
            'password = "supersecret123"\n'
            'api_key = "sk-abc123def456"\n'
            'username = "admin"\n'
        )
        creds = skill._extract_credentials(content)

        types = {c["type"] for c in creds}
        assert "password" in types
        assert "api_key" in types

    def test_extract_credentials_short_values_filtered(self):
        """Test that very short credential values are filtered out."""
        skill = WebSkill()
        content = 'password = "ab"\n'  # Too short (3 chars required)
        creds = skill._extract_credentials(content)
        assert len(creds) == 0

    def test_find_interesting_patterns(self):
        """Test detection of interesting security patterns."""
        skill = WebSkill()
        content = (
            'flag = "CTF{test_flag}"\n'
            "DEBUG = True\n"
            "eval(user_input)\n"
        )
        patterns = skill._find_interesting_patterns(content)

        assert "Flag value found" in patterns
        assert "Debug mode enabled" in patterns
        assert "eval() function used" in patterns

    def test_find_web_files(self, tmp_path: Path):
        """Test web file discovery in directory."""
        (tmp_path / "index.php").write_text("<?php ?>")
        (tmp_path / "style.css").write_text("body { }")
        (tmp_path / "app.js").write_text("console.log('hi')")
        (tmp_path / "binary.bin").write_bytes(b"\x00" * 50)

        skill = WebSkill()
        files = skill._find_web_files(tmp_path)

        names = [f.name for f in files]
        assert "index.php" in names
        assert "app.js" in names
        # .css is not in WEB_EXTENSIONS, so it should not be found
        # unless it matches a keyword
        assert "binary.bin" not in names

    def test_find_web_files_keyword_match(self, tmp_path: Path):
        """Test that files with interesting names are included."""
        (tmp_path / "flag").write_text("you found it")
        (tmp_path / "config").write_text("secret stuff")

        skill = WebSkill()
        files = skill._find_web_files(tmp_path)

        names = [f.name for f in files]
        assert "flag" in names
        assert "config" in names

    def test_generate_suggestions_sqli(self):
        """Test suggestions for SQL injection vulnerabilities."""
        skill = WebSkill()
        analysis = {
            "vulnerabilities": [{"type": "sqli"}],
            "technology_stack": [],
            "endpoints": [],
            "credentials": [],
            "interesting_patterns": [],
        }
        suggestions = skill._generate_suggestions(analysis)
        assert any("sql" in s.lower() for s in suggestions)

    def test_generate_suggestions_xss(self):
        """Test suggestions for XSS vulnerabilities."""
        skill = WebSkill()
        analysis = {
            "vulnerabilities": [{"type": "xss"}],
            "technology_stack": [],
            "endpoints": [],
            "credentials": [],
            "interesting_patterns": [],
        }
        suggestions = skill._generate_suggestions(analysis)
        assert any("xss" in s.lower() for s in suggestions)

    def test_generate_suggestions_no_vulns(self):
        """Test default suggestions when no vulnerabilities found."""
        skill = WebSkill()
        analysis = {
            "vulnerabilities": [],
            "technology_stack": [],
            "endpoints": [],
            "credentials": [],
            "interesting_patterns": [],
        }
        suggestions = skill._generate_suggestions(analysis)
        assert any("directory" in s.lower() or "enumerat" in s.lower() for s in suggestions)

    def test_calculate_confidence(self):
        """Test confidence calculation for web analysis."""
        skill = WebSkill()

        empty = {
            "vulnerabilities": [],
            "technology_stack": [],
            "endpoints": [],
            "credentials": [],
            "interesting_patterns": [],
        }
        assert skill._calculate_confidence(empty) == 0.0

        rich = {
            "vulnerabilities": [{"type": "sqli"}, {"type": "xss"}],
            "technology_stack": ["Flask"],
            "endpoints": ["/login"],
            "credentials": [{"type": "password", "value": "test"}],
            "interesting_patterns": ["debug mode"],
        }
        confidence = skill._calculate_confidence(rich)
        assert confidence > 0.7

    def test_vuln_patterns_defined(self):
        """Test that vulnerability pattern constants are defined."""
        assert "sqli" in WebSkill.VULN_PATTERNS
        assert "xss" in WebSkill.VULN_PATTERNS
        assert "command_injection" in WebSkill.VULN_PATTERNS
        assert "path_traversal" in WebSkill.VULN_PATTERNS
        assert "ssti" in WebSkill.VULN_PATTERNS
        assert "auth" in WebSkill.VULN_PATTERNS

    def test_web_extensions_defined(self):
        """Test that web extension constants are defined."""
        assert ".php" in WebSkill.WEB_EXTENSIONS
        assert ".html" in WebSkill.WEB_EXTENSIONS
        assert ".js" in WebSkill.WEB_EXTENSIONS
        assert ".py" in WebSkill.WEB_EXTENSIONS

    def test_registry(self):
        """Test that WebSkill is registered."""
        skill = get_skill("web")
        assert skill is not None
        assert isinstance(skill, WebSkill)


# ---------------------------------------------------------------------------
# Cross-skill registry tests
# ---------------------------------------------------------------------------


class TestExtendedSkillRegistry:
    """Tests for all extended skills in the registry."""

    def test_all_extended_skills_registered(self):
        """Test that all extended skills are in the registry."""
        skills = get_all_skills()
        expected = ["forensics", "misc", "osint", "pwn", "reversing", "stego", "web"]
        for name in expected:
            assert name in skills, f"Skill '{name}' not found in registry"

    def test_all_skills_have_descriptions(self):
        """Test that every registered skill has a non-empty description."""
        skills = get_all_skills()
        for name, skill in skills.items():
            assert skill.description, f"Skill '{name}' has no description"

    def test_all_skills_have_tool_names(self):
        """Test that every registered skill declares at least one tool."""
        skills = get_all_skills()
        for name, skill in skills.items():
            assert len(skill.tool_names) > 0, f"Skill '{name}' has no tool_names"

    def test_all_skills_have_unique_names(self):
        """Test that no two skills share the same name."""
        skills = get_all_skills()
        names = list(skills.keys())
        assert len(names) == len(set(names))
