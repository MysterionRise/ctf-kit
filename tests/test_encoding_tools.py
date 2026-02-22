"""Tests for encoding tool integrations (CyberChef)."""

from ctf_kit.integrations.encoding.cyberchef import SUPPORTED_OPERATIONS, CyberChefTool


class TestCyberChefTool:
    """Tests for CyberChefTool."""

    def test_tool_attributes(self):
        """Test tool has correct attributes."""
        tool = CyberChefTool()
        assert tool.name == "cyberchef"
        assert tool.description == "Data encoding/decoding transformations"
        assert tool.binary_names == []

    def test_is_always_installed(self):
        """Test tool is always available."""
        tool = CyberChefTool()
        assert tool.is_installed is True

    def test_supported_operations_defined(self):
        """Test supported operations list is populated."""
        assert len(SUPPORTED_OPERATIONS) > 10
        assert "base64_encode" in SUPPORTED_OPERATIONS
        assert "base64_decode" in SUPPORTED_OPERATIONS
        assert "rot13" in SUPPORTED_OPERATIONS
        assert "xor" in SUPPORTED_OPERATIONS

    # --- Base64 ---

    def test_base64_encode(self):
        """Test base64 encoding."""
        tool = CyberChefTool()
        result = tool.run("Hello World", operation="base64_encode")
        assert result.success
        assert result.stdout == "SGVsbG8gV29ybGQ="

    def test_base64_decode(self):
        """Test base64 decoding."""
        tool = CyberChefTool()
        result = tool.run("SGVsbG8gV29ybGQ=", operation="base64_decode")
        assert result.success
        assert result.stdout == "Hello World"

    # --- Base32 ---

    def test_base32_encode(self):
        """Test base32 encoding."""
        tool = CyberChefTool()
        result = tool.run("Hello", operation="base32_encode")
        assert result.success
        assert result.stdout == "JBSWY3DP"

    def test_base32_decode(self):
        """Test base32 decoding."""
        tool = CyberChefTool()
        result = tool.run("JBSWY3DP", operation="base32_decode")
        assert result.success
        assert result.stdout == "Hello"

    # --- Hex ---

    def test_hex_encode(self):
        """Test hex encoding."""
        tool = CyberChefTool()
        result = tool.run("ABC", operation="hex_encode")
        assert result.success
        assert result.stdout == "414243"

    def test_hex_decode(self):
        """Test hex decoding."""
        tool = CyberChefTool()
        result = tool.run("414243", operation="hex_decode")
        assert result.success
        assert result.stdout == "ABC"

    # --- ROT13 ---

    def test_rot13(self):
        """Test ROT13."""
        tool = CyberChefTool()
        result = tool.run("Hello", operation="rot13")
        assert result.success
        assert result.stdout == "Uryyb"

    def test_rot13_roundtrip(self):
        """Test ROT13 applied twice returns original."""
        tool = CyberChefTool()
        result1 = tool.run("flag{test}", operation="rot13")
        assert result1.success
        result2 = tool.run(result1.stdout, operation="rot13")
        assert result2.success
        assert result2.stdout == "flag{test}"

    # --- ROT-N ---

    def test_rot_n(self):
        """Test ROT-N with custom rotation."""
        tool = CyberChefTool()
        result = tool.run("ABC", operation="rot_n", n=3)
        assert result.success
        assert result.stdout == "DEF"

    # --- URL ---

    def test_url_encode(self):
        """Test URL encoding."""
        tool = CyberChefTool()
        result = tool.run("hello world&foo=bar", operation="url_encode")
        assert result.success
        assert "hello%20world" in result.stdout

    def test_url_decode(self):
        """Test URL decoding."""
        tool = CyberChefTool()
        result = tool.run("hello%20world", operation="url_decode")
        assert result.success
        assert result.stdout == "hello world"

    # --- HTML ---

    def test_html_encode(self):
        """Test HTML encoding."""
        tool = CyberChefTool()
        result = tool.run("<script>alert(1)</script>", operation="html_encode")
        assert result.success
        assert "&lt;" in result.stdout
        assert "&gt;" in result.stdout

    def test_html_decode(self):
        """Test HTML decoding."""
        tool = CyberChefTool()
        result = tool.run("&lt;script&gt;", operation="html_decode")
        assert result.success
        assert result.stdout == "<script>"

    # --- Reverse ---

    def test_reverse(self):
        """Test string reversal."""
        tool = CyberChefTool()
        result = tool.run("Hello", operation="reverse")
        assert result.success
        assert result.stdout == "olleH"

    # --- XOR ---

    def test_xor_with_key(self):
        """Test XOR with a key."""
        tool = CyberChefTool()
        result = tool.run("Hello", operation="xor", key="K")
        assert result.success
        # XOR should produce different output
        assert result.stdout != "Hello"
        # XOR again with same key should restore
        result2 = tool.run(result.parsed_data["output_bytes"], operation="xor", key="K")
        assert result2.success
        assert result2.stdout == "Hello"

    # --- Atbash ---

    def test_atbash(self):
        """Test Atbash cipher."""
        tool = CyberChefTool()
        result = tool.run("ABC", operation="atbash")
        assert result.success
        assert result.stdout == "ZYX"

    def test_atbash_roundtrip(self):
        """Test Atbash applied twice returns original."""
        tool = CyberChefTool()
        result1 = tool.run("Hello", operation="atbash")
        result2 = tool.run(result1.stdout, operation="atbash")
        assert result2.stdout == "Hello"

    # --- Binary ---

    def test_text_to_binary(self):
        """Test text to binary conversion."""
        tool = CyberChefTool()
        result = tool.run("Hi", operation="text_to_binary")
        assert result.success
        assert "01001000" in result.stdout  # H
        assert "01101001" in result.stdout  # i

    def test_binary_to_text(self):
        """Test binary to text conversion."""
        tool = CyberChefTool()
        result = tool.run("01001000 01101001", operation="binary_to_text")
        assert result.success
        assert result.stdout == "Hi"

    # --- Decimal ---

    def test_decimal_to_text(self):
        """Test decimal to text conversion."""
        tool = CyberChefTool()
        result = tool.run("72 101 108 108 111", operation="decimal_to_text")
        assert result.success
        assert result.stdout == "Hello"

    # --- Morse ---

    def test_morse_encode(self):
        """Test Morse code encoding."""
        tool = CyberChefTool()
        result = tool.run("SOS", operation="morse_encode")
        assert result.success
        assert "..." in result.stdout  # S
        assert "---" in result.stdout  # O

    def test_morse_decode(self):
        """Test Morse code decoding."""
        tool = CyberChefTool()
        result = tool.run("... --- ...", operation="morse_decode")
        assert result.success
        assert result.stdout == "SOS"

    def test_morse_decode_with_words(self):
        """Test Morse decode with word separation."""
        tool = CyberChefTool()
        result = tool.run(".... .. / - .... . .-. .", operation="morse_decode")
        assert result.success
        assert "HI" in result.stdout
        assert "THERE" in result.stdout

    # --- Decode Chain ---

    def test_decode_chain(self):
        """Test chaining multiple decode operations."""
        tool = CyberChefTool()
        # Encode: Hello -> base64 -> hex
        import base64
        import binascii

        encoded = binascii.hexlify(base64.b64encode(b"Hello")).decode()

        # Decode: hex -> base64
        result = tool.decode_chain(encoded, ["hex_decode", "base64_decode"])
        assert result.success
        assert result.stdout == "Hello"
        assert result.parsed_data is not None
        assert len(result.parsed_data["steps"]) == 2

    def test_decode_chain_failure(self):
        """Test decode chain fails gracefully."""
        tool = CyberChefTool()
        result = tool.decode_chain("not-valid-hex!", ["hex_decode", "base64_decode"])
        assert not result.success
        assert result.parsed_data["failed_at"] == "hex_decode"

    # --- Magic ---

    def test_magic_base64(self):
        """Test magic detection of base64."""
        tool = CyberChefTool()
        import base64

        encoded = base64.b64encode(b"This is a test string for magic detection").decode()
        result = tool.magic(encoded)
        assert result.success
        assert result.parsed_data is not None
        decodings = result.parsed_data["decodings"]
        assert any(d["encoding"] == "Base64" for d in decodings)

    def test_magic_hex(self):
        """Test magic detection of hex."""
        tool = CyberChefTool()
        import binascii

        encoded = binascii.hexlify(b"Hello World testing hex").decode()
        result = tool.magic(encoded)
        assert result.success
        decodings = result.parsed_data["decodings"]
        assert any(d["encoding"] == "Hex" for d in decodings)

    def test_magic_with_flag(self):
        """Test magic detects flags in decoded output."""
        tool = CyberChefTool()
        import base64

        encoded = base64.b64encode(b"flag{found_the_flag}").decode()
        result = tool.magic(encoded)
        assert result.success
        decodings = result.parsed_data["decodings"]
        flag_decodings = [d for d in decodings if d.get("has_flag")]
        assert len(flag_decodings) >= 1

    # --- Error Handling ---

    def test_unknown_operation(self):
        """Test unknown operation returns error."""
        tool = CyberChefTool()
        result = tool.run("test", operation="nonexistent_op")
        assert not result.success
        assert "Unknown operation" in (result.error_message or "")

    def test_invalid_base64(self):
        """Test invalid base64 input."""
        tool = CyberChefTool()
        result = tool.run("not-valid-base64!!!", operation="base64_decode")
        assert not result.success

    # --- Utility Methods ---

    def test_looks_meaningful(self):
        """Test meaningful text detection."""
        tool = CyberChefTool()
        assert tool._looks_meaningful("Hello World") is True
        assert tool._looks_meaningful("") is False
        assert tool._looks_meaningful("\x00\x01\x02\x03\x04") is False

    def test_contains_flag(self):
        """Test flag pattern detection."""
        tool = CyberChefTool()
        assert tool._contains_flag("flag{test}") is True
        assert tool._contains_flag("CTF{test}") is True
        assert tool._contains_flag("no flag here") is False

    def test_check_for_flags(self):
        """Test flag checking in decoded text."""
        tool = CyberChefTool()
        suggestions = tool._check_for_flags("The answer is flag{secret_123}")
        assert any("flag{secret_123}" in s for s in suggestions)
