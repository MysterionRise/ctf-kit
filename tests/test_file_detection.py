"""
Tests for file detection utilities.
"""

from pathlib import Path
import tempfile

from ctf_kit.utils.file_detection import (
    CTFCategory,
    FileInfo,
    analyze_directory,
    detect_file_type,
    detect_magic_type,
    format_size,
    get_magic_bytes,
    suggest_category,
)


class TestMagicBytes:
    """Test magic byte detection."""

    def test_png_magic(self) -> None:
        """Test PNG detection."""
        magic = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
        result = detect_magic_type(magic)
        assert result == "PNG image"

    def test_jpeg_magic(self) -> None:
        """Test JPEG detection."""
        magic = b"\xff\xd8\xff" + b"\x00" * 29
        result = detect_magic_type(magic)
        assert result == "JPEG image"

    def test_elf_magic(self) -> None:
        """Test ELF detection."""
        magic = b"\x7fELF" + b"\x00" * 28
        result = detect_magic_type(magic)
        assert result == "ELF executable"

    def test_zip_magic(self) -> None:
        """Test ZIP detection."""
        magic = b"PK\x03\x04" + b"\x00" * 28
        result = detect_magic_type(magic)
        assert result == "ZIP archive"

    def test_unknown_magic(self) -> None:
        """Test unknown magic bytes."""
        magic = b"\x00\x01\x02\x03" + b"\x00" * 28
        result = detect_magic_type(magic)
        assert result is None


class TestFileInfo:
    """Test FileInfo dataclass."""

    def test_to_dict(self) -> None:
        """Test FileInfo serialization."""
        info = FileInfo(
            path=Path("/fake/path/test.txt"),
            name="test.txt",
            size=1024,
            extension=".txt",
            magic_bytes=b"test",
            file_type="ASCII text",
            suggested_category=CTFCategory.MISC,
        )
        data = info.to_dict()
        assert data["name"] == "test.txt"
        assert data["size"] == 1024
        assert data["suggested_category"] == "misc"


class TestDetectFileType:
    """Test file type detection."""

    def test_detect_text_file(self) -> None:
        """Test detecting a text file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello, World!")
            f.flush()
            path = Path(f.name)

        try:
            info = detect_file_type(path)
            assert info.name.endswith(".txt")
            assert info.size > 0
            assert "text" in info.file_type.lower() or "ascii" in info.file_type.lower()
        finally:
            path.unlink()

    def test_detect_binary_file(self) -> None:
        """Test detecting a binary file."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"\x00\x01\x02\x03\x04\x05")
            f.flush()
            path = Path(f.name)

        try:
            info = detect_file_type(path)
            assert info.name.endswith(".bin")
            assert info.size == 6
        finally:
            path.unlink()

    def test_detect_nonexistent_file(self) -> None:
        """Test detecting a nonexistent file."""
        path = Path("/nonexistent/file.txt")
        info = detect_file_type(path)
        assert "not found" in info.file_type.lower()

    def test_detect_png_file(self) -> None:
        """Test detecting a PNG file from magic bytes."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".png", delete=False) as f:
            # Write PNG magic bytes
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
            f.flush()
            path = Path(f.name)

        try:
            info = detect_file_type(path)
            assert info.suggested_category == CTFCategory.STEGO
        finally:
            path.unlink()


class TestSuggestCategory:
    """Test category suggestion."""

    def test_crypto_extension(self) -> None:
        """Test crypto category from extension."""
        info = FileInfo(
            path=Path("/fake/path/key.pem"),
            name="key.pem",
            size=1024,
            extension=".pem",
            magic_bytes=b"",
            file_type="PEM certificate",
        )
        assert suggest_category(info) == CTFCategory.CRYPTO

    def test_stego_image(self) -> None:
        """Test stego category from image file type."""
        info = FileInfo(
            path=Path("/fake/path/image.png"),
            name="image.png",
            size=1024,
            extension=".png",
            magic_bytes=b"",
            file_type="PNG image data",
        )
        assert suggest_category(info) == CTFCategory.STEGO

    def test_forensics_pcap(self) -> None:
        """Test forensics category from pcap extension."""
        info = FileInfo(
            path=Path("/fake/path/capture.pcap"),
            name="capture.pcap",
            size=1024,
            extension=".pcap",
            magic_bytes=b"",
            file_type="pcap-ng capture file",
        )
        assert suggest_category(info) == CTFCategory.FORENSICS

    def test_pwn_elf(self) -> None:
        """Test pwn category from ELF binary."""
        info = FileInfo(
            path=Path("/fake/path/binary"),
            name="binary",
            size=1024,
            extension="",
            magic_bytes=b"\x7fELF",
            file_type="ELF 64-bit LSB executable",
        )
        assert suggest_category(info) == CTFCategory.PWN


class TestAnalyzeDirectory:
    """Test directory analysis."""

    def test_analyze_empty_directory(self) -> None:
        """Test analyzing an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = analyze_directory(Path(tmpdir))
            assert files == []

    def test_analyze_directory_with_files(self) -> None:
        """Test analyzing a directory with files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some test files
            (Path(tmpdir) / "test.txt").write_text("Hello")
            (Path(tmpdir) / "data.bin").write_bytes(b"\x00\x01\x02")

            files = analyze_directory(Path(tmpdir))
            assert len(files) == 2
            names = {f.name for f in files}
            assert "test.txt" in names
            assert "data.bin" in names

    def test_analyze_directory_ignores_hidden(self) -> None:
        """Test that hidden files are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "visible.txt").write_text("Hello")
            (Path(tmpdir) / ".hidden").write_text("Secret")

            files = analyze_directory(Path(tmpdir))
            assert len(files) == 1
            assert files[0].name == "visible.txt"


class TestFormatSize:
    """Test size formatting."""

    def test_bytes(self) -> None:
        assert format_size(500) == "500.0 B"

    def test_kilobytes(self) -> None:
        assert format_size(2048) == "2.0 KB"

    def test_megabytes(self) -> None:
        assert format_size(1048576) == "1.0 MB"

    def test_gigabytes(self) -> None:
        assert format_size(1073741824) == "1.0 GB"


class TestGetMagicBytes:
    """Test magic bytes reading."""

    def test_read_magic_bytes(self) -> None:
        """Test reading magic bytes from file."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"rest of file")
            f.flush()
            path = Path(f.name)

        try:
            magic = get_magic_bytes(path, 8)
            assert magic == b"\x89PNG\r\n\x1a\n"
        finally:
            path.unlink()

    def test_read_nonexistent_file(self) -> None:
        """Test reading from nonexistent file."""
        magic = get_magic_bytes(Path("/nonexistent/file"))
        assert magic == b""
