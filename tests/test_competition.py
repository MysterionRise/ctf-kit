"""
Tests for competition management functionality.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile

import pytest
from typer.testing import CliRunner

from ctf_kit.cli import app
from ctf_kit.competition import (
    COMPETITION_FILE,
    ChallengeEntry,
    ChallengeStatus,
    Competition,
    TeamMember,
    find_competition_root,
    load_competition,
    save_competition,
    scan_challenges,
)

runner = CliRunner()


class TestChallengeStatus:
    """Test ChallengeStatus enum."""

    def test_status_values(self):
        assert ChallengeStatus.UNSOLVED == "unsolved"
        assert ChallengeStatus.IN_PROGRESS == "in_progress"
        assert ChallengeStatus.SOLVED == "solved"
        assert ChallengeStatus.SKIPPED == "skipped"

    def test_status_from_string(self):
        assert ChallengeStatus("solved") == ChallengeStatus.SOLVED
        assert ChallengeStatus("unsolved") == ChallengeStatus.UNSOLVED


class TestTeamMember:
    """Test TeamMember dataclass."""

    def test_basic_member(self):
        member = TeamMember(name="alice")
        assert member.name == "alice"
        assert member.role is None

    def test_member_with_role(self):
        member = TeamMember(name="bob", role="crypto")
        assert member.role == "crypto"

    def test_to_dict(self):
        member = TeamMember(name="alice", role="web")
        data = member.to_dict()
        assert data == {"name": "alice", "role": "web"}

    def test_to_dict_no_role(self):
        member = TeamMember(name="alice")
        data = member.to_dict()
        assert data == {"name": "alice"}

    def test_from_dict(self):
        data = {"name": "charlie", "role": "pwn"}
        member = TeamMember.from_dict(data)
        assert member.name == "charlie"
        assert member.role == "pwn"

    def test_from_dict_no_role(self):
        data = {"name": "dave"}
        member = TeamMember.from_dict(data)
        assert member.role is None


class TestChallengeEntry:
    """Test ChallengeEntry dataclass."""

    def test_default_status(self):
        entry = ChallengeEntry(name="rsa-baby")
        assert entry.status == ChallengeStatus.UNSOLVED
        assert entry.category is None
        assert entry.points is None

    def test_solve_duration(self):
        now = datetime.now(tz=UTC)
        start = (now - timedelta(hours=1, minutes=30)).isoformat()
        end = now.isoformat()
        entry = ChallengeEntry(
            name="test",
            started_at=start,
            solved_at=end,
        )
        duration = entry.solve_duration
        assert duration is not None
        assert 89 <= duration.total_seconds() / 60 <= 91

    def test_solve_duration_none(self):
        entry = ChallengeEntry(name="test")
        assert entry.solve_duration is None

    def test_to_dict_minimal(self):
        entry = ChallengeEntry(name="test")
        data = entry.to_dict()
        assert data == {"name": "test", "status": "unsolved"}

    def test_to_dict_full(self):
        entry = ChallengeEntry(
            name="rsa-baby",
            category="crypto",
            status=ChallengeStatus.SOLVED,
            points=100,
            flag="flag{test}",
            assigned_to="alice",
            started_at="2026-01-01T00:00:00+00:00",
            solved_at="2026-01-01T01:00:00+00:00",
            tags=["rsa", "easy"],
            notes="Cube root attack",
            tools_used=["rsactftool", "gmpy2"],
        )
        data = entry.to_dict()
        assert data["category"] == "crypto"
        assert data["points"] == 100
        assert data["flag"] == "flag{test}"
        assert data["tags"] == ["rsa", "easy"]
        assert data["tools_used"] == ["rsactftool", "gmpy2"]

    def test_from_dict(self):
        data = {
            "name": "web-sqli",
            "category": "web",
            "status": "in_progress",
            "points": 200,
            "assigned_to": "bob",
        }
        entry = ChallengeEntry.from_dict(data)
        assert entry.name == "web-sqli"
        assert entry.status == ChallengeStatus.IN_PROGRESS
        assert entry.points == 200

    def test_roundtrip(self):
        entry = ChallengeEntry(
            name="forensics-dump",
            category="forensics",
            status=ChallengeStatus.SOLVED,
            points=300,
            flag="flag{mem_dump}",
        )
        data = entry.to_dict()
        restored = ChallengeEntry.from_dict(data)
        assert restored.name == entry.name
        assert restored.status == entry.status
        assert restored.flag == entry.flag


class TestCompetition:
    """Test Competition dataclass."""

    def test_empty_competition(self):
        comp = Competition(name="TestCTF")
        assert comp.name == "TestCTF"
        assert comp.solved_count == 0
        assert comp.in_progress_count == 0
        assert comp.unsolved_count == 0
        assert comp.total_points == 0

    def test_add_challenge(self):
        comp = Competition(name="TestCTF")
        entry = comp.add_challenge("rsa-baby", category="crypto", points=100)
        assert entry.name == "rsa-baby"
        assert len(comp.challenges) == 1
        assert comp.unsolved_count == 1

    def test_add_duplicate_challenge(self):
        comp = Competition(name="TestCTF")
        comp.add_challenge("rsa-baby")
        with pytest.raises(ValueError, match="already exists"):
            comp.add_challenge("rsa-baby")

    def test_get_challenge(self):
        comp = Competition(name="TestCTF")
        comp.add_challenge("rsa-baby")
        assert comp.get_challenge("rsa-baby") is not None
        assert comp.get_challenge("RSA-Baby") is not None  # case-insensitive
        assert comp.get_challenge("nonexistent") is None

    def test_start_challenge(self):
        comp = Competition(name="TestCTF")
        comp.add_challenge("rsa-baby")
        entry = comp.start_challenge("rsa-baby", assigned_to="alice")
        assert entry.status == ChallengeStatus.IN_PROGRESS
        assert entry.assigned_to == "alice"
        assert entry.started_at is not None
        assert comp.in_progress_count == 1

    def test_start_nonexistent(self):
        comp = Competition(name="TestCTF")
        with pytest.raises(KeyError, match="not found"):
            comp.start_challenge("nope")

    def test_solve_challenge(self):
        comp = Competition(name="TestCTF")
        comp.add_challenge("rsa-baby", points=100)
        comp.start_challenge("rsa-baby")
        entry = comp.solve_challenge("rsa-baby", flag="flag{easy}", points=100)
        assert entry.status == ChallengeStatus.SOLVED
        assert entry.flag == "flag{easy}"
        assert entry.solved_at is not None
        assert comp.solved_count == 1
        assert comp.total_points == 100

    def test_solve_without_start(self):
        comp = Competition(name="TestCTF")
        comp.add_challenge("rsa-baby")
        entry = comp.solve_challenge("rsa-baby", flag="flag{quick}")
        assert entry.status == ChallengeStatus.SOLVED
        assert entry.started_at is not None  # auto-filled

    def test_solve_nonexistent(self):
        comp = Competition(name="TestCTF")
        with pytest.raises(KeyError, match="not found"):
            comp.solve_challenge("nope")

    def test_add_team_member(self):
        comp = Competition(name="TestCTF")
        member = comp.add_team_member("alice", role="crypto")
        assert member.name == "alice"
        assert len(comp.team) == 1

    def test_total_points(self):
        comp = Competition(name="TestCTF")
        comp.add_challenge("a", points=100)
        comp.add_challenge("b", points=200)
        comp.add_challenge("c", points=300)
        comp.solve_challenge("a", flag="f1")
        comp.solve_challenge("c", flag="f3")
        assert comp.total_points == 400

    def test_to_dict(self):
        comp = Competition(name="TestCTF", url="https://test.ctf")
        comp.add_challenge("ch1", category="crypto")
        comp.add_team_member("alice")
        data = comp.to_dict()
        assert data["name"] == "TestCTF"
        assert data["url"] == "https://test.ctf"
        assert len(data["challenges"]) == 1
        assert len(data["team"]) == 1

    def test_from_dict(self):
        data = {
            "name": "TestCTF",
            "url": "https://test.ctf",
            "team": [{"name": "alice", "role": "crypto"}],
            "challenges": [
                {"name": "ch1", "status": "solved", "points": 100},
            ],
        }
        comp = Competition.from_dict(data)
        assert comp.name == "TestCTF"
        assert len(comp.team) == 1
        assert comp.solved_count == 1

    def test_roundtrip(self):
        comp = Competition(name="RoundtripCTF", url="https://rt.ctf", flag_format="flag{.*}")
        comp.add_challenge("ch1", category="crypto", points=100)
        comp.add_team_member("alice", role="web")

        data = comp.to_dict()
        restored = Competition.from_dict(data)
        assert restored.name == comp.name
        assert restored.url == comp.url
        assert len(restored.challenges) == 1
        assert len(restored.team) == 1


class TestCompetitionPersistence:
    """Test competition save/load/find."""

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            comp = Competition(name="SaveTest", url="https://save.test")
            comp.add_challenge("ch1", category="web", points=200)

            save_competition(comp, path)

            loaded = load_competition(path)
            assert loaded is not None
            assert loaded.name == "SaveTest"
            assert len(loaded.challenges) == 1

    def test_find_competition_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            comp = Competition(name="FindTest")
            save_competition(comp, root)

            # Should find from root itself
            found = find_competition_root(root)
            assert found == root

            # Should find from subdirectory
            subdir = root / "crypto" / "rsa-baby"
            subdir.mkdir(parents=True)
            found = find_competition_root(subdir)
            assert found == root

    def test_find_competition_root_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            found = find_competition_root(Path(tmpdir))
            assert found is None

    def test_load_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            loaded = load_competition(Path(tmpdir))
            assert loaded is None

    def test_scan_challenges_flat(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            # Create challenge with .ctf/ and flag
            ch1 = root / "rsa-baby"
            (ch1 / ".ctf").mkdir(parents=True)
            (ch1 / "flag.txt").write_text("flag{test}")

            # Create challenge without flag
            ch2 = root / "web-hard"
            (ch2 / ".ctf").mkdir(parents=True)

            entries = scan_challenges(root)
            assert len(entries) == 2

            names = {e.name for e in entries}
            assert "rsa-baby" in names
            assert "web-hard" in names

            solved = [e for e in entries if e.status == ChallengeStatus.SOLVED]
            assert len(solved) == 1
            assert solved[0].flag == "flag{test}"

    def test_scan_challenges_nested(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            # Create category/challenge structure
            ch1 = root / "crypto" / "rsa-baby"
            (ch1 / ".ctf").mkdir(parents=True)

            entries = scan_challenges(root)
            assert len(entries) == 1
            assert entries[0].name == "rsa-baby"
            assert entries[0].category == "crypto"


class TestCompetitionCLI:
    """Test competition CLI commands."""

    def test_competition_init(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app, ["competition", "init", "--name", "TestCTF", tmpdir]
            )
            assert result.exit_code == 0
            assert "Competition initialized" in result.stdout

            config = Path(tmpdir) / COMPETITION_FILE
            assert config.exists()

    def test_competition_init_with_url_and_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app,
                [
                    "competition", "init",
                    "--name", "PicoCTF",
                    "--url", "https://play.picoctf.org",
                    "--flag-format", r"picoCTF\{.*\}",
                    tmpdir,
                ],
            )
            assert result.exit_code == 0

            comp = load_competition(Path(tmpdir))
            assert comp is not None
            assert comp.name == "PicoCTF"
            assert comp.url == "https://play.picoctf.org"
            assert comp.flag_format == r"picoCTF\{.*\}"

    def test_competition_init_duplicate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            result = runner.invoke(
                app, ["competition", "init", "--name", "TestCTF2", tmpdir]
            )
            assert result.exit_code == 1
            assert "already initialized" in result.stdout

    def test_competition_add_from_dir(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            result = runner.invoke(
                app,
                ["competition", "add", "rsa-baby", "--category", "crypto", "--points", "100"],
            )
            assert result.exit_code == 0
            assert "rsa-baby" in result.stdout

            comp = load_competition(Path(tmpdir))
            assert comp is not None
            assert comp.get_challenge("rsa-baby") is not None

    def test_competition_add_duplicate(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            runner.invoke(app, ["competition", "add", "rsa-baby"])
            result = runner.invoke(app, ["competition", "add", "rsa-baby"])
            assert result.exit_code == 1
            assert "already exists" in result.stdout

    def test_competition_start(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            runner.invoke(app, ["competition", "add", "rsa-baby"])
            result = runner.invoke(
                app, ["competition", "start", "rsa-baby", "--assign", "alice"]
            )
            assert result.exit_code == 0
            assert "Started" in result.stdout
            assert "alice" in result.stdout

    def test_competition_start_nonexistent(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            result = runner.invoke(app, ["competition", "start", "nope"])
            assert result.exit_code == 1

    def test_competition_solve(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            runner.invoke(app, ["competition", "add", "rsa-baby", "--points", "100"])
            runner.invoke(app, ["competition", "start", "rsa-baby"])
            result = runner.invoke(
                app,
                ["competition", "solve", "rsa-baby", "--flag", "flag{easy}", "--points", "100"],
            )
            assert result.exit_code == 0
            assert "Solved" in result.stdout

    def test_competition_solve_nonexistent(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            result = runner.invoke(app, ["competition", "solve", "nope"])
            assert result.exit_code == 1

    def test_competition_status(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            runner.invoke(app, ["competition", "add", "ch1", "--category", "crypto", "--points", "100"])
            runner.invoke(app, ["competition", "add", "ch2", "--category", "web"])
            runner.invoke(app, ["competition", "solve", "ch1", "--flag", "flag{ch1}"])

            result = runner.invoke(app, ["competition", "status"])
            assert result.exit_code == 0
            assert "TestCTF" in result.stdout
            assert "ch1" in result.stdout
            assert "ch2" in result.stdout

    def test_competition_status_with_scan(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            # Create a challenge dir with .ctf
            ch_dir = Path(tmpdir) / "new-challenge"
            (ch_dir / ".ctf").mkdir(parents=True)

            result = runner.invoke(app, ["competition", "status", "--scan"])
            assert result.exit_code == 0
            assert "new-challenge" in result.stdout

    def test_competition_status_no_competition(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["competition", "status", tmpdir])
            assert result.exit_code == 1

    def test_competition_status_empty(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            result = runner.invoke(app, ["competition", "status"])
            assert result.exit_code == 0
            assert "No challenges tracked" in result.stdout

    def test_competition_team_add(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, ["competition", "init", "--name", "TestCTF", tmpdir])
            monkeypatch.chdir(tmpdir)

            result = runner.invoke(
                app, ["competition", "team-add", "alice", "--role", "crypto"]
            )
            assert result.exit_code == 0
            assert "alice" in result.stdout

            comp = load_competition(Path(tmpdir))
            assert comp is not None
            assert len(comp.team) == 1
            assert comp.team[0].name == "alice"

    def test_competition_help(self):
        result = runner.invoke(app, ["competition", "--help"])
        assert result.exit_code == 0
        assert "competition" in result.stdout.lower()


class TestWriteupExport:
    """Test writeup generation with competition support."""

    def test_single_challenge_writeup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            ctf_dir = path / ".ctf"
            ctf_dir.mkdir()
            (ctf_dir / "analysis.md").write_text("# Analysis\nCrypto RSA challenge")
            (ctf_dir / "approach.md").write_text("# Approach\nCube root attack")
            (path / "flag.txt").write_text("flag{test_flag}")

            result = runner.invoke(app, ["writeup", tmpdir])
            assert result.exit_code == 0
            assert "Writeup generated" in result.stdout

            writeup = (ctf_dir / "writeup.md").read_text()
            assert "flag{test_flag}" in writeup
            assert "Crypto" in writeup

    def test_writeup_with_solve_script(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            ctf_dir = path / ".ctf"
            ctf_dir.mkdir()
            (ctf_dir / "analysis.md").write_text("# Analysis")
            (path / "solve.py").write_text("print('hello')")
            (path / "flag.txt").write_text("flag{solved}")

            result = runner.invoke(app, ["writeup", tmpdir])
            assert result.exit_code == 0

            writeup = (ctf_dir / "writeup.md").read_text()
            assert "solve.py" in writeup
            assert "print('hello')" in writeup

    def test_writeup_with_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            ctf_dir = path / ".ctf"
            ctf_dir.mkdir()
            (ctf_dir / "analysis.md").write_text("# Analysis")
            (ctf_dir / "attempts.md").write_text(
                "# Attempts\n- Ran binwalk on the file\n- Used hashcat for password"
            )
            (path / "flag.txt").write_text("flag{tools}")

            result = runner.invoke(app, ["writeup", tmpdir])
            assert result.exit_code == 0

            writeup = (ctf_dir / "writeup.md").read_text()
            assert "binwalk" in writeup
            assert "hashcat" in writeup

    def test_writeup_no_ctf_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["writeup", tmpdir])
            assert result.exit_code == 1

    def test_competition_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            # Create competition
            comp = Competition(name="ExportCTF")
            comp.add_challenge("ch1", category="crypto", points=100)
            comp.solve_challenge("ch1", flag="flag{ch1}")
            comp.add_challenge("ch2", category="web", points=200)
            save_competition(comp, root)

            # Create challenge directories
            ch1_dir = root / "ch1"
            ch1_ctf = ch1_dir / ".ctf"
            ch1_ctf.mkdir(parents=True)
            (ch1_ctf / "analysis.md").write_text("RSA analysis")
            (ch1_dir / "flag.txt").write_text("flag{ch1}")

            result = runner.invoke(app, ["writeup", "--all", tmpdir])
            assert result.exit_code == 0
            assert "Competition writeup exported" in result.stdout

            writeup_path = root / "writeups.md"
            assert writeup_path.exists()
            content = writeup_path.read_text()
            assert "ExportCTF" in content
            assert "ch1" in content
            assert "ch2" in content

    def test_competition_export_no_competition(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["writeup", "--all", tmpdir])
            assert result.exit_code == 1
