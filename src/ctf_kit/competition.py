"""
Competition management for CTF Kit.

Handles challenge tracking (solved/unsolved/in-progress), team coordination,
and time tracking for CTF competitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class ChallengeStatus(StrEnum):
    """Status of a challenge in a competition."""

    UNSOLVED = "unsolved"
    IN_PROGRESS = "in_progress"
    SOLVED = "solved"
    SKIPPED = "skipped"


@dataclass
class TeamMember:
    """A team member participating in the competition."""

    name: str
    role: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result: dict[str, Any] = {"name": self.name}
        if self.role:
            result["role"] = self.role
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TeamMember:
        """Deserialize from dictionary."""
        return cls(name=data["name"], role=data.get("role"))


@dataclass
class ChallengeEntry:
    """A challenge tracked within a competition."""

    name: str
    category: str | None = None
    status: ChallengeStatus = ChallengeStatus.UNSOLVED
    points: int | None = None
    flag: str | None = None
    assigned_to: str | None = None
    started_at: str | None = None
    solved_at: str | None = None
    tags: list[str] = field(default_factory=list)
    notes: str | None = None
    tools_used: list[str] = field(default_factory=list)

    @property
    def solve_duration(self) -> timedelta | None:
        """Calculate time spent on the challenge."""
        if not self.started_at or not self.solved_at:
            return None
        start = datetime.fromisoformat(self.started_at)
        end = datetime.fromisoformat(self.solved_at)
        return end - start

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result: dict[str, Any] = {
            "name": self.name,
            "status": self.status.value,
        }
        if self.category:
            result["category"] = self.category
        if self.points is not None:
            result["points"] = self.points
        if self.flag:
            result["flag"] = self.flag
        if self.assigned_to:
            result["assigned_to"] = self.assigned_to
        if self.started_at:
            result["started_at"] = self.started_at
        if self.solved_at:
            result["solved_at"] = self.solved_at
        if self.tags:
            result["tags"] = self.tags
        if self.notes:
            result["notes"] = self.notes
        if self.tools_used:
            result["tools_used"] = self.tools_used
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChallengeEntry:
        """Deserialize from dictionary."""
        return cls(
            name=data["name"],
            category=data.get("category"),
            status=ChallengeStatus(data.get("status", "unsolved")),
            points=data.get("points"),
            flag=data.get("flag"),
            assigned_to=data.get("assigned_to"),
            started_at=data.get("started_at"),
            solved_at=data.get("solved_at"),
            tags=data.get("tags", []),
            notes=data.get("notes"),
            tools_used=data.get("tools_used", []),
        )


@dataclass
class Competition:
    """A CTF competition with challenge tracking and team coordination."""

    name: str
    url: str | None = None
    flag_format: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    team: list[TeamMember] = field(default_factory=list)
    challenges: list[ChallengeEntry] = field(default_factory=list)

    @property
    def total_points(self) -> int:
        """Sum of points from solved challenges."""
        return sum(c.points or 0 for c in self.challenges if c.status == ChallengeStatus.SOLVED)

    @property
    def solved_count(self) -> int:
        """Number of solved challenges."""
        return sum(1 for c in self.challenges if c.status == ChallengeStatus.SOLVED)

    @property
    def in_progress_count(self) -> int:
        """Number of in-progress challenges."""
        return sum(1 for c in self.challenges if c.status == ChallengeStatus.IN_PROGRESS)

    @property
    def unsolved_count(self) -> int:
        """Number of unsolved challenges."""
        return sum(1 for c in self.challenges if c.status == ChallengeStatus.UNSOLVED)

    def get_challenge(self, name: str) -> ChallengeEntry | None:
        """Find a challenge by name (case-insensitive)."""
        name_lower = name.lower()
        for challenge in self.challenges:
            if challenge.name.lower() == name_lower:
                return challenge
        return None

    def add_challenge(
        self,
        name: str,
        category: str | None = None,
        points: int | None = None,
    ) -> ChallengeEntry:
        """Add a new challenge to the competition."""
        existing = self.get_challenge(name)
        if existing:
            msg = f"Challenge '{name}' already exists"
            raise ValueError(msg)

        entry = ChallengeEntry(name=name, category=category, points=points)
        self.challenges.append(entry)
        return entry

    def start_challenge(self, name: str, assigned_to: str | None = None) -> ChallengeEntry:
        """Mark a challenge as in-progress."""
        challenge = self.get_challenge(name)
        if not challenge:
            msg = f"Challenge '{name}' not found"
            raise KeyError(msg)

        challenge.status = ChallengeStatus.IN_PROGRESS
        challenge.started_at = datetime.now(tz=UTC).isoformat()
        if assigned_to:
            challenge.assigned_to = assigned_to
        return challenge

    def solve_challenge(
        self,
        name: str,
        flag: str | None = None,
        points: int | None = None,
    ) -> ChallengeEntry:
        """Mark a challenge as solved."""
        challenge = self.get_challenge(name)
        if not challenge:
            msg = f"Challenge '{name}' not found"
            raise KeyError(msg)

        challenge.status = ChallengeStatus.SOLVED
        challenge.solved_at = datetime.now(tz=UTC).isoformat()
        if flag:
            challenge.flag = flag
        if points is not None:
            challenge.points = points
        if not challenge.started_at:
            challenge.started_at = challenge.solved_at
        return challenge

    def add_team_member(self, name: str, role: str | None = None) -> TeamMember:
        """Add a team member."""
        member = TeamMember(name=name, role=role)
        self.team.append(member)
        return member

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result: dict[str, Any] = {"name": self.name}
        if self.url:
            result["url"] = self.url
        if self.flag_format:
            result["flag_format"] = self.flag_format
        if self.start_time:
            result["start_time"] = self.start_time
        if self.end_time:
            result["end_time"] = self.end_time
        if self.team:
            result["team"] = [m.to_dict() for m in self.team]
        if self.challenges:
            result["challenges"] = [c.to_dict() for c in self.challenges]
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Competition:
        """Deserialize from dictionary."""
        team = [TeamMember.from_dict(m) for m in data.get("team", [])]
        challenges = [ChallengeEntry.from_dict(c) for c in data.get("challenges", [])]
        return cls(
            name=data["name"],
            url=data.get("url"),
            flag_format=data.get("flag_format"),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            team=team,
            challenges=challenges,
        )


# --- Persistence ---

COMPETITION_FILE = ".ctf-competition.yaml"


def find_competition_root(start_path: Path | None = None) -> Path | None:
    """Find the competition root by looking for .ctf-competition.yaml."""
    path = start_path or Path.cwd()

    for parent in [path, *list(path.parents)]:
        if (parent / COMPETITION_FILE).is_file():
            return parent

    return None


def load_competition(path: Path | None = None) -> Competition | None:
    """Load competition from a directory."""
    root = find_competition_root(path)
    if not root:
        return None

    config_file = root / COMPETITION_FILE
    with config_file.open() as f:
        data = yaml.safe_load(f) or {}

    return Competition.from_dict(data)


def save_competition(competition: Competition, path: Path) -> None:
    """Save competition to a directory."""
    config_file = path / COMPETITION_FILE
    config_file.parent.mkdir(parents=True, exist_ok=True)

    with config_file.open("w") as f:
        yaml.dump(competition.to_dict(), f, default_flow_style=False, sort_keys=False)


def scan_challenges(competition_dir: Path) -> list[ChallengeEntry]:
    """Scan a competition directory for challenge folders with .ctf/ subdirs."""
    entries: list[ChallengeEntry] = []

    for child in sorted(competition_dir.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue

        # Direct challenge folder (has .ctf/)
        if (child / ".ctf").is_dir():
            entries.append(_entry_from_challenge_dir(child))
            continue

        # Category subfolder (e.g., crypto/rsa-baby)
        for subchild in sorted(child.iterdir()):
            if subchild.is_dir() and (subchild / ".ctf").is_dir():
                entry = _entry_from_challenge_dir(subchild)
                if not entry.category:
                    entry.category = child.name
                entries.append(entry)

    return entries


def _entry_from_challenge_dir(path: Path) -> ChallengeEntry:
    """Create a ChallengeEntry from a challenge directory."""
    name = path.name
    category: str | None = None
    flag: str | None = None
    status = ChallengeStatus.UNSOLVED

    # Read challenge.yaml if it exists
    challenge_yaml = path / ".ctf" / "challenge.yaml"
    if challenge_yaml.exists():
        with challenge_yaml.open() as f:
            data = yaml.safe_load(f) or {}
        category = data.get("category")
        if data.get("solved"):
            status = ChallengeStatus.SOLVED
        if data.get("flag"):
            flag = data["flag"]

    # Check for flag.txt
    flag_file = path / "flag.txt"
    if flag_file.exists():
        flag = flag_file.read_text().strip()
        status = ChallengeStatus.SOLVED

    return ChallengeEntry(name=name, category=category, flag=flag, status=status)
