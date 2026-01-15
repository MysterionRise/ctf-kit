"""
Configuration management for CTF Kit.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml


class ToolsConfig(BaseModel):  # type: ignore[misc]
    """Tool path overrides."""

    ghidra: str | None = None
    ida: str | None = None
    radare2: str | None = None


class ApiKeysConfig(BaseModel):  # type: ignore[misc]
    """API keys for external services."""

    shodan: str | None = None
    virustotal: str | None = None
    censys: str | None = None


class PreferencesConfig(BaseModel):  # type: ignore[misc]
    """User preferences."""

    auto_commit: bool = False
    writeup_format: str = "markdown"
    include_failed_attempts: bool = True
    organize_by_category: bool = False


class Config(BaseSettings):  # type: ignore[misc]
    """
    Main configuration for CTF Kit.

    Loaded from:
    1. .ctf-kit/config.yaml (repo level)
    2. ~/.config/ctf-kit/config.yaml (user level)
    3. Environment variables (CTF_KIT_*)
    """

    model_config = SettingsConfigDict(
        env_prefix="CTF_KIT_",
        env_nested_delimiter="__",
    )

    version: str = "1.0"
    ai_agent: str = "claude"
    flag_formats: list[str] = Field(
        default_factory=lambda: [
            r"flag\{.*\}",
            r"CTF\{.*\}",
            r"picoCTF\{.*\}",
        ]
    )
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    api_keys: ApiKeysConfig = Field(default_factory=ApiKeysConfig)
    preferences: PreferencesConfig = Field(default_factory=PreferencesConfig)


# Global config instance
_config: Config | None = None


def find_repo_root(start_path: Path | None = None) -> Path | None:
    """Find the repository root by looking for .ctf-kit/ or .git/"""
    path = start_path or Path.cwd()

    for parent in [path, *list(path.parents)]:
        if (parent / ".ctf-kit").is_dir():
            return parent
        if (parent / ".git").is_dir():
            return parent

    return None


def load_config(path: Path | None = None) -> Config:
    """Load configuration from file."""
    config_data: dict[str, Any] = {}

    # Try repo-level config
    repo_root = find_repo_root(path)
    if repo_root:
        repo_config = repo_root / ".ctf-kit" / "config.yaml"
        if repo_config.exists():
            with repo_config.open() as f:
                config_data.update(yaml.safe_load(f) or {})

    # Try user-level config
    user_config = Path.home() / ".config" / "ctf-kit" / "config.yaml"
    if user_config.exists():
        with user_config.open() as f:
            user_data = yaml.safe_load(f) or {}
            # User config has lower priority, only fill missing values
            for key, value in user_data.items():
                if key not in config_data:
                    config_data[key] = value

    return Config(**config_data)


def get_config() -> Config:
    """Get the global config instance, loading if necessary."""
    global _config  # noqa: PLW0603
    if _config is None:
        _config = load_config()
    return _config


def save_config(config: Config, path: Path) -> None:
    """Save configuration to file."""
    config_dict = config.model_dump(exclude_none=True)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)


# Challenge-level configuration
@dataclass
class ChallengeConfig:
    """Configuration for a specific challenge."""

    name: str
    category: str | None = None
    flag_format: str | None = None
    solved: bool = False
    flag: str | None = None
    points: int | None = None
    tags: list[str] = field(default_factory=list)


def load_challenge_config(challenge_path: Path) -> ChallengeConfig | None:
    """Load challenge-specific configuration."""
    config_file = challenge_path / ".ctf" / "challenge.yaml"

    if not config_file.exists():
        return None

    with config_file.open() as f:
        data = yaml.safe_load(f) or {}

    return ChallengeConfig(**data)


def save_challenge_config(config: ChallengeConfig, challenge_path: Path) -> None:
    """Save challenge-specific configuration."""
    config_file = challenge_path / ".ctf" / "challenge.yaml"
    config_file.parent.mkdir(parents=True, exist_ok=True)

    with config_file.open("w") as f:
        yaml.dump(vars(config), f, default_flow_style=False)
