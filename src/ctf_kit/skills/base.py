"""
Base classes for CTF Kit skills.

Skills are AI-facing interfaces that orchestrate tools to solve
specific types of CTF challenges.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from ctf_kit.integrations.base import BaseTool, ToolResult


@dataclass
class SkillResult:
    """
    Standard result format for skill operations.

    Provides structured output for AI agents to understand and act upon.
    """

    success: bool
    skill_name: str
    analysis: dict[str, Any]
    suggestions: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)
    confidence: float = 0.0  # 0-1 confidence in the analysis

    def __str__(self) -> str:
        status = "✅" if self.success else "❌"
        return f"{status} {self.skill_name}: {len(self.suggestions)} suggestions"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "skill_name": self.skill_name,
            "analysis": self.analysis,
            "suggestions": self.suggestions,
            "next_steps": self.next_steps,
            "tool_results": [r.to_dict() for r in self.tool_results],
            "artifacts": [str(p) for p in self.artifacts],
            "confidence": self.confidence,
        }

    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            f"## {self.skill_name} Analysis",
            "",
        ]

        if self.analysis:
            lines.append("### Findings")
            for key, value in self.analysis.items():
                if isinstance(value, list):
                    lines.append(f"- **{key}**: {len(value)} items")
                elif isinstance(value, dict):
                    lines.append(f"- **{key}**: {len(value)} entries")
                else:
                    lines.append(f"- **{key}**: {value}")
            lines.append("")

        if self.suggestions:
            lines.append("### Suggestions")
            lines.extend(f"- {suggestion}" for suggestion in self.suggestions)
            lines.append("")

        if self.next_steps:
            lines.append("### Next Steps")
            for i, step in enumerate(self.next_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        return "\n".join(lines)


class BaseSkill(ABC):
    """
    Base class for CTF Kit skills.

    Skills orchestrate tools to analyze and solve specific challenge types.
    They provide a higher-level interface for AI agents.

    Subclasses must define:
    - name: Skill name
    - description: What the skill does
    - category: Challenge category this skill handles
    - tool_names: Names of tools this skill uses

    Subclasses should implement:
    - analyze(): Analyze challenge files
    - suggest_approach(): Suggest solving approaches
    - execute(): Execute a specific approach
    """

    name: ClassVar[str] = "base_skill"
    description: ClassVar[str] = ""
    category: ClassVar[str] = "misc"
    tool_names: ClassVar[list[str]] = []

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}
        self._load_tools()

    def _load_tools(self) -> None:
        """Load required tools from registry."""
        from ctf_kit.integrations.base import get_tool

        for tool_name in self.tool_names:
            tool = get_tool(tool_name)
            if tool:
                self._tools[tool_name] = tool

    @property
    def available_tools(self) -> list[str]:
        """List tools that are installed and available."""
        return [name for name, tool in self._tools.items() if tool.is_installed]

    @property
    def missing_tools(self) -> list[str]:
        """List tools that are required but not installed."""
        return [name for name, tool in self._tools.items() if not tool.is_installed]

    def check_requirements(self) -> dict[str, bool]:
        """Check which required tools are available."""
        return {name: tool.is_installed for name, tool in self._tools.items()}

    @abstractmethod
    def analyze(self, path: Path) -> SkillResult:
        """
        Analyze challenge files and provide insights.

        Args:
            path: Path to challenge file or directory

        Returns:
            SkillResult with analysis and suggestions
        """

    @abstractmethod
    def suggest_approach(self, analysis: dict[str, Any]) -> list[str]:
        """
        Suggest approaches based on analysis.

        Args:
            analysis: Analysis data from analyze()

        Returns:
            List of suggested approaches
        """

    def get_tool(self, name: str) -> BaseTool | None:
        """Get a specific tool by name."""
        return self._tools.get(name)

    def run_tool(self, name: str, *args: Any, **kwargs: Any) -> ToolResult | None:
        """Run a tool and return its result."""
        tool = self._tools.get(name)
        if tool:
            return tool.run(*args, **kwargs)
        return None

    def __repr__(self) -> str:
        available = len(self.available_tools)
        total = len(self.tool_names)
        return f"{self.name} ({available}/{total} tools available)"


# Skill registry for discovery
_skill_registry: dict[str, type[BaseSkill]] = {}


def register_skill(cls: type[BaseSkill]) -> type[BaseSkill]:
    """Decorator to register a skill class."""
    _skill_registry[cls.name] = cls
    return cls


def get_skill(name: str) -> BaseSkill | None:
    """Get a skill instance by name."""
    if name in _skill_registry:
        return _skill_registry[name]()
    return None


def get_all_skills() -> dict[str, BaseSkill]:
    """Get all registered skills."""
    return {name: cls() for name, cls in _skill_registry.items()}


def get_skills_by_category(category: str) -> dict[str, BaseSkill]:
    """Get all skills for a category."""
    return {name: cls() for name, cls in _skill_registry.items() if cls.category == category}
