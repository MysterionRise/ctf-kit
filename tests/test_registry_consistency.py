"""
Tests for registry consistency between _tool_registry and TOOL_REGISTRY.

Verifies that tools registered via decorators in integrations/base.py
have corresponding entries in check.py's TOOL_REGISTRY, and flags
any mismatches (Charge 1 remedy).
"""

from ctf_kit.commands.check import TOOL_REGISTRY
from ctf_kit.integrations.base import get_all_tools


def _get_check_tool_names() -> set[str]:
    """Collect all tool names from TOOL_REGISTRY (check.py)."""
    names: set[str] = set()
    for tools in TOOL_REGISTRY.values():
        names.update(tools.keys())
    return names


def test_registered_tools_appear_in_check_registry() -> None:
    """Every tool in _tool_registry should have an entry in TOOL_REGISTRY."""
    registered = set(get_all_tools().keys())
    check_names = _get_check_tool_names()

    # Some registered wrapper names may differ from check.py names.
    # Build a mapping of binary names from TOOL_REGISTRY for fuzzy matching.
    check_binaries: set[str] = set()
    for tools in TOOL_REGISTRY.values():
        for info in tools.values():
            check_binaries.add(info["binary"])

    missing: list[str] = []
    for tool_name in sorted(registered):
        if tool_name not in check_names and tool_name not in check_binaries:
            missing.append(tool_name)

    # Tools that have wrappers but are not in the static check.py catalog.
    # These are known gaps -- either the tool is accessed via a different
    # name in check.py (e.g. "volatility3" vs "volatility") or was added
    # as a wrapper without updating the static catalog.
    allowed_wrapper_only: set[str] = {
        "cyberchef",  # encoding tool, not in check.py catalog
        "dig",  # OSINT DNS tool
        "ghidra",  # reversing, not in check.py (only radare2 listed)
        "qrencode",  # misc QR tool
        "ropgadget",  # check.py uses "ROPgadget" (different casing)
        "rsactftool",  # crypto tool not in check.py
        "shodan",  # OSINT tool
        "theharvester",  # check.py uses "theHarvester" (different casing)
        "volatility",  # check.py uses "volatility3"
        "whois",  # OSINT tool
        "zbarimg",  # misc QR reader
    }

    unexpected = [t for t in missing if t not in allowed_wrapper_only]
    assert not unexpected, (
        f"Tools in _tool_registry but missing from TOOL_REGISTRY (check.py): {unexpected}. "
        "Either add them to TOOL_REGISTRY or add to allowed_wrapper_only with a comment."
    )


def test_check_registry_tools_have_wrappers() -> None:
    """Flag tools in TOOL_REGISTRY that lack a registered wrapper.

    This is informational -- not all tools need wrappers -- but helps
    track coverage gaps.
    """
    registered = set(get_all_tools().keys())
    check_names = _get_check_tool_names()

    # Tools in check.py that have no wrapper (expected for some)
    allowed_no_wrapper: set[str] = {
        # System utilities that don't need full wrappers
        "xxd",
        "python3",
        "openssl",
        "gdb",
        "ltrace",
        "strace",
        "stegsolve",
        "7z",
        "zip2john",
        "fcrackzip",
        "one_gadget",
        "pwntools",
        "objdump",
        "nm",
    }

    unwrapped = check_names - registered - allowed_no_wrapper
    # This is a soft check -- just ensure the set doesn't grow unexpectedly
    assert len(unwrapped) < 10, (
        f"Many tools in TOOL_REGISTRY lack wrappers: {sorted(unwrapped)}. "
        "Consider adding wrappers or updating allowed_no_wrapper."
    )
