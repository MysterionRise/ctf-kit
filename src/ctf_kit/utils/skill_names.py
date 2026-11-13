"""Map detected CTF categories to their ``/ctf-kit:<skill>`` plugin commands.

The plugin skill names match the category values except for ``reversing``,
whose skill is ``reverse``. Other modules (for example ``ctf check --category``)
reuse :data:`CATEGORY_SKILL_NAMES` for the bare-name map.
"""

from ctf_kit.utils.file_detection import CTFCategory

#: Bare plugin skill name for each category (only reversing differs from its value).
CATEGORY_SKILL_NAMES: dict[CTFCategory, str] = {
    CTFCategory.CRYPTO: "crypto",
    CTFCategory.FORENSICS: "forensics",
    CTFCategory.STEGO: "stego",
    CTFCategory.WEB: "web",
    CTFCategory.PWN: "pwn",
    CTFCategory.REVERSING: "reverse",
    CTFCategory.OSINT: "osint",
    CTFCategory.MISC: "misc",
}


def skill_name(category: CTFCategory) -> str:
    """Return the plugin skill name for a category (``reversing`` -> ``reverse``)."""
    return CATEGORY_SKILL_NAMES.get(category, category.value)


def skill_command(category: CTFCategory) -> str:
    """Return the ``/ctf-kit:<skill>`` command for a category."""
    return f"/ctf-kit:{skill_name(category)}"
