"""Single source of truth for the version string."""

from __future__ import annotations

__all__ = ["__version__", "__version_info__"]

__version_info__ = (0, 1, 0)
__version__ = ".".join(str(part) for part in __version_info__)
