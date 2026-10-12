"""Command-line interface for ``python -m nfvpn``."""

from __future__ import annotations

from nfvpn.cli.commands import *  # noqa: F403
from nfvpn.cli.main import build_parser, main

__all__ = ["build_parser", "main"]
