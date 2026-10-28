"""Small relay-only entry point for the mini-server zipapp and console script.

The regular ``nfvpn`` command remains the full administration CLI. This entry
point exposes only ``serve`` so a minimal relay deployment does not need the
client and management command tree in its user-facing interface.
"""

from __future__ import annotations

import sys

from nfvpn.cli.main import main as cli_main

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    """Run the relay command, defaulting to ``./config.json``."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not any(item == "--config" or item.startswith("--config=") for item in arguments):
        arguments = ["--config", "config.json", *arguments]
    return cli_main(["serve", *arguments])


if __name__ == "__main__":  # pragma: no cover - covered by entry-point tests
    raise SystemExit(main())
