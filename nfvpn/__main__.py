"""``python -m nfvpn`` — the command-line entry point."""

from __future__ import annotations

import sys

from nfvpn.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
