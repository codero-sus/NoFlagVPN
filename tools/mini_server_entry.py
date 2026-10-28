"""PyInstaller entry point for the native relay executable."""

from __future__ import annotations

from nfvpn.mini_server import main

if __name__ == "__main__":
    raise SystemExit(main())
