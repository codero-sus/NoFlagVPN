#!/usr/bin/env python3
"""Build a tiny, dependency-free NoFlagVPN relay zipapp.

The output is a compressed Python zipapp, not a native machine-code binary. It
contains only the ``nfvpn`` package and a relay-only entry point, needs no pip
install on the destination machine, and runs with Python 3.10 or newer.
"""

from __future__ import annotations

import argparse
import shutil
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = Path("dist/nfvpn-mini-server.pyz")
MAIN_SCRIPT = '''"""Self-contained NoFlagVPN relay entry point."""
from nfvpn.mini_server import main
raise SystemExit(main())
'''


def build_mini_server(output: Path, *, interpreter: str = "/usr/bin/env python3") -> Path:
    """Create a compressed relay-only zipapp at ``output`` and make it executable."""
    target = output.expanduser().resolve()
    package = ROOT / "nfvpn"
    if not package.is_dir():
        raise FileNotFoundError(f"NoFlagVPN package not found: {package}")
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="nfvpn-mini-server-") as temporary:
        staging = Path(temporary)
        shutil.copytree(
            package,
            staging / "nfvpn",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (staging / "__main__.py").write_text(MAIN_SCRIPT, encoding="utf-8")
        zipapp.create_archive(
            staging,
            target=target,
            interpreter=interpreter or None,
            compressed=True,
        )

    target.chmod(target.stat().st_mode | 0o111)
    return target


def main(argv: list[str] | None = None) -> int:
    """CLI for the build tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"zipapp destination (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--interpreter",
        default="/usr/bin/env python3",
        help="zipapp shebang (use an empty value to omit it)",
    )
    args = parser.parse_args(argv)
    artifact = build_mini_server(args.output, interpreter=args.interpreter)
    print(f"Built {artifact} ({artifact.stat().st_size:,} bytes)")
    command = f"{artifact} --help" if args.interpreter else f"python3 {artifact} --help"
    print(f"Run it with Python 3.10+: {command}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess in tests
    raise SystemExit(main())
