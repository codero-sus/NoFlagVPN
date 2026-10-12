#!/usr/bin/env python3
"""Update a NoFlagVPN checkout in place.

This is the cross-platform updater; ``updater.sh`` and ``updater.bat`` are thin
wrappers around it, so all three behave identically.

What it does
------------
1. Finds the checkout this script lives in.
2. Refuses to touch a working tree with uncommitted changes unless ``--force``
   is given (in which case the changes are stashed and restored).
3. ``git fetch``\\ es the branch, fast-forwards, and reports what changed.
4. Reinstalls the console script if ``pyproject.toml`` changed *and* nfvpn is
   already installed as a package, so ``nfvpn --version`` matches the checkout.

It never touches your keys, membership file or configs: those live in the
config directory (``~/.config/nfvpn`` by default, or ``NFVPN_CONFIG_DIR``), not
in the repository.

Usage
-----
    python updater.py                 # update to the tip of this branch
    python updater.py --check         # say whether an update exists, change nothing
    python updater.py --branch main   # track a different branch
    python updater.py --force         # update even with local changes (stashed)
    python updater.py --no-install    # never run pip

Exit codes
----------
``0`` already up to date, or updated successfully · ``1`` something failed ·
``10`` an update is available (only with ``--check``) · ``2`` bad usage.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_URL = "https://github.com/codero-sus/NoFlagVPN"
DEFAULT_BRANCH = "main"
DEFAULT_REMOTE = "origin"

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_UPDATE_AVAILABLE = 10
EXIT_USAGE = 2

STASH_MESSAGE = "nfvpn-updater: automatic stash"

#: Files whose change means the installed package needs refreshing.
_REINSTALL_TRIGGERS = ("pyproject.toml", "setup.py", "setup.cfg", "nfvpn/__init__.py")


class UpdateError(Exception):
    """Anything that stops the update, with a message a person can act on."""


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def git(*args: str, cwd: Path, check: bool = True) -> str:
    """Run git and return its stdout, or raise :class:`UpdateError`."""
    if shutil.which("git") is None:
        raise UpdateError(
            "git is not installed.  Install it, or download the project again from "
            f"{PROJECT_URL}"
        )
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise UpdateError(f"git {' '.join(args)} failed: {detail[-1] if detail else 'no output'}")
    return result.stdout.strip()


def script_root() -> Path:
    """The checkout this script lives in."""
    return Path(__file__).resolve().parent


def local_version(root: Path) -> str:
    """Read the version without importing the package (it may not be importable)."""
    version_file = root / "nfvpn" / "version.py"
    try:
        text = version_file.read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if match:
        return match.group(1)
    numbers = re.search(r"__version_info__\s*=\s*\(([^)]*)\)", text)
    if numbers:
        parts = [part.strip() for part in numbers.group(1).split(",") if part.strip()]
        if parts:
            return ".".join(parts)
    return "unknown"


def working_tree_changes(root: Path) -> list:
    """Paths with uncommitted changes, staged or not."""
    output = git("status", "--porcelain", cwd=root, check=False)
    return [line[3:].strip() for line in output.splitlines() if line.strip()]


def current_branch(root: Path) -> str:
    name = git("rev-parse", "--abbrev-ref", "HEAD", cwd=root, check=False)
    # A detached HEAD reports "HEAD"; tracking the default branch is the sane
    # interpretation of "update me" in that state.
    return name if name and name != "HEAD" else DEFAULT_BRANCH


def describe(root: Path, revision: str) -> str:
    line = git("log", "-1", "--pretty=%h %s", revision, cwd=root, check=False)
    return line or revision


def is_installed_package() -> bool:
    """Is nfvpn importable from this interpreter, i.e. worth reinstalling?"""
    try:
        import importlib.util

        return importlib.util.find_spec("nfvpn") is not None
    except Exception:  # pragma: no cover - defensive
        return False


def running_processes() -> list:
    """Best-effort list of running nfvpn commands, so we can warn about restarts."""
    names = []
    try:
        if os.name == "nt":  # pragma: no cover - Windows
            output = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout
            if "python" in output.lower():
                names.append("python.exe")
        else:
            listing = subprocess.run(
                ["ps", "-eo", "args"], capture_output=True, text=True, check=False
            ).stdout
            for line in listing.splitlines():
                if "nfvpn" in line and (" serve" in line or " connect" in line):
                    names.append(line.strip()[:120])
    except Exception:  # pragma: no cover - a missing ps is not an error
        return []
    return names


# --------------------------------------------------------------------------- #
# the update
# --------------------------------------------------------------------------- #
def fetch(remote: str, branch: str, root: Path) -> str:
    """Fetch ``branch`` from ``remote``; returns the fetched commit."""
    git("fetch", "--prune", remote, branch, cwd=root)
    return git("rev-parse", "FETCH_HEAD", cwd=root)


def fast_forward(root: Path, target: str, branch: str) -> None:
    """Move the checkout to ``target``, refusing to merge anything by itself."""
    on_branch = current_branch(root)
    if on_branch != branch:
        git("checkout", branch, cwd=root)
    result = subprocess.run(
        ["git", "merge", "--ff-only", target],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise UpdateError(
            f"could not fast-forward {branch} to {target}: {detail}\n"
            "Your branch has diverged from the remote.  Resolve it with git "
            "(git status, git rebase, git pull), or re-clone the project."
        )


def changed_files(root: Path, old: str, new: str) -> list:
    output = git("diff", "--name-only", f"{old}..{new}", cwd=root, check=False)
    return [line for line in output.splitlines() if line.strip()]


def reinstall(root: Path, quiet: bool) -> None:
    """Refresh the editable install so the console script matches the checkout."""
    if not is_installed_package() and not shutil.which("nfvpn"):
        return
    say(quiet, "reinstalling the package (pyproject.toml changed)…")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--editable", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        say(
            quiet,
            "  pip could not reinstall it (that is not fatal; the checkout is updated):",
            f"  {detail[-1] if detail else 'no output'}",
            "  fix it later with:  python -m pip install -e .",
        )
    else:
        say(quiet, "  reinstalled.")


def say(quiet: bool, *lines: str) -> None:
    if not quiet:
        for line in lines:
            print(line, flush=True)


def update(args: argparse.Namespace) -> int:
    root = script_root()
    if not (root / ".git").exists():
        raise UpdateError(
            f"{root} is not a git checkout.\n"
            "Downloading a zip does not give you an updatable copy; clone it instead:\n"
            f"    git clone {PROJECT_URL}.git nfvpn && cd nfvpn"
        )

    branch = args.branch or current_branch(root)
    before = git("rev-parse", "HEAD", cwd=root)
    version_before = local_version(root)

    say(not args.quiet, f"repository   {root}")
    say(not args.quiet, f"branch       {branch}  ({describe(root, before)})")
    say(not args.quiet, f"version      {version_before}")

    changes = working_tree_changes(root)
    if changes and not (args.force or args.check):
        listing = "\n".join(f"    {name}" for name in changes[:10])
        raise UpdateError(
            "there are uncommitted changes in the checkout:\n"
            f"{listing}\n"
            "Commit or discard them, or run the updater with --force to have them "
            "stashed and restored around the update."
        )
    if changes:
        say(not args.quiet, f"note         {len(changes)} uncommitted file(s) will be stashed")

    say(not args.quiet, f"fetching     {args.remote}/{branch} …")
    target = fetch(args.remote, branch, root)

    if target == before:
        say(not args.quiet, "", "Already up to date.")
        return EXIT_OK

    behind = git("rev-list", "--count", f"HEAD..{target}", cwd=root, check=False) or "?"
    say(not args.quiet, f"incoming     {describe(root, target)}  ({behind} commit(s) ahead)")

    if args.check:
        say(
            not args.quiet,
            "",
            "An update is available.  Run this script without --check to install it.",
        )
        return EXIT_UPDATE_AVAILABLE

    if args.dry_run:
        say(not args.quiet, "dry run: nothing was changed.")
        return EXIT_UPDATE_AVAILABLE

    stashed = False
    if changes and args.force:
        say(not args.quiet, "stashing     local changes …")
        git("stash", "push", "--include-untracked", "-m", STASH_MESSAGE, cwd=root)
        stashed = True

    try:
        fast_forward(root, target, branch)
    finally:
        if stashed:
            result = subprocess.run(
                ["git", "stash", "pop"],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip().splitlines()
                say(
                    not args.quiet,
                    "",
                    "Your local changes could not be restored cleanly and are safe in a stash.",
                    "Recover them with:  git stash list  &&  git stash pop",
                )
                if detail:
                    say(not args.quiet, f"  {detail[-1]}")
            else:
                say(not args.quiet, "restored     local changes")

    after = git("rev-parse", "HEAD", cwd=root)
    version_after = local_version(root)
    touched = changed_files(root, before, after)

    say(not args.quiet, "")
    say(not args.quiet, f"updated      {version_before} → {version_after}")
    if version_before == version_after:
        say(not args.quiet, "             (the version string did not change)")
    for name in touched[:15]:
        say(not args.quiet, f"  changed    {name}")
    if len(touched) > 15:
        say(not args.quiet, f"  … and {len(touched) - 15} more file(s)")

    if any(name in touched for name in _REINSTALL_TRIGGERS) and not args.no_install:
        reinstall(root, args.quiet)

    running = running_processes()
    if running:
        say(
            not args.quiet,
            "",
            "Restart these to run the new code:",
            *[f"    {line}" for line in running[:5]],
        )

    say(not args.quiet, "", "Done.  `nfvpn selftest` will confirm everything still works.")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="updater.py",
        description="Update this NoFlagVPN checkout in place.",
        epilog=f"Project: {PROJECT_URL}",
    )
    parser.add_argument("--check", action="store_true", help="report whether an update exists")
    parser.add_argument("--dry-run", action="store_true", help="fetch, then stop short of updating")
    parser.add_argument("--branch", help=f"branch to track (default: the current one, else {DEFAULT_BRANCH})")
    parser.add_argument("--remote", default=DEFAULT_REMOTE, help="git remote (default: origin)")
    parser.add_argument("--force", action="store_true", help="stash local changes and update anyway")
    parser.add_argument("--no-install", action="store_true", help="never run pip")
    parser.add_argument("--quiet", action="store_true", help="only print errors")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return update(args)
    except UpdateError as exc:
        print(f"updater: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print("updater: interrupted", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
