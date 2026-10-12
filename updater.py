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
    numbers = re.search(r"__version_info__\s*=\s*\(([^)]*)\)", text)
    if numbers:
        parts = [part.strip() for part in numbers.group(1).split(",") if part.strip()]
        if parts:
            return ".".join(parts)
    # Only a literal version, and only one that starts with a digit: this module
    # may define __version__ as a computed string such as ".".join(...).
    match = re.search(r'^__version__\s*=\s*["\'](\d[^"\']*)["\']', text, re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown"


def working_tree_changes(root: Path) -> list:
    """Tracked paths with uncommitted changes, staged or not.

    Untracked files are deliberately *not* included: a checkout with someone's
    notes in it is normal, and git itself refuses a fast-forward that would
    overwrite one.  They are reported separately and left alone.
    """
    output = git("status", "--porcelain", "--untracked-files=no", cwd=root, check=False)
    return [line[3:].strip() for line in output.splitlines() if line.strip()]


def untracked_files(root: Path) -> list:
    """Files git is not tracking and would not overwrite, ignored files aside."""
    output = git("ls-files", "--others", "--exclude-standard", cwd=root, check=False)
    return [line.strip() for line in output.splitlines() if line.strip()]


def current_branch(root: Path) -> str:
    """The branch this checkout tracks: the current one, or the one at HEAD."""
    name = git("rev-parse", "--abbrev-ref", "HEAD", cwd=root, check=False)
    if name and name != "HEAD":
        return name
    # A detached HEAD reports "HEAD".  If some branch points at this commit then
    # that branch is what "this checkout" means; the default branch is only the
    # last resort, and update() says so out loud when it is used.
    # for-each-ref over refs/heads: `git branch --points-at` also prints a
    # "(HEAD detached at …)" pseudo-entry, which is not a branch name.
    pointed = git(
        "for-each-ref",
        "--points-at",
        "HEAD",
        "--format=%(refname:short)",
        "refs/heads/",
        cwd=root,
        check=False,
    )
    for candidate in pointed.splitlines():
        if candidate.strip():
            return candidate.strip()
    return DEFAULT_BRANCH


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


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


def redact(command: str) -> str:
    """Hide the value of any secret-bearing flag before printing a command line.

    A running ``nfvpn connect`` has an invite token in its argv, and the token
    contains the pre-shared key.  The updater prints command lines, so it
    redacts them first.
    """
    secret_flags = ("--token", "--psk")
    words = command.split()
    for index, word in enumerate(words[:-1]):
        if word.split("=", 1)[0] in secret_flags:
            if "=" in word:
                words[index] = word.split("=", 1)[0] + "=…"
            else:
                words[index + 1] = "…"
    return " ".join(words)


def running_processes() -> list:
    """Best-effort list of running nfvpn commands, so we can warn about restarts."""
    found = []
    try:
        if os.name == "nt":  # pragma: no cover - Windows
            output = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout
            if "python" in output.lower():
                found.append(("", "python.exe (check it is the right one)"))
        else:
            listing = subprocess.run(
                ["ps", "-eo", "pid,args"], capture_output=True, text=True, check=False
            ).stdout
            for line in listing.splitlines()[1:]:
                pid, _, command = line.strip().partition(" ")
                if "nfvpn" not in command:
                    continue
                if " serve" not in command and " connect" not in command:
                    continue
                found.append((pid, redact(command.strip())[:110]))
    except Exception:  # pragma: no cover - a missing ps is not an error
        return []
    return found


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


def reinstall(root: Path, verbose: bool) -> None:
    """Refresh the editable install so the console script matches the checkout."""
    if not is_installed_package() and not shutil.which("nfvpn"):
        return
    say(verbose, "reinstalling the package (pyproject.toml changed)…")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--editable", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        say(
            verbose,
            "  pip could not reinstall it (that is not fatal; the checkout is updated):",
            f"  {detail[-1] if detail else 'no output'}",
            "  fix it later with:  python -m pip install -e .",
        )
    else:
        say(verbose, "  reinstalled.")


def say(verbose: bool, *lines: str) -> None:
    """Print unless the caller asked for quiet; ``verbose`` is ``not --quiet``."""
    if verbose:
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
    detached = git("rev-parse", "--abbrev-ref", "HEAD", cwd=root, check=False) == "HEAD"

    say(not args.quiet, f"repository   {root}")
    say(not args.quiet, f"branch       {branch}  ({describe(root, before)})")
    if detached:
        say(
            not args.quiet,
            f"note         HEAD is not on a branch; tracking {branch} "
            "(use --branch to choose another)",
        )
    say(not args.quiet, f"version      {version_before}")

    changes = working_tree_changes(root)
    loose = untracked_files(root) if not args.check else []
    if loose and not args.quiet:
        say(not args.quiet, f"note         {len(loose)} untracked file(s) will be left alone")
    if changes and not (args.force or args.check):
        listing = "\n".join(f"    {name}" for name in changes[:10])
        raise UpdateError(
            "there are uncommitted changes in the checkout:\n"
            f"{listing}\n"
            "Commit or discard them, or run the updater with --force to have them "
            "stashed and restored around the update."
        )
    if changes and not args.check:
        say(not args.quiet, f"note         {len(changes)} uncommitted file(s) will be stashed")

    say(not args.quiet, f"fetching     {args.remote}/{branch} …")
    target = fetch(args.remote, branch, root)

    if target == before:
        say(not args.quiet, "", "Already up to date.")
        return EXIT_OK

    if is_ancestor(root, target, before):
        # HEAD already contains the remote tip: a local commit, or a checkout of
        # something newer.  Merging an ancestor is a silent no-op, and reporting
        # that as an update would be a lie.
        say(
            not args.quiet,
            "",
            f"Nothing to do: {before[:12]} already contains {args.remote}/{branch}.",
        )
        return EXIT_OK

    if not is_ancestor(root, before, target):
        raise UpdateError(
            f"this checkout and {args.remote}/{branch} have diverged:\n"
            f"    HEAD          {describe(root, before)}\n"
            f"    {args.remote}/{branch}  {describe(root, target)}\n"
            "Fast-forwarding would throw away local commits, so nothing was "
            "changed.  Reconcile them with git (status, rebase, pull), or "
            "re-clone the project."
        )

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
        # Tracked changes only: untracked files are none of the update's
        # business and stashing them can sweep up a whole build directory.
        say(not args.quiet, "stashing     local changes …")
        git("stash", "push", "-m", STASH_MESSAGE, cwd=root)
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
    if after != target:
        # Belt and braces: never report success unless HEAD is where we aimed.
        raise UpdateError(
            f"HEAD is at {after[:12]} after the update, not {target[:12]}.  "
            "Inspect the checkout with: git status && git log --oneline -5"
        )
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
        reinstall(root, not args.quiet)

    running = running_processes()
    if running:
        say(
            not args.quiet,
            "",
            "Restart these to run the new code:",
            *[f"    pid {pid:<7} {command}" if pid else f"    {command}" for pid, command in running[:5]],
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
