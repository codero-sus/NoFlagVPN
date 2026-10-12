"""The updater: it must never lose work, and never touch secrets.

The updater is the one piece of this project that moves files around inside the
user's checkout, so the tests care about the destructive paths: a dirty tree, a
diverged branch, and the tokens that appear in a running process list.  The
end-to-end test builds two throwaway git repositories on disk, so nothing here
touches the network or the real checkout.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import updater  # noqa: E402  (the script is not a package module)

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="the updater needs git"
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def init_repo(path: Path, *, branch: str = "main") -> Path:
    """A repository with an identity configured and one commit."""
    path.mkdir(parents=True, exist_ok=True)
    git("init", "-q", f"--initial-branch={branch}", cwd=path)
    git("config", "user.name", "NoFlagVPN tests", cwd=path)
    git("config", "user.email", "tests@nfvpn.invalid", cwd=path)
    git("config", "commit.gpgsign", "false", cwd=path)
    return path


def commit_file(path: Path, name: str, content: str, message: str) -> str:
    (path / name).write_text(content, encoding="utf-8")
    git("add", name, cwd=path)
    git("commit", "-q", "-m", message, cwd=path)
    return git("rev-parse", "HEAD", cwd=path)


def run_updater(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "updater.py", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


# --------------------------------------------------------------------------- #
# pure functions
# --------------------------------------------------------------------------- #
def test_the_version_is_read_from_this_project():
    assert updater.local_version(REPO_ROOT) == "0.1.0"


def test_the_version_parser_ignores_a_computed_version_string(tmp_path):
    """A project may define __version__ as a join; that must not be read as '.'."""
    (tmp_path / "nfvpn").mkdir()
    (tmp_path / "nfvpn" / "version.py").write_text(
        '__version_info__ = (2, 3, 4)\n__version__ = ".".join(map(str, __version_info__))\n',
        encoding="utf-8",
    )
    assert updater.local_version(tmp_path) == "2.3.4"

    (tmp_path / "nfvpn" / "version.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    assert updater.local_version(tmp_path) == "9.9.9"


def test_a_missing_version_file_is_not_a_crash(tmp_path):
    assert updater.local_version(tmp_path) == "unknown"


@pytest.mark.parametrize(
    "command",
    [
        "nfvpn connect --token nfvpn://SECRETVALUE --listen 127.0.0.1:8080",
        "nfvpn connect --token=nfvpn://SECRETVALUE --listen 127.0.0.1:8080",
        "nfvpn member add --psk SECRETVALUE --name laptop",
        "nfvpn token --member laptop",
    ],
)
def test_secrets_are_redacted_from_printed_command_lines(command):
    output = updater.redact(command)
    assert "SECRETVALUE" not in output
    assert "nfvpn" in output


def test_the_parser_defaults_are_sane():
    args = updater.build_parser().parse_args([])
    assert args.remote == "origin"
    assert args.check is False
    assert args.force is False
    assert args.branch is None


# --------------------------------------------------------------------------- #
# refusing to do damage
# --------------------------------------------------------------------------- #
def test_a_directory_that_is_not_a_checkout_is_refused(tmp_path):
    shutil.copy(REPO_ROOT / "updater.py", tmp_path / "updater.py")
    result = run_updater(tmp_path, "--check")
    assert result.returncode == 1
    assert "not a git checkout" in result.stderr
    assert "git clone" in result.stderr


def test_uncommitted_changes_stop_the_update(tmp_path):
    work, clone = build_pair(tmp_path)
    commit_file(work, "new.txt", "new\n", "second")
    git("push", "-q", git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)
    before = git("rev-parse", "HEAD", cwd=clone)

    (clone / "nfvpn" / "version.py").write_text("# edited by hand\n", encoding="utf-8")
    result = run_updater(clone)
    assert result.returncode == 1
    assert "uncommitted changes" in result.stderr
    assert (clone / "nfvpn" / "version.py").read_text(encoding="utf-8") == "# edited by hand\n"
    assert git("rev-parse", "HEAD", cwd=clone) == before


# --------------------------------------------------------------------------- #
# the update itself
# --------------------------------------------------------------------------- #
def build_pair(tmp_path: Path) -> tuple[Path, Path]:
    """(working repo, clone of it) with the updater committed in both."""
    work = init_repo(tmp_path / "work")
    shutil.copy(REPO_ROOT / "updater.py", work / "updater.py")
    (work / "nfvpn").mkdir()
    shutil.copy(REPO_ROOT / "nfvpn" / "version.py", work / "nfvpn" / "version.py")
    git("add", "-A", cwd=work)
    git("commit", "-q", "-m", "first", cwd=work)

    remote = tmp_path / "remote.git"
    git("clone", "-q", "--bare", str(work), str(remote), cwd=tmp_path)
    clone = tmp_path / "clone"
    git("clone", "-q", str(remote), str(clone), cwd=tmp_path)
    git("config", "user.name", "NoFlagVPN tests", cwd=clone)
    git("config", "user.email", "tests@nfvpn.invalid", cwd=clone)
    git("remote", "set-url", "origin", str(remote), cwd=clone)
    return work, clone


def test_an_up_to_date_checkout_says_so(tmp_path):
    _work, clone = build_pair(tmp_path)
    result = run_updater(clone, "--check")
    assert result.returncode == 0
    assert "Already up to date" in result.stdout


def test_check_reports_an_available_update_without_applying_it(tmp_path):
    work, clone = build_pair(tmp_path)
    before = git("rev-parse", "HEAD", cwd=clone)
    commit_file(work, "new.txt", "new\n", "second")
    git("push", "-q", clone.absolute() and git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)

    result = run_updater(clone, "--check")
    assert result.returncode == 10
    assert "update is available" in result.stdout.lower()
    assert git("rev-parse", "HEAD", cwd=clone) == before, "--check must not move HEAD"


def test_the_update_fast_forwards_and_keeps_user_changes(tmp_path):
    work, clone = build_pair(tmp_path)
    commit_file(work, "new.txt", "new\n", "second")
    git("push", "-q", git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)
    target = git("rev-parse", "HEAD", cwd=work)

    # An untracked scratch file must survive an update; it is not the updater's
    # business, and people keep notes and scripts next to a checkout.
    (clone / "notes.txt").write_text("mine\n", encoding="utf-8")

    result = run_updater(clone)
    assert result.returncode == 0, result.stderr
    assert "1 commit(s) ahead" in result.stdout
    assert git("rev-parse", "HEAD", cwd=clone) == target
    assert (clone / "new.txt").read_text(encoding="utf-8") == "new\n"
    assert (clone / "notes.txt").read_text(encoding="utf-8") == "mine\n"


def test_force_stashes_and_restores_local_edits(tmp_path):
    work, clone = build_pair(tmp_path)
    commit_file(work, "new.txt", "new\n", "second")
    git("push", "-q", git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)

    edited = clone / "nfvpn" / "version.py"
    edited.write_text("# a local edit that must survive\n", encoding="utf-8")

    result = run_updater(clone, "--force")
    assert result.returncode == 0, result.stderr
    assert "stashing" in result.stdout
    assert "restored" in result.stdout
    # Upstream landed, and the hand edit is back in the working tree.
    assert (clone / "new.txt").exists()
    assert edited.read_text(encoding="utf-8") == "# a local edit that must survive\n"
    assert git("status", "--porcelain", cwd=clone)


def test_a_checkout_that_is_already_ahead_is_not_an_update(tmp_path):
    """Fast-forwarding to an ancestor is a silent no-op; do not report it."""
    _work, clone = build_pair(tmp_path)
    commit_file(clone, "local.txt", "mine\n", "local work")
    head = git("rev-parse", "HEAD", cwd=clone)

    result = run_updater(clone)
    assert result.returncode == 0, result.stderr
    assert "Nothing to do" in result.stdout
    assert "updated" not in result.stdout
    assert git("rev-parse", "HEAD", cwd=clone) == head


def test_a_detached_head_follows_the_branch_at_that_commit(tmp_path):
    """`git checkout <sha>` then updating must not jump to the default branch."""
    work, clone = build_pair(tmp_path)
    git("checkout", "-q", "--detach", "HEAD", cwd=clone)
    commit_file(work, "new.txt", "new\n", "second")
    git("push", "-q", git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)
    target = git("rev-parse", "HEAD", cwd=work)

    result = run_updater(clone)
    assert result.returncode == 0, result.stderr
    assert "branch       main" in result.stdout
    assert "HEAD is not on a branch" in result.stdout
    assert git("rev-parse", "HEAD", cwd=clone) == target


def test_an_unrelated_history_is_refused(tmp_path):
    """A remote with nothing in common must not be merged into this checkout."""
    _work, clone = build_pair(tmp_path)
    unrelated = init_repo(tmp_path / "unrelated")
    commit_file(unrelated, "other.txt", "other\n", "unrelated")
    git("remote", "add", "elsewhere", str(unrelated), cwd=clone)
    before = git("rev-parse", "HEAD", cwd=clone)

    result = run_updater(clone, "--remote", "elsewhere")
    assert result.returncode == 1
    assert "diverged" in result.stderr
    assert git("rev-parse", "HEAD", cwd=clone) == before


def test_a_diverged_branch_explains_itself(tmp_path):
    work, clone = build_pair(tmp_path)
    commit_file(clone, "local.txt", "mine\n", "local work")
    commit_file(work, "upstream.txt", "theirs\n", "upstream work")
    git("push", "-q", git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)

    result = run_updater(clone)
    assert result.returncode == 1
    assert "diverged" in result.stderr
    assert "nothing was changed" in result.stderr
    # The local commit is untouched.
    assert (clone / "local.txt").read_text(encoding="utf-8") == "mine\n"


def test_dry_run_fetches_but_changes_nothing(tmp_path):
    work, clone = build_pair(tmp_path)
    commit_file(work, "new.txt", "new\n", "second")
    git("push", "-q", git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)
    before = git("rev-parse", "HEAD", cwd=clone)

    result = run_updater(clone, "--dry-run")
    assert result.returncode == 10
    assert git("rev-parse", "HEAD", cwd=clone) == before


def test_quiet_only_prints_when_something_happens(tmp_path):
    _work, clone = build_pair(tmp_path)
    result = run_updater(clone, "--check", "--quiet")
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_no_install_never_calls_pip(tmp_path):
    work, clone = build_pair(tmp_path / "a")
    commit_file(work, "pyproject.toml", "[project]\nname='x'\n", "add pyproject")
    git("push", "-q", git("remote", "get-url", "origin", cwd=clone), "main", cwd=work)

    result = subprocess.run(
        [sys.executable, "updater.py", "--no-install"],
        cwd=str(clone),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )
    assert result.returncode == 0, result.stderr
    assert "reinstalling" not in result.stdout
