"""Repository validation and a safe, read-only wrapper around the Git CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

# Config overrides applied to every command: the scanned repository is untrusted,
# so nothing in its local config may run code (fsmonitor) or write back (auto gc).
_SAFE_CONFIG = (
    "-c", "core.fsmonitor=false",
    "-c", "core.untrackedCache=false",
    "-c", "gc.auto=0",
    "-c", "maintenance.auto=false",
)  # fmt: skip


class GitError(RuntimeError):
    """A Git command failed or the target is not a usable repository."""


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        GIT_OPTIONAL_LOCKS="0",  # never refresh/write the index while reading
        GIT_TERMINAL_PROMPT="0",  # never block on credential prompts
        GIT_PAGER="cat",
        LC_ALL="C",  # stable, parseable messages
    )
    return env


def run_git(
    repo: Path,
    *args: str,
    input: bytes | None = None,
    check: bool = True,
) -> bytes:
    """Run ``git -C <repo> <args>`` without a shell and return raw stdout bytes.

    Output stays as bytes because blobs may be binary; callers decode as needed.
    With ``check=False`` the caller accepts non-zero exits (e.g. ``fsck`` on a
    corrupted repository still prints useful findings).
    """
    git = shutil.which("git")
    if git is None:
        raise GitError("git executable not found on PATH")

    command = [git, *_SAFE_CONFIG, "-C", str(repo), *args]
    try:
        result = subprocess.run(  # noqa: S603 - fixed executable, argument list, no shell
            command,
            input=input,
            capture_output=True,
            env=_git_env(),
            check=False,
        )
    except OSError as exc:
        raise GitError(f"cannot execute git: {exc}") from exc

    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitError(f"git {' '.join(args)} failed ({result.returncode}): {stderr}")
    return result.stdout


def validate_repository(path: str | os.PathLike[str]) -> Path:
    """Return the absolute path of a local Git repository (work tree or bare).

    Raises ``GitError`` if the path does not exist or is not inside a repository.
    """
    repo = Path(path).resolve()
    if not repo.is_dir():
        raise GitError(f"not a directory: {repo}")
    try:
        run_git(repo, "rev-parse", "--absolute-git-dir")
    except GitError as exc:
        raise GitError(f"not a Git repository: {repo}") from exc
    return repo
