"""Generate an isolated Git repository that hides FAKE credentials five different ways.

Every secret below is a documented placeholder or a deterministic dummy value:
nothing here is a live credential. The generated history is reproducible because
identities, dates and config are pinned, so object SHAs are stable across runs.

Usage: uv run python tests/fixtures/generate_repo.py <empty-output-dir>
"""

from __future__ import annotations

import argparse
import base64
import itertools
import os
import random
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

# AWS's own documentation example keys (never valid).
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_ACCESS_KEY_ID_2 = "AKIAI44QH8DHBEXAMPLE"
AWS_SECRET_ACCESS_KEY_2 = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
# Correct ghp_ shape (prefix + 36 chars) but obviously fake content.
GITHUB_TOKEN = "ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0001"
GITHUB_TOKEN_2 = "ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0002"


def _fake_pem_private_key() -> str:
    """A PEM envelope around deterministic random bytes: looks like a key, is not one."""
    body = base64.b64encode(random.Random(2027).randbytes(608)).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "\n".join(["-----BEGIN RSA PRIVATE KEY-----", *lines, "-----END RSA PRIVATE KEY-----"])


PEM_PRIVATE_KEY = _fake_pem_private_key()
BINARY_ASSET = bytes(range(256))  # contains NUL bytes, so Git treats it as binary

# Scenario -> a unique string proving that scenario's secret was recovered.
SCENARIO_SECRETS: dict[str, str] = {
    "file_deletion": AWS_ACCESS_KEY_ID,
    "amend": GITHUB_TOKEN,
    "rebase": PEM_PRIVATE_KEY.splitlines()[1],
    "branch_deletion": AWS_ACCESS_KEY_ID_2,
    "stash_drop": GITHUB_TOKEN_2,
}

_BASE_TIMESTAMP = 1_767_225_600  # 2026-01-01T00:00:00Z
_GIT_CONFIG = (
    "-c", "init.defaultBranch=main",
    "-c", "core.autocrlf=false",
    "-c", "core.longpaths=true",  # Windows: deep temp dirs exceed MAX_PATH during rebase
    "-c", "commit.gpgsign=false",
    "-c", "gc.auto=0",  # never let Git prune the objects we are hiding
    "-c", "maintenance.auto=false",
)  # fmt: skip


def _isolated_env(author: str, timestamp: int) -> dict[str, str]:
    env = os.environ.copy()
    # Ignore the developer's global/system config (hooks, signing, templates...).
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    email = f"{author.lower().replace(' ', '.')}@example.com"
    date = f"{timestamp} +0000"
    env.update(
        GIT_AUTHOR_NAME=author,
        GIT_AUTHOR_EMAIL=email,
        GIT_AUTHOR_DATE=date,
        GIT_COMMITTER_NAME=author,
        GIT_COMMITTER_EMAIL=email,
        GIT_COMMITTER_DATE=date,
    )
    return env


def _write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode())  # bytes: no platform newline translation


def generate_repo(target: Path) -> Path:
    """Create the fixture repository in ``target`` (must be absent or empty)."""
    target = target.resolve()
    if target.exists() and any(target.iterdir()):
        raise FileExistsError(f"refusing to write into non-empty directory: {target}")
    target.mkdir(parents=True, exist_ok=True)

    git_path = shutil.which("git")
    if git_path is None:
        raise RuntimeError("git executable not found on PATH")
    clock: Iterator[int] = itertools.count(_BASE_TIMESTAMP, 3600)

    def git(*args: str, author: str = "Alice Admin") -> None:
        result = subprocess.run(
            [git_path, *_GIT_CONFIG, "-C", str(target), *args],
            env=_isolated_env(author, next(clock)),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")

    git("init")
    git("config", "core.longpaths", "true")  # persists for later commands run by tests
    _write(target, "README.md", "# Demo service\n")
    (target / "assets").mkdir()
    (target / "assets" / "favicon.ico").write_bytes(BINARY_ASSET)
    git("add", "README.md", "assets/favicon.ico")
    git("commit", "-m", "Initial commit")

    # 1. File deletion: the blob stays reachable through the older commit.
    _write(
        target,
        "config/aws_credentials",
        "[default]\n"
        f"aws_access_key_id = {AWS_ACCESS_KEY_ID}\n"
        f"aws_secret_access_key = {AWS_SECRET_ACCESS_KEY}\n",
    )
    git("add", "config/aws_credentials")
    git("commit", "-m", "Add AWS credentials for deployment", author="Bob Builder")
    git("rm", "-q", "config/aws_credentials")
    git("commit", "-m", "Remove credentials", author="Bob Builder")

    # 2. Amend: the original commit is replaced; only the HEAD/main reflogs keep it.
    _write(target, ".env", f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
    git("add", ".env")
    git("commit", "-m", "Add app configuration", author="Carol Coder")
    _write(target, ".env", "GITHUB_TOKEN=${GITHUB_TOKEN}\n")
    git("add", ".env")
    git("commit", "--amend", "--no-edit", author="Carol Coder")

    # 3. Rebase: drop the commit that added a private key from a feature branch.
    git("switch", "-c", "feature/deploy")
    _write(target, "deploy/id_rsa", PEM_PRIVATE_KEY + "\n")
    git("add", "deploy/id_rsa")
    git("commit", "-m", "Add deploy key", author="Dave Deployer")
    _write(target, "deploy/deploy.sh", "#!/bin/sh\nrsync -az ./build/ prod:/srv/app/\n")
    git("add", "deploy/deploy.sh")
    git("commit", "-m", "Add deploy script", author="Dave Deployer")
    git("rebase", "--onto", "feature/deploy~2", "feature/deploy~1", "feature/deploy")
    git("switch", "main")

    # 4. Branch deletion: the branch and its own reflog disappear.
    git("switch", "-c", "experiment")
    _write(
        target,
        "scripts/backup.sh",
        "#!/bin/sh\n"
        f"export AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_ID_2}\n"
        f"export AWS_SECRET_ACCESS_KEY={AWS_SECRET_ACCESS_KEY_2}\n"
        "aws s3 sync /var/backups s3://demo-backups\n",
    )
    git("add", "scripts/backup.sh")
    git("commit", "-m", "Try S3 backups", author="Eve Experimenter")
    git("switch", "main")
    git("branch", "-D", "experiment")

    # 5. Stash drop: the stash commits become dangling, with no ref and no reflog.
    _write(target, "README.md", f"# Demo service\n\nexport GITHUB_TOKEN={GITHUB_TOKEN_2}\n")
    git("stash", "push", "-m", "WIP: local token", author="Frank Forgetful")
    git("stash", "drop", author="Frank Forgetful")

    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path, help="absent or empty directory to create")
    args = parser.parse_args()
    print(generate_repo(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
