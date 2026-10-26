from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fixtures.generate_repo import (
    AWS_ACCESS_KEY_ID,
    AWS_ACCESS_KEY_ID_2,
    AWS_SECRET_ACCESS_KEY,
    AWS_SECRET_ACCESS_KEY_2,
    GITHUB_TOKEN,
    GITHUB_TOKEN_2,
    PEM_PRIVATE_KEY,
)

from git_secret_recovery.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_SECRETS_FOUND, main
from git_secret_recovery.core.models import secret_fingerprint
from git_secret_recovery.git.repository import run_git

RAW_SECRETS = [
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_ACCESS_KEY_ID_2,
    AWS_SECRET_ACCESS_KEY_2,
    GITHUB_TOKEN,
    GITHUB_TOKEN_2,
    PEM_PRIVATE_KEY,
    *PEM_PRIVATE_KEY.splitlines()[1:-1],  # no single line of the key body either
]

# scenario -> (secret, type, path, line, author, commits, reachability)
SCENARIOS = {
    "file_deletion": (AWS_ACCESS_KEY_ID, "aws_access_key_id", "config/aws_credentials", 2,
                      "Bob Builder", 1, "reachable"),
    "amend": (GITHUB_TOKEN, "github_classic_pat", ".env", 1, "Carol Coder", 1, "reflog_only"),
    "rebase": (PEM_PRIVATE_KEY, "private_key", "deploy/id_rsa", 1, "Dave Deployer", 2,
               "reflog_only"),
    "branch_deletion": (AWS_ACCESS_KEY_ID_2, "aws_access_key_id", "scripts/backup.sh", 2,
                        "Eve Experimenter", 1, "reflog_only"),
    "stash_drop": (GITHUB_TOKEN_2, "github_classic_pat", "README.md", 3, "Frank Forgetful", 1,
                   "unreachable"),
}  # fmt: skip


@pytest.fixture(scope="module")
def cli_run(fixture_repo: Path) -> subprocess.CompletedProcess[str]:
    """Run the real entry point in a subprocess: true stdout/stderr and exit code."""
    return subprocess.run(
        [sys.executable, "-m", "git_secret_recovery", "scan", str(fixture_repo)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="module")
def report(cli_run: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return json.loads(cli_run.stdout)


def test_exit_code_and_streams(cli_run: subprocess.CompletedProcess[str]) -> None:
    assert cli_run.returncode == EXIT_SECRETS_FOUND
    json.loads(cli_run.stdout)  # stdout is exactly one JSON document
    assert cli_run.stderr.strip().endswith("7 secrets, 8 occurrences")


def test_summary(report: dict[str, Any], fixture_repo: Path) -> None:
    summary = report["summary"]
    assert summary["findings"] == 7
    assert summary["occurrences"] == 8
    assert summary["binary_blobs"] == 1
    assert summary["findings_by_type"] == {
        "aws_access_key_id": 2,
        "aws_secret_access_key": 2,
        "github_classic_pat": 2,
        "private_key": 1,
    }
    head = run_git(fixture_repo, "rev-parse", "HEAD").decode().strip()
    assert report["repository"]["head"] == head


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_each_hiding_scenario_is_reported(report: dict[str, Any], scenario: str) -> None:
    secret, secret_type, path, line, author, commits, reachability = SCENARIOS[scenario]
    (finding,) = [
        f for f in report["findings"] if f["fingerprint_sha256"] == secret_fingerprint(secret)
    ]
    assert finding["type"] == secret_type
    assert (
        finding["occurrences"]
        == commits
        == len({loc["commit_sha"] for loc in finding["locations"]})
    )
    for loc in finding["locations"]:
        assert (loc["path"], loc["line"], loc["author_name"]) == (path, line, author)
        assert loc["reachability"] == reachability
        date = datetime.fromisoformat(loc["date"])
        assert date.year == 2026 and date.utcoffset() is not None
        assert len(loc["blob_sha"]) == len(loc["commit_sha"]) == 40


@pytest.mark.parametrize("secret", ["AWS secret #1", "AWS secret #2"])
def test_aws_secret_keys_are_reported_next_to_their_ids(
    report: dict[str, Any], secret: str
) -> None:
    value = AWS_SECRET_ACCESS_KEY if secret.endswith("1") else AWS_SECRET_ACCESS_KEY_2
    fingerprints = {f["fingerprint_sha256"] for f in report["findings"]}
    assert secret_fingerprint(value) in fingerprints


def test_no_raw_secret_in_stdout_or_stderr(cli_run: subprocess.CompletedProcess[str]) -> None:
    for secret in RAW_SECRETS:
        assert secret not in cli_run.stdout
        assert secret not in cli_run.stderr


def test_output_file(
    fixture_repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "findings.json"
    assert main(["scan", str(fixture_repo), "--output", str(output)]) == EXIT_SECRETS_FOUND
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"report written to {output}" in captured.err
    document = output.read_text(encoding="utf-8")
    assert json.loads(document)["summary"]["findings"] == 7
    assert not any(secret in document for secret in RAW_SECRETS)


@pytest.mark.parametrize("target", ["report.json", ".git/report.json", "sub/dir/report.json"])
def test_refuses_to_write_inside_scanned_repository(
    fixture_repo: Path, target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(fixture_repo), "-o", str(fixture_repo / target)]) == EXIT_ERROR
    assert "refusing to write" in capsys.readouterr().err
    assert not (fixture_repo / target).exists()


def test_cli_scan_does_not_modify_repository(fixture_repo: Path, tmp_path: Path) -> None:
    def snapshot() -> dict[str, str]:
        return {
            str(p.relative_to(fixture_repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(fixture_repo.rglob("*"))
            if p.is_file()
        }

    before = snapshot()
    main(["scan", str(fixture_repo), "-o", str(tmp_path / "out.json")])
    assert snapshot() == before


def test_uncommitted_blob_is_reported_with_null_history(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``git add`` then unstage: the blob exists, but no tree or commit ever held it."""
    repo = tmp_path / "repo"
    run_git(tmp_path, "init", "-q", str(repo))
    (repo / "token.txt").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
    run_git(repo, "add", "token.txt")
    run_git(repo, "rm", "-q", "--cached", "token.txt")
    (repo / "token.txt").unlink()

    assert main(["scan", str(repo)]) == EXIT_SECRETS_FOUND
    (finding,) = json.loads(capsys.readouterr().out)["findings"]
    (location,) = finding["locations"]
    assert location["reachability"] == "unreachable"
    for key in ("path", "commit_sha", "author_name", "author_email", "date"):
        assert location[key] is None


def test_clean_repository_exits_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = tmp_path / "repo"
    run_git(tmp_path, "init", "-q", str(repo))
    (repo / "README.md").write_text("nothing secret\n")
    run_git(repo, "add", "README.md")
    run_git(
        repo,
        "-c",
        "user.name=T",
        "-c",
        "user.email=t@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "init",
    )

    assert main(["scan", str(repo)]) == EXIT_CLEAN
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["summary"]["objects"] == 3
