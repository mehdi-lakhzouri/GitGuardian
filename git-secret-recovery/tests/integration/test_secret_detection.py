from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fixtures.generate_repo import (
    AWS_ACCESS_KEY_ID,
    AWS_ACCESS_KEY_ID_2,
    AWS_SECRET_ACCESS_KEY,
    AWS_SECRET_ACCESS_KEY_2,
    GITHUB_TOKEN,
    GITHUB_TOKEN_2,
    PEM_PRIVATE_KEY,
    generate_repo,
)

from git_secret_recovery.attribution.resolver import find_secrets
from git_secret_recovery.core.models import Finding, Reachability, secret_fingerprint
from git_secret_recovery.git.repository import run_git

# secret -> (type, path, line, author, [commit messages, oldest first], reachability)
EXPECTED = {
    AWS_ACCESS_KEY_ID: (
        "aws_access_key_id", "config/aws_credentials", 2, "Bob Builder",
        ["Add AWS credentials for deployment"], Reachability.REACHABLE,
    ),
    AWS_SECRET_ACCESS_KEY: (
        "aws_secret_access_key", "config/aws_credentials", 3, "Bob Builder",
        ["Add AWS credentials for deployment"], Reachability.REACHABLE,
    ),
    GITHUB_TOKEN: (
        "github_classic_pat", ".env", 1, "Carol Coder",
        ["Add app configuration"], Reachability.REFLOG_ONLY,
    ),
    PEM_PRIVATE_KEY: (
        "private_key", "deploy/id_rsa", 1, "Dave Deployer",
        ["Add deploy key", "Add deploy script"], Reachability.REFLOG_ONLY,
    ),
    AWS_ACCESS_KEY_ID_2: (
        "aws_access_key_id", "scripts/backup.sh", 2, "Eve Experimenter",
        ["Try S3 backups"], Reachability.REFLOG_ONLY,
    ),
    AWS_SECRET_ACCESS_KEY_2: (
        "aws_secret_access_key", "scripts/backup.sh", 3, "Eve Experimenter",
        ["Try S3 backups"], Reachability.REFLOG_ONLY,
    ),
    GITHUB_TOKEN_2: (
        "github_classic_pat", "README.md", 3, "Frank Forgetful",
        ["On main: WIP: local token"], Reachability.UNREACHABLE,
    ),
}  # fmt: skip


@pytest.fixture(scope="module")
def findings(fixture_repo: Path) -> dict[str, Finding]:
    return {f.fingerprint: f for f in find_secrets(fixture_repo)}


def test_detects_exactly_the_planted_secrets(findings: dict[str, Finding]) -> None:
    assert set(findings) == {secret_fingerprint(secret) for secret in EXPECTED}
    assert {f.secret_type for f in findings.values()} == {
        "aws_access_key_id",
        "aws_secret_access_key",
        "github_classic_pat",
        "private_key",
    }


@pytest.mark.parametrize("secret", list(EXPECTED), ids=lambda s: s[:12])
def test_finding_has_accurate_history(
    fixture_repo: Path, findings: dict[str, Finding], secret: str
) -> None:
    secret_type, path, line, author, messages, reachability = EXPECTED[secret]
    finding = findings[secret_fingerprint(secret)]

    assert finding.secret_type == secret_type
    assert [loc.commit.message for loc in finding.locations if loc.commit] == messages
    for loc in finding.locations:
        assert (loc.path, loc.line, loc.reachability) == (path, line, reachability)
        assert loc.commit is not None
        assert loc.commit.author_name == author
        assert loc.commit.authored_at is not None
        assert loc.commit.authored_at.utcoffset() is not None
        # Byte offsets point at the exact secret inside the stored blob.
        blob = run_git(fixture_repo, "cat-file", "blob", loc.blob_sha)
        assert blob[loc.start : loc.end].decode() == secret


def test_findings_are_ordered_by_first_appearance(findings: dict[str, Finding]) -> None:
    dates = [f.locations[0].commit.authored_at for f in findings.values() if f.locations[0].commit]
    assert dates == sorted(dates)


def test_findings_do_not_expose_raw_secrets(findings: dict[str, Finding]) -> None:
    rendered = repr(list(findings.values()))
    for secret in EXPECTED:
        assert secret not in rendered


def test_secrets_survive_reflog_expiry_as_unreachable(tmp_path: Path) -> None:
    repo = generate_repo(tmp_path / "repo")
    run_git(repo, "reflog", "expire", "--expire=now", "--all")
    by_fp = {f.fingerprint: f for f in find_secrets(repo)}

    assert set(by_fp) == {secret_fingerprint(secret) for secret in EXPECTED}
    for secret, (*_, before) in EXPECTED.items():
        # Only the deleted file is still in branch history; everything else lost its reflog.
        after = before if before is Reachability.REACHABLE else Reachability.UNREACHABLE
        states = {loc.reachability for loc in by_fp[secret_fingerprint(secret)].locations}
        assert states == {after}


def test_detection_does_not_modify_repository(fixture_repo: Path) -> None:
    def snapshot() -> dict[str, str]:
        git_dir = fixture_repo / ".git"
        return {
            str(p.relative_to(git_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(git_dir.rglob("*"))
            if p.is_file()
        }

    before = snapshot()
    find_secrets(fixture_repo)
    assert snapshot() == before
