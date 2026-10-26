from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest
from fixtures.generate_repo import BINARY_ASSET, SCENARIO_SECRETS, generate_repo
from fixtures.scan import Scan, scan_repository

from git_secret_recovery.core.models import Reachability
from git_secret_recovery.git.history import list_reflog_entries, list_refs
from git_secret_recovery.git.objects import is_binary, list_objects, read_object, read_tree
from git_secret_recovery.git.repository import GitError, run_git, validate_repository

# scenario -> (historical path, author, how the secret's blob can still be reached)
EXPECTED = {
    "file_deletion": ("config/aws_credentials", "Bob Builder", Reachability.REACHABLE),
    "amend": (".env", "Carol Coder", Reachability.REFLOG_ONLY),
    "rebase": ("deploy/id_rsa", "Dave Deployer", Reachability.REFLOG_ONLY),
    "branch_deletion": ("scripts/backup.sh", "Eve Experimenter", Reachability.REFLOG_ONLY),
    "stash_drop": ("README.md", "Frank Forgetful", Reachability.UNREACHABLE),
}


def _snapshot(git_dir: Path) -> dict[str, str]:
    return {
        str(p.relative_to(git_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(git_dir.rglob("*"))
        if p.is_file()
    }


# --- repository ------------------------------------------------------------------


def test_validate_repository_accepts_fixture(fixture_repo: Path) -> None:
    assert validate_repository(fixture_repo) == fixture_repo.resolve()


def test_validate_repository_rejects_plain_directory(tmp_path: Path) -> None:
    with pytest.raises(GitError, match="not a Git repository"):
        validate_repository(tmp_path)


def test_validate_repository_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(GitError, match="not a directory"):
        validate_repository(tmp_path / "missing")


def test_run_git_reports_failures(fixture_repo: Path) -> None:
    with pytest.raises(GitError, match="cat-file"):
        run_git(fixture_repo, "cat-file", "-p", "0" * 40)


# --- hiding scenarios ------------------------------------------------------------


@pytest.mark.parametrize("scenario", sorted(SCENARIO_SECRETS))
def test_secret_blob_is_recovered(scan: Scan, scenario: str) -> None:
    path, author, reachability = EXPECTED[scenario]
    blobs = scan.blobs_containing(SCENARIO_SECRETS[scenario])
    assert blobs, f"{scenario}: secret not found in any blob"

    for sha in blobs:
        assert scan.objects[sha].reachability is reachability
        locations = scan.locations[sha]
        assert {loc.path for loc in locations} == {path}
        for loc in locations:
            assert loc.commit is not None
            assert loc.commit.author_name == author
            assert loc.commit.author_email == f"{author.lower().replace(' ', '.')}@example.com"
            assert loc.commit.authored_at is not None
            assert loc.commit.authored_at.utcoffset() is not None


def test_secrets_are_hidden_from_current_refs(scan: Scan) -> None:
    refs = list_refs(scan.repo)
    assert set(refs) == {"refs/heads/main", "refs/heads/feature/deploy"}
    tip_blobs = {sha for tip in refs.values() for sha, _ in read_tree(scan.repo, tip)}
    for scenario, marker in SCENARIO_SECRETS.items():
        assert not tip_blobs & set(scan.blobs_containing(marker)), f"{scenario} still visible"


def test_rebased_key_keeps_every_historical_occurrence(scan: Scan) -> None:
    (blob,) = scan.blobs_containing(SCENARIO_SECRETS["rebase"])
    messages = [loc.commit.message for loc in scan.locations[blob] if loc.commit]
    # The dropped commit and the pre-rebase child commit both contained the key.
    assert messages == ["Add deploy key", "Add deploy script"]


def test_deleted_branch_commit_is_still_in_head_reflog(scan: Scan) -> None:
    (blob,) = scan.blobs_containing(SCENARIO_SECRETS["branch_deletion"])
    (location,) = scan.locations[blob]
    assert location.commit is not None
    reflog_shas = {sha for _, sha, _ in list_reflog_entries(scan.repo)}
    assert location.commit.sha in reflog_shas


def test_dropped_stash_commit_is_dangling(scan: Scan) -> None:
    (blob,) = scan.blobs_containing(SCENARIO_SECRETS["stash_drop"])
    commits = {loc.commit.sha for loc in scan.locations[blob] if loc.commit}
    assert any(scan.objects[sha].dangling for sha in commits)
    assert scan.objects[blob].reachability is Reachability.UNREACHABLE


# --- object storage --------------------------------------------------------------


def test_all_secrets_unreachable_after_reflog_expiry(tmp_path: Path) -> None:
    repo = generate_repo(tmp_path / "repo")
    # Expire reflogs (no gc/prune): rewritten history loses its last reference.
    run_git(repo, "reflog", "expire", "--expire=now", "--all")
    assert list_reflog_entries(repo) == []
    result = scan_repository(repo)

    # Every commit that only a reflog kept alive is now unreachable; exactly the
    # tips of the lost chains are dangling (a dropped parent is referenced by its child).
    commits = {
        loc.commit.message: result.objects[loc.commit.sha]
        for locations in result.locations.values()
        for loc in locations
        if loc.commit and result.objects[loc.commit.sha].reachability is not Reachability.REACHABLE
    }
    assert {msg for msg, obj in commits.items() if obj.dangling} == {
        "Add app configuration",  # pre-amend original
        "Add deploy script",  # pre-rebase tip
        "Try S3 backups",  # deleted branch tip
        "On main: WIP: local token",  # dropped stash
    }
    assert {obj.reachability for obj in commits.values()} == {Reachability.UNREACHABLE}

    for scenario, marker in SCENARIO_SECRETS.items():
        blobs = result.blobs_containing(marker)
        assert blobs, f"{scenario}: secret lost after reflog expiry"
        expected = EXPECTED[scenario][2]
        if expected is Reachability.REFLOG_ONLY:
            expected = Reachability.UNREACHABLE
        assert {result.objects[sha].reachability for sha in blobs} == {expected}
        assert all(result.locations[sha] for sha in blobs), f"{scenario}: no location"


def test_packed_and_loose_duplicates_are_deduplicated(tmp_path: Path) -> None:
    repo = generate_repo(tmp_path / "repo")
    loose_only = list_objects(repo)
    # Pack reachable objects but keep the loose copies (no -d, no prune).
    run_git(repo, "repack", "-a", "-q")
    assert list((repo / ".git" / "objects" / "pack").glob("*.pack"))

    after = scan_repository(repo)
    assert set(after.objects) == set(loose_only)
    for marker in SCENARIO_SECRETS.values():
        assert after.blobs_containing(marker)


def test_binary_blob_is_read_intact(scan: Scan) -> None:
    sha = run_git(scan.repo, "rev-parse", "main:assets/favicon.ico").decode().strip()
    content = read_object(scan.repo, sha)
    assert content == BINARY_ASSET
    assert is_binary(content)
    assert not is_binary(scan.blob_contents[scan.blobs_containing(SCENARIO_SECRETS["amend"])[0]])


def test_scan_does_not_modify_repository(fixture_repo: Path) -> None:
    git_dir = fixture_repo / ".git"
    before = _snapshot(git_dir)
    scan_repository(fixture_repo)
    list_refs(fixture_repo)
    list_reflog_entries(fixture_repo)
    assert _snapshot(git_dir) == before


def test_fixture_generation_is_reproducible(tmp_path: Path) -> None:
    first = generate_repo(tmp_path / "a")
    second = generate_repo(tmp_path / "b")
    assert list_refs(first) == list_refs(second)
    assert set(list_objects(first)) == set(list_objects(second))


def test_generator_refuses_non_empty_directory(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("data")
    with pytest.raises(FileExistsError):
        generate_repo(tmp_path)


def test_fixture_has_no_gc_artifacts(fixture_repo: Path) -> None:
    output = subprocess.run(
        ["git", "-C", str(fixture_repo), "count-objects", "-v"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "packs: 0" in output  # everything is still loose: nothing was gc'd
