from __future__ import annotations

from datetime import UTC, datetime

from git_secret_recovery.attribution.resolver import resolve_findings
from git_secret_recovery.core.models import (
    BlobLocation,
    Commit,
    GitObject,
    Reachability,
    SecretMatch,
)

TOKEN = "ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0001"


def commit(sha: str, day: int | None, author: str | None = "Ann") -> Commit:
    date = datetime(2026, 1, day, tzinfo=UTC) if day else None
    return Commit(sha, "tree", (), author, author and "ann@example.com", date, "msg")


def match(line: int = 1, value: str = TOKEN) -> SecretMatch:
    return SecretMatch("github_classic_pat", value, 0, len(value), line)


def objects(*specs: tuple[str, str, Reachability]) -> dict[str, GitObject]:
    return {sha: GitObject(sha, kind, 1, state) for sha, kind, state in specs}


def test_identical_secret_in_two_blobs_is_one_finding_with_all_occurrences() -> None:
    old, new = commit("c1", 2), commit("c2", 1)
    objs = objects(
        ("b1", "blob", Reachability.REACHABLE),
        ("b2", "blob", Reachability.REFLOG_ONLY),
        ("c1", "commit", Reachability.REACHABLE),
        ("c2", "commit", Reachability.REFLOG_ONLY),
    )
    locations = {
        "b1": [BlobLocation("b1", "a.env", old)],
        "b2": [BlobLocation("b2", "b.env", new), BlobLocation("b2", "copy.env", new)],
    }
    (finding,) = resolve_findings({"b1": [match()], "b2": [match(line=7)]}, objs, locations)

    assert finding.secret_type == "github_classic_pat"
    assert [(loc.path, loc.line, loc.reachability) for loc in finding.locations] == [
        ("b.env", 7, Reachability.REFLOG_ONLY),  # oldest commit first
        ("copy.env", 7, Reachability.REFLOG_ONLY),
        ("a.env", 1, Reachability.REACHABLE),
    ]


def test_different_secrets_stay_separate_findings() -> None:
    objs = objects(("b1", "blob", Reachability.REACHABLE))
    other = TOKEN[:-1] + "2"
    findings = resolve_findings({"b1": [match(), match(2, other)]}, objs, {})
    assert len(findings) == 2
    assert len({f.fingerprint for f in findings}) == 2


def test_blob_without_history_keeps_a_location_with_blob_reachability() -> None:
    objs = objects(("b1", "blob", Reachability.UNREACHABLE))
    (finding,) = resolve_findings({"b1": [match()]}, objs, {})
    (location,) = finding.locations
    assert location.path is None
    assert location.commit is None
    assert location.reachability is Reachability.UNREACHABLE


def test_missing_author_and_date_are_tolerated_and_sorted_last() -> None:
    undated, dated = commit("c1", None, author=None), commit("c2", 3)
    objs = objects(
        ("b1", "blob", Reachability.REACHABLE),
        ("c1", "commit", Reachability.UNREACHABLE),
        ("c2", "commit", Reachability.REACHABLE),
    )
    locations = {"b1": [BlobLocation("b1", "x", undated), BlobLocation("b1", "x", dated)]}
    (finding,) = resolve_findings({"b1": [match()]}, objs, locations)

    assert [loc.commit.sha for loc in finding.locations if loc.commit] == ["c2", "c1"]
    last = finding.locations[-1].commit
    assert last is not None
    assert (last.author_name, last.author_email, last.authored_at) == (None, None, None)


def test_dangling_tree_location_uses_blob_reachability() -> None:
    objs = objects(("b1", "blob", Reachability.UNREACHABLE))
    (finding,) = resolve_findings({"b1": [match()]}, objs, {"b1": [BlobLocation("b1", "p", None)]})
    assert finding.locations[0].path == "p"
    assert finding.locations[0].reachability is Reachability.UNREACHABLE


def test_no_matches_means_no_findings() -> None:
    assert resolve_findings({}, {}, {}) == []


def test_findings_never_expose_the_raw_secret() -> None:
    objs = objects(("b1", "blob", Reachability.REACHABLE))
    (finding,) = resolve_findings({"b1": [match()]}, objs, {})
    assert TOKEN not in repr(finding)
    assert finding.redacted == "ghp_…[40 chars]"
