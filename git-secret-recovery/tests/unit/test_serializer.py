from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from git_secret_recovery.attribution.resolver import resolve_findings
from git_secret_recovery.core.models import (
    BlobLocation,
    Commit,
    GitObject,
    Reachability,
    ScanResult,
    SecretMatch,
)
from git_secret_recovery.reporting.serializer import SCHEMA_VERSION, report_dict, to_json

TOKEN = "ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0001"
SECRET_PATH_TOKEN = "ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0009"

TOP_KEYS = {"schema_version", "tool", "repository", "scan", "summary", "findings"}
FINDING_KEYS = {"type", "fingerprint_sha256", "redacted", "occurrences", "locations"}
LOCATION_KEYS = {
    "blob_sha", "path", "line", "start_byte", "end_byte", "commit_sha",
    "author_name", "author_email", "date", "reachability",
}  # fmt: skip


def make_result() -> ScanResult:
    """One secret in three places: dated commit, undated author-less commit, no history."""
    dated = Commit("c1", "t", (), "Ann", "ann@example.com", datetime(2026, 1, 2, tzinfo=UTC), "m")
    anonymous = Commit("c2", "t", (), None, None, None, "m")
    objects = {
        sha: GitObject(sha, kind, 1, state)
        for sha, kind, state in [
            ("b1", "blob", Reachability.REACHABLE),
            ("b2", "blob", Reachability.UNREACHABLE),
            ("c1", "commit", Reachability.REACHABLE),
            ("c2", "commit", Reachability.REFLOG_ONLY),
        ]
    }
    match = SecretMatch("github_classic_pat", TOKEN, 4, 44, 1)
    findings = resolve_findings(
        {"b1": [match], "b2": [match]},
        objects,
        {
            "b1": [
                BlobLocation("b1", f"dir/{SECRET_PATH_TOKEN}", dated),
                BlobLocation("b1", "x", anonymous),
            ]
        },
    )
    return ScanResult(
        repository=Path("/repos/demo"),
        head=None,
        started_at=datetime(2026, 10, 26, tzinfo=UTC),
        duration_seconds=0.5,
        objects_by_type={"blob": 2, "commit": 2},
        objects_by_reachability={"reachable": 2, "reflog_only": 1, "unreachable": 1},
        blobs_scanned=2,
        binary_blobs=0,
        findings=tuple(findings),
    )


def test_json_is_valid_and_matches_dict() -> None:
    result = make_result()
    assert json.loads(to_json(result)) == json.loads(json.dumps(report_dict(result)))
    assert to_json(result).endswith("\n")
    to_json(result).encode("ascii")  # safe on any console encoding


def test_schema_keys_are_always_present() -> None:
    report = report_dict(make_result())
    assert set(report) == TOP_KEYS
    assert report["schema_version"] == SCHEMA_VERSION
    for finding in report["findings"]:
        assert set(finding) == FINDING_KEYS
        for location in finding["locations"]:
            assert set(location) == LOCATION_KEYS


def test_duplicates_are_one_finding_with_every_occurrence() -> None:
    report = report_dict(make_result())
    (finding,) = report["findings"]
    assert finding["occurrences"] == len(finding["locations"]) == 3
    assert report["summary"]["findings"] == 1
    assert report["summary"]["occurrences"] == 3
    assert report["summary"]["findings_by_type"] == {"github_classic_pat": 1}
    assert report["summary"]["occurrences_by_reachability"] == {
        "reachable": 1,
        "reflog_only": 1,
        "unreachable": 1,
    }


def test_missing_metadata_is_explicit_null() -> None:
    report = report_dict(make_result())
    by_commit = {loc["commit_sha"]: loc for loc in report["findings"][0]["locations"]}
    dated, anonymous, orphan = by_commit["c1"], by_commit["c2"], by_commit[None]

    assert dated["date"] == "2026-01-02T00:00:00+00:00"
    assert (anonymous["author_name"], anonymous["author_email"], anonymous["date"]) == (
        None,
        None,
        None,
    )
    assert anonymous["commit_sha"] == "c2"
    assert {k: orphan[k] for k in ("path", "commit_sha", "author_name", "date")} == dict.fromkeys(
        ("path", "commit_sha", "author_name", "date")
    )
    assert orphan["reachability"] == "unreachable"
    assert report["repository"]["head"] is None


def test_no_raw_secret_anywhere_in_the_report() -> None:
    document = to_json(make_result())
    assert TOKEN not in document
    assert SECRET_PATH_TOKEN not in document  # a secret used as a file name is masked too
    report = json.loads(document)
    assert report["findings"][0]["redacted"] == "ghp_…[40 chars]"
    assert report["findings"][0]["locations"][0]["path"] == "dir/ghp_…[40 chars]"
