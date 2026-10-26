"""Attach Phase 1 history (paths, commits, authors, reachability) to detected secrets."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from git_secret_recovery.core.models import (
    BlobLocation,
    Commit,
    Finding,
    GitObject,
    SecretLocation,
    SecretMatch,
)
from git_secret_recovery.detection.engine import scan_blob
from git_secret_recovery.git.history import reconstruct_blob_locations
from git_secret_recovery.git.objects import iter_object_contents, list_objects

_UNDATED = datetime.max.replace(tzinfo=UTC)


def find_secrets(repo: Path) -> list[Finding]:
    """Scan every blob in the repository and return attributed, deduplicated findings.

    ``repo`` must already be validated (see ``validate_repository``). Read-only.
    """
    objects = list_objects(repo)
    blob_shas = [obj.sha for obj in objects.values() if obj.type == "blob"]
    matches = {
        sha: found
        for sha, _, content in iter_object_contents(repo, blob_shas)
        if (found := scan_blob(content))
    }
    return resolve_findings(matches, objects, reconstruct_blob_locations(repo, objects))


def resolve_findings(
    matches_by_blob: Mapping[str, Sequence[SecretMatch]],
    objects: Mapping[str, GitObject],
    locations: Mapping[str, Sequence[BlobLocation]],
) -> list[Finding]:
    """Group matches by (type, fingerprint) and expand each into its historical locations.

    A secret present in several blobs, commits or lines becomes one ``Finding`` with one
    ``SecretLocation`` per (blob, path, commit, line). Blobs with no known location still
    produce a location (``path=None``, ``commit=None``) so no secret is ever dropped.
    """
    grouped: defaultdict[tuple[str, str], list[SecretLocation]] = defaultdict(list)
    redactions: dict[tuple[str, str], str] = {}

    for blob_sha, matches in matches_by_blob.items():
        occurrences: list[tuple[str | None, Commit | None]] = [
            (loc.path, loc.commit) for loc in locations.get(blob_sha, ())
        ] or [(None, None)]
        for match in matches:
            key = (match.secret_type, match.fingerprint)
            redactions[key] = match.redacted
            for path, commit in occurrences:
                # The commit tells how *this occurrence* survives (the same blob may also
                # sit in a reachable commit); without one, use the blob's own state.
                state_of = commit.sha if commit else blob_sha
                grouped[key].append(
                    SecretLocation(
                        blob_sha=blob_sha,
                        path=path,
                        commit=commit,
                        reachability=objects[state_of].reachability,
                        line=match.line,
                        start=match.start,
                        end=match.end,
                    )
                )

    findings = [
        Finding(secret_type, fp, redactions[(secret_type, fp)], tuple(sorted(locs, key=_order)))
        for (secret_type, fp), locs in grouped.items()
    ]
    return sorted(findings, key=lambda f: (_order(f.locations[0]), f.secret_type, f.fingerprint))


def _order(loc: SecretLocation) -> tuple[datetime, str, str, int]:
    date = loc.commit.authored_at if loc.commit and loc.commit.authored_at else _UNDATED
    return (date, loc.commit.sha if loc.commit else "", loc.path or "", loc.start)
