"""The scan pipeline: discover objects -> detect secrets -> attribute them to history."""

from __future__ import annotations

import os
import time
from collections import Counter
from datetime import UTC, datetime

from git_secret_recovery.attribution.resolver import resolve_findings
from git_secret_recovery.core.models import ScanResult, SecretMatch
from git_secret_recovery.detection.engine import scan_blob
from git_secret_recovery.git.history import reconstruct_blob_locations
from git_secret_recovery.git.objects import is_binary, iter_object_contents, list_objects
from git_secret_recovery.git.repository import head_commit, validate_repository


def scan_repository(path: str | os.PathLike[str]) -> ScanResult:
    """Scan every object of a local repository, read-only.

    Raises ``GitError`` if ``path`` is not a usable Git repository.
    """
    started_at = datetime.now(UTC)
    clock = time.perf_counter()
    repo = validate_repository(path)

    objects = list_objects(repo)
    blob_shas = [obj.sha for obj in objects.values() if obj.type == "blob"]

    matches: dict[str, list[SecretMatch]] = {}
    blobs_scanned = binary_blobs = 0
    for sha, _, content in iter_object_contents(repo, blob_shas):
        blobs_scanned += 1
        binary_blobs += is_binary(content)
        if found := scan_blob(content):
            matches[sha] = found

    findings = resolve_findings(matches, objects, reconstruct_blob_locations(repo, objects))
    return ScanResult(
        repository=repo,
        head=head_commit(repo),
        started_at=started_at,
        duration_seconds=round(time.perf_counter() - clock, 3),
        objects_by_type=dict(sorted(Counter(o.type for o in objects.values()).items())),
        objects_by_reachability=dict(
            sorted(Counter(str(o.reachability) for o in objects.values()).items())
        ),
        blobs_scanned=blobs_scanned,
        binary_blobs=binary_blobs,
        findings=tuple(findings),
    )
