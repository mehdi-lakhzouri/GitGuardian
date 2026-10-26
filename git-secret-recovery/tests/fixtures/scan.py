"""Run the full Phase 1 pipeline on a repository, for assertions in tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from git_secret_recovery.core.models import BlobLocation, GitObject
from git_secret_recovery.git.history import reconstruct_blob_locations
from git_secret_recovery.git.objects import iter_object_contents, list_objects
from git_secret_recovery.git.repository import validate_repository


@dataclass(frozen=True)
class Scan:
    repo: Path
    objects: dict[str, GitObject]
    blob_contents: dict[str, bytes]
    locations: dict[str, list[BlobLocation]]

    def blobs_containing(self, marker: str) -> list[str]:
        needle = marker.encode()
        return [sha for sha, content in self.blob_contents.items() if needle in content]


def scan_repository(path: Path) -> Scan:
    repo = validate_repository(path)
    objects = list_objects(repo)
    blob_shas = [o.sha for o in objects.values() if o.type == "blob"]
    contents = {sha: raw for sha, _, raw in iter_object_contents(repo, blob_shas)}
    return Scan(repo, objects, contents, reconstruct_blob_locations(repo, objects))
