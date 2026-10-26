"""Typed, immutable records describing what was recovered from a Git repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Reachability(StrEnum):
    """How an object can still be reached, from most to least visible."""

    REACHABLE = "reachable"  # from a ref (branch, tag, stash) or the index
    REFLOG_ONLY = "reflog_only"  # only through a reflog entry (amend, rebase, deleted branch)
    UNREACHABLE = "unreachable"  # no ref, no reflog: survives only until garbage collection


@dataclass(frozen=True, slots=True)
class GitObject:
    sha: str
    type: str  # "commit", "tree", "blob" or "tag"
    size: int
    reachability: Reachability = Reachability.REACHABLE
    dangling: bool = False  # unreachable *and* not referenced by any other unreachable object


@dataclass(frozen=True, slots=True)
class Commit:
    sha: str
    tree: str
    parents: tuple[str, ...]
    author_name: str | None
    author_email: str | None
    authored_at: datetime | None
    message: str


@dataclass(frozen=True, slots=True)
class BlobLocation:
    """One historical occurrence of a blob: a path inside a commit (or an orphan tree)."""

    blob_sha: str
    path: str
    commit: Commit | None  # None when the blob was only found in a dangling tree
