"""Typed, immutable records describing what was recovered from a Git repository."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path


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


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """A secret found inside one blob. ``value`` is excluded from ``repr`` so it never leaks
    into logs or tracebacks; use ``fingerprint`` and ``redacted`` to refer to it."""

    secret_type: str  # stable identifier, e.g. "aws_access_key_id", "private_key"
    value: str = field(repr=False)
    start: int  # byte offset in the blob, inclusive
    end: int  # byte offset in the blob, exclusive
    line: int  # 1-based line of ``start``

    @property
    def fingerprint(self) -> str:
        return secret_fingerprint(self.value)

    @property
    def redacted(self) -> str:
        return redact(self.value)


@dataclass(frozen=True, slots=True)
class SecretLocation:
    """One historical occurrence of a secret: where it sat, in which commit, and how
    reachable that commit (or, without a commit, the blob) still is."""

    blob_sha: str
    path: str | None  # None when the blob was never seen inside a tree
    commit: Commit | None
    reachability: Reachability
    line: int
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Finding:
    """A distinct secret (deduplicated by type and fingerprint) with all its occurrences."""

    secret_type: str
    fingerprint: str
    redacted: str
    locations: tuple[SecretLocation, ...]


def secret_fingerprint(value: str) -> str:
    """SHA-256 of the secret: identifies it across blobs without storing it."""
    return hashlib.sha256(value.encode()).hexdigest()


def redact(value: str) -> str:
    """Keep only a 4-character prefix (enough to recognise the type) and the length."""
    return f"{value[:4]}…[{len(value)} chars]"


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one scan produced: the findings plus the context needed to report them."""

    repository: Path
    head: str | None
    started_at: datetime
    duration_seconds: float
    objects_by_type: dict[str, int]
    objects_by_reachability: dict[str, int]
    blobs_scanned: int
    binary_blobs: int
    findings: tuple[Finding, ...]
