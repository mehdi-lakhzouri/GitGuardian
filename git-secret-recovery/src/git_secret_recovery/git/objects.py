"""Enumerate, classify and read every object in the object database.

Enumeration goes through ``git cat-file --batch-all-objects`` rather than history
walking, so loose *and* packed objects are listed whether or not anything still
points at them. Reachability is then derived from three ``git fsck`` passes.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta, timezone
from itertools import islice
from pathlib import Path

from git_secret_recovery.core.models import Commit, GitObject, Reachability
from git_secret_recovery.git.repository import GitError, run_git

logger = logging.getLogger(__name__)

_BATCH_SIZE = 256  # objects per `cat-file --batch` process: bounds memory use
_BINARY_SNIFF_BYTES = 8000  # same heuristic window Git uses for diffs
_IDENTITY = re.compile(rb"^(?P<name>.*?) ?<(?P<email>[^>]*)> (?P<ts>-?\d+) (?P<tz>[+-]\d{4})$")


def list_objects(repo: Path) -> dict[str, GitObject]:
    """Return every object in the repository keyed (and so deduplicated) by SHA."""
    output = run_git(
        repo,
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
    )
    found: dict[str, tuple[str, int]] = {}
    for line in output.decode("ascii").splitlines():
        sha, obj_type, size = line.split()
        found[sha] = (obj_type, int(size))  # an object stored twice (loose + pack) collapses

    unreachable_from_refs = _fsck(repo, "--unreachable", "--no-reflogs")
    unreachable = _fsck(repo, "--unreachable")
    dangling = _fsck(repo)  # default fsck output reports dangling objects

    objects: dict[str, GitObject] = {}
    for sha, (obj_type, size) in found.items():
        if sha in unreachable:
            reachability = Reachability.UNREACHABLE
        elif sha in unreachable_from_refs:
            reachability = Reachability.REFLOG_ONLY
        else:
            reachability = Reachability.REACHABLE
        objects[sha] = GitObject(sha, obj_type, size, reachability, dangling=sha in dangling)
    return objects


def _fsck(repo: Path, *flags: str) -> set[str]:
    """SHAs reported by ``git fsck`` as unreachable or dangling for the given flags."""
    # Non-zero exit only means corruption was found; the listing is still valid.
    output = run_git(repo, "fsck", "--connectivity-only", "--no-progress", *flags, check=False)
    shas: set[str] = set()
    for line in output.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in ("unreachable", "dangling"):
            shas.add(parts[2])
    return shas


def iter_object_contents(repo: Path, shas: Iterable[str]) -> Iterator[tuple[str, str, bytes]]:
    """Yield ``(sha, type, raw_content)`` for each readable object, in input order.

    Objects are read in batches through ``git cat-file --batch``; missing objects
    are logged and skipped instead of aborting the whole scan.
    """
    pending = iter(shas)
    while chunk := list(islice(pending, _BATCH_SIZE)):
        output = run_git(repo, "cat-file", "--batch", input="\n".join(chunk).encode() + b"\n")
        offset = 0
        while offset < len(output):
            header_end = output.index(b"\n", offset)
            header = output[offset:header_end].decode("ascii").split()
            offset = header_end + 1
            if len(header) != 3:  # "<sha> missing" or "<sha> ambiguous"
                logger.warning("cannot read object %s", " ".join(header))
                continue
            sha, obj_type, size = header[0], header[1], int(header[2])
            yield sha, obj_type, output[offset : offset + size]
            offset += size + 1  # content is followed by a newline


def read_object(repo: Path, sha: str) -> bytes:
    """Return the raw content of a single object."""
    for _, _, content in iter_object_contents(repo, [sha]):
        return content
    raise GitError(f"object not found: {sha}")


def read_commits(repo: Path, shas: Iterable[str]) -> dict[str, Commit]:
    """Parse the given commit objects; non-commits and unreadable objects are skipped."""
    return {
        sha: parse_commit(sha, raw)
        for sha, obj_type, raw in iter_object_contents(repo, shas)
        if obj_type == "commit"
    }


def parse_commit(sha: str, raw: bytes) -> Commit:
    """Parse a raw commit object. Author fields are ``None`` when absent or malformed."""
    headers, _, message = raw.partition(b"\n\n")
    tree = ""
    parents: list[str] = []
    author: re.Match[bytes] | None = None
    for line in headers.split(b"\n"):
        key, _, value = line.partition(b" ")
        if key == b"tree":
            tree = value.decode("ascii", errors="replace")
        elif key == b"parent":
            parents.append(value.decode("ascii", errors="replace"))
        elif key == b"author":
            author = _IDENTITY.match(value)
        # other headers (committer, gpgsig and its " "-prefixed continuation lines) are ignored

    return Commit(
        sha=sha,
        tree=tree,
        parents=tuple(parents),
        author_name=_decode(author["name"]) if author else None,
        author_email=_decode(author["email"]) if author else None,
        authored_at=_parse_timestamp(author["ts"], author["tz"]) if author else None,
        message=_decode(message).strip(),
    )


def _parse_timestamp(ts: bytes, tz: bytes) -> datetime | None:
    try:
        sign = -1 if tz.startswith(b"-") else 1
        offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
        return datetime.fromtimestamp(int(ts), UTC).astimezone(timezone(offset))
    except (ValueError, OverflowError, OSError):
        return None


def read_tree(repo: Path, tree_sha: str) -> list[tuple[str, str]]:
    """Return ``(blob_sha, path)`` for every blob under a tree, recursively.

    Submodule entries (gitlinks) are skipped. An unreadable tree yields an empty list.
    """
    try:
        output = run_git(repo, "ls-tree", "-r", "-z", "--full-tree", tree_sha)
    except GitError as exc:
        logger.warning("cannot read tree %s: %s", tree_sha, exc)
        return []

    entries: list[tuple[str, str]] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")  # "<mode> <type> <sha>\t<path>"
        _, obj_type, sha = meta.decode("ascii").split()
        if obj_type == "blob":
            entries.append((sha, _decode(path)))
    return entries


def is_binary(content: bytes) -> bool:
    """Git's heuristic: a NUL byte in the first 8000 bytes means binary."""
    return b"\0" in content[:_BINARY_SNIFF_BYTES]


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")
