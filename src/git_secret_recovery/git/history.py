"""Refs, reflogs, and blob -> path -> commit reconstruction.

Locations are rebuilt from *every* commit object in the database (reachable,
reflog-only or unreachable), not from ``git log``, so commits that were amended,
rebased away, left on a deleted branch or stashed and dropped are still covered.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from git_secret_recovery.core.models import BlobLocation, Commit, GitObject
from git_secret_recovery.git.objects import read_commits, read_tree
from git_secret_recovery.git.repository import run_git


def list_refs(repo: Path) -> dict[str, str]:
    """Map each ref name (branches, tags, ``refs/stash``...) to the SHA it points to."""
    output = run_git(repo, "for-each-ref", "--format=%(refname)%00%(objectname)")
    refs: dict[str, str] = {}
    for line in output.decode("utf-8", errors="replace").splitlines():
        name, _, sha = line.partition("\0")
        refs[name] = sha
    return refs


def list_reflog_entries(repo: Path) -> list[tuple[str, str, str]]:
    """Return ``(selector, sha, subject)`` for every reflog entry, e.g.
    ``("HEAD@{2}", "7c0d...", "commit: Try S3 backups")``.

    Reflogs of deleted branches are gone, but HEAD's reflog usually still records
    the commits made while they were checked out.
    """
    output = run_git(repo, "reflog", "show", "--all", "--format=%gd%x00%H%x00%gs")
    entries: list[tuple[str, str, str]] = []
    for line in output.decode("utf-8", errors="replace").splitlines():
        selector, sha, subject = line.split("\0", 2)
        entries.append((selector, sha, subject))
    return entries


def reconstruct_blob_locations(
    repo: Path, objects: dict[str, GitObject]
) -> dict[str, list[BlobLocation]]:
    """Map each blob SHA to every ``(path, commit)`` where it ever appeared.

    The same blob keeps one entry per commit and path, so a secret committed once
    and carried through ten later commits yields eleven locations, oldest first.
    Blobs held only by a dangling tree get locations with ``commit=None``; blobs
    never written into any tree (e.g. ``git add`` then unstaged) get none at all.
    """
    commit_shas = [obj.sha for obj in objects.values() if obj.type == "commit"]
    commits = sorted(read_commits(repo, commit_shas).values(), key=_chronological)

    tree_cache: dict[str, list[tuple[str, str]]] = {}
    locations: defaultdict[str, list[BlobLocation]] = defaultdict(list)

    for commit in commits:
        if commit.tree not in tree_cache:
            tree_cache[commit.tree] = read_tree(repo, commit.tree)
        for blob_sha, path in tree_cache[commit.tree]:
            locations[blob_sha].append(BlobLocation(blob_sha, path, commit))

    orphan_trees = (o.sha for o in objects.values() if o.type == "tree" and o.dangling)
    for tree_sha in orphan_trees:
        for blob_sha, path in read_tree(repo, tree_sha):
            locations[blob_sha].append(BlobLocation(blob_sha, path, None))

    return dict(locations)


def _chronological(commit: Commit) -> tuple[bool, datetime, str]:
    # Commits without a parseable date go last; the SHA keeps the order deterministic.
    return (
        commit.authored_at is None,
        commit.authored_at or datetime.min.replace(tzinfo=UTC),
        commit.sha,
    )
