# git-secret-recovery

*Find what Git forgot to forget.* Phase 1: a read-only Git forensics engine that
enumerates every object in a local repository, including objects that no branch
or log shows anymore, and rebuilds where each blob lived (path, commit, author, date).

Secret detection, the CLI and JSON reporting come in later phases.

## Layout

```text
src/git_secret_recovery/
├── core/models.py       # GitObject, Commit, BlobLocation, Reachability (frozen dataclasses)
└── git/
    ├── repository.py    # validate_repository(), run_git(): no shell, read-only env
    ├── objects.py       # list_objects(), iter_object_contents(), parse_commit(), read_tree()
    └── history.py       # list_refs(), list_reflog_entries(), reconstruct_blob_locations()
tests/
├── fixtures/generate_repo.py   # builds the 5-scenario fake-secret repository
├── fixtures/scan.py            # test helper that runs the full pipeline
├── integration/                # end-to-end checks on generated repositories
└── unit/                       # commit parsing and binary detection
```

## How it works

1. **Enumerate** with `git cat-file --batch-all-objects --batch-check`. This lists loose
   and packed objects whether anything references them or not, and each SHA appears
   once.
2. **Classify** with three `git fsck --connectivity-only` passes:
   - `reachable`: reachable from a ref or from the index
   - `reflog_only`: reachable only through a reflog (amend, rebase, deleted branch)
   - `unreachable`: no ref and no reflog (dropped stash, or anything after reflog expiry)
   - `dangling`: an unreachable object that no other object references (the tip of a lost chain)
3. **Read** in batches through `git cat-file --batch`. Content stays as `bytes` because
   blobs may be binary.
4. **Reconstruct** locations by walking the tree of *every* commit object, not only the
   commits `git log` can see. A blob gets one `BlobLocation` per (commit, path) where it
   occurs, sorted oldest first. Blobs held only by a dangling tree get `commit=None`.

## Hiding scenarios in the fixture

| Scenario        | Fake secret                 | Path                     | Recovered as                 |
|-----------------|-----------------------------|--------------------------|------------------------------|
| File deletion   | AWS docs example key        | `config/aws_credentials` | reachable (older commit)     |
| Commit amend    | `ghp_FAKE…0001`             | `.env`                   | reflog-only                  |
| Rebase (drop)   | Dummy PEM private key       | `deploy/id_rsa`          | reflog-only, 2 occurrences   |
| Branch deletion | 2nd AWS docs example key    | `scripts/backup.sh`      | reflog-only (HEAD reflog)    |
| Stash drop      | `ghp_FAKE…0002`             | `README.md`              | unreachable, dangling commit |

After `git reflog expire --expire=now --all` (which the tests run on a copy), every
rewritten secret becomes `unreachable` and is still recovered.

## Commands

```sh
uv sync                                                     # create .venv with dev tools
uv run python tests/fixtures/generate_repo.py ./demo-repo   # build the fixture repository
uv run pytest                                               # unit and integration tests
uv run ruff format --check . && uv run ruff check .         # formatting and lint
```

## Safety

- Git always runs as an argument list, never through a shell (`shell=True` is not used).
- Only read-only plumbing is called (`cat-file`, `fsck`, `ls-tree`, `for-each-ref`,
  `reflog show`). `GIT_OPTIONAL_LOCKS=0`, `gc.auto=0`, `maintenance.auto=false` and
  `core.fsmonitor=false` stop Git from writing to the scanned repository or running
  code from its config. A test checks that every file under `.git/` is byte-identical
  after a scan.
- The fixture contains only AWS's published example keys, tokens that are obviously
  fake, and a PEM envelope around deterministic random bytes. It is **not** a valid
  key, so no real private key is committed to this project. The fixture never runs
  `gc`, `prune` or `repack -d`.

## Limitations

- **Garbage collection is final.** After `git gc --prune=now` (or the default 2-week
  prune), unreachable objects are deleted and cannot be recovered from the object store.
- **Never-committed data is out of scope.** `git add` writes a blob, so a staged-then-
  unstaged file *is* recovered, but it has no path or commit. Working-tree changes that
  were never staged or stashed never became objects.
- **No author for some objects.** Blobs and trees have no author. Metadata comes only
  from commits, so a blob in a dangling tree, or a blob that was never committed, has no
  author or date.
- **Remote-only history** (other clones, forks, hosting-side PR refs) is not visible
  locally.
- **Encoding.** Commit text is decoded as UTF-8 with replacement characters. The legacy
  `encoding` header is ignored.
- **Scale.** `fsck` runs three times, and `ls-tree` runs once per distinct root tree.
  This is fine for typical repositories but slow on very large monorepos. Reading in
  batches keeps memory bounded per batch of 256 objects.
- **Not covered:** shallow or partial clones (objects may be missing; they are logged
  and skipped), objects borrowed through `alternates` (listed, but not classified
  separately), and submodule contents (gitlinks are skipped).
- **Ownership checks.** Git's `safe.directory` check is not bypassed. Scanning a
  repository owned by another user raises `GitError`.
