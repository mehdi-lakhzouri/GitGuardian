# git-secret-recovery

*Find what Git forgot to forget.* A read-only tool that recovers secrets from every
object in a local Git repository, including objects that no branch or log shows
anymore, and attributes each one to its paths, commits, authors, dates and reachability.

- **Phase 1:** Git forensics engine (object enumeration, reachability, history index).
- **Phase 2:** secret detection (AWS, GitHub, private keys) and attribution.
- **Phase 3 (not yet implemented):** CLI and JSON reporting.

## Layout

```text
src/git_secret_recovery/
├── core/models.py       # GitObject, Commit, BlobLocation, SecretMatch, SecretLocation, Finding
├── git/
│   ├── repository.py    # validate_repository(), run_git(): no shell, read-only env
│   ├── objects.py       # list_objects(), iter_object_contents(), parse_commit(), read_tree()
│   └── history.py       # list_refs(), list_reflog_entries(), reconstruct_blob_locations()
├── detection/
│   ├── engine.py        # scan_blob(bytes) -> list[SecretMatch] (byte offsets + line numbers)
│   └── rules/           # aws.py, github.py, private_key.py: pure detect(bytes) functions
└── attribution/
    └── resolver.py      # find_secrets(repo), resolve_findings(): dedup + history
tests/
├── fixtures/generate_repo.py   # builds the 5-scenario fake-secret repository
├── fixtures/scan.py            # test helper that runs the full pipeline
├── integration/                # end-to-end checks on generated repositories
└── unit/                       # parsing, each detector, engine, resolver
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

## Secret detection (Phase 2)

Each rule is a pure function that runs over the **raw bytes** of a blob. Offsets are
exact byte offsets, and binary blobs need no decoding.

| Rule | Detects | False-positive guard |
|---|---|---|
| `aws` | `AKIA…` / `ASIA…` access key IDs (20 chars) | Word boundaries, upper-case only |
| `aws` | 40-char secret access keys | Must be assigned to a `secret_access_key`-style name **and** be identifiably AWS: an `aws` prefix, or an access key ID in the same blob |
| `github` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` + 36 chars; `github_pat_` 22 + `_` + 59 chars | Exact lengths, word boundaries |
| `private_key` | PEM / OpenSSH / PGP `PRIVATE KEY` blocks | BEGIN and END labels must match; the body (minus armor headers) must be valid base64 of at least 32 bytes. Handles CRLF and `
`-escaped keys in JSON. |

`resolve_findings()` groups matches by `(type, SHA-256 fingerprint)`. Each distinct
secret becomes one `Finding`, with one `SecretLocation` per (blob, path, commit, line).
A location's reachability is that of its **commit**, because the same blob can also
sit in a reachable commit. Without a commit, the blob's own reachability is used.
Raw values exist only in `SecretMatch.value`, which is left out of `repr`. Everything
else carries a fingerprint and a redacted form such as `ghp_…[40 chars]`.

Results on the fixture, as asserted by the tests:

| Secret | Path:line | Author | Occurrences | Reachability |
|---|---|---|---|---|
| AWS key ID + secret #1 | `config/aws_credentials:2-3` | Bob Builder | 1 | reachable |
| GitHub PAT #1 | `.env:1` | Carol Coder | 1 | reflog-only |
| Private key | `deploy/id_rsa:1` | Dave Deployer | 2 (both pre-rebase commits) | reflog-only |
| AWS key ID + secret #2 | `scripts/backup.sh:2-3` | Eve Experimenter | 1 | reflog-only |
| GitHub PAT #2 | `README.md:3` | Frank Forgetful | 1 (stash commit) | unreachable |

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

### Detection

- **No validity check.** By design, no credential is sent to an external service.
  GitHub's offline CRC32 token checksum is also not verified, because the fixture's
  `ghp_FAKE…` tokens would fail it.
- **No allowlist.** AWS's documented `…EXAMPLE` keys are reported like real keys,
  because the fixture depends on them. A production scanner would suppress them.
- **Context-dependent AWS secrets.** A secret key named without "aws", in a blob with no
  access key ID (for example, split across two files), is not reported.
- **Truncated private keys** (no END line) are not reported, and neither are keys
  stored in binary formats such as DER or PKCS#12.
- **Compressed or encoded content** (zip, gzip, base64-wrapped config) is not unpacked.

### Git forensics

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
