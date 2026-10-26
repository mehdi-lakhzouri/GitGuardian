# git-secret-recovery

*Find what Git forgot to forget.* An offline, read-only tool that recovers secrets from
**every** object in a local Git repository, including commits that no branch or log
shows anymore. It reports each secret's type, file path, line, commit, author, date and
reachability as machine-parsable JSON.

Detected: AWS access key IDs and secret access keys, GitHub tokens (`ghp_`, `gho_`,
`ghu_`, `ghs_`, `ghr_`, `github_pat_`) and PEM/OpenSSH/PGP private keys.

## Installation

Requires Python 3.11+ and the Git CLI on `PATH`. No runtime dependencies.

```sh
uv sync                                   # dev environment (.venv, pytest, ruff)
uv tool install .                         # or install the CLI globally from the checkout
```

## Usage

```sh
git-secret-recovery scan ./repository                         # JSON report on stdout
git-secret-recovery scan ./repository --output findings.json  # JSON report to a file
python -m git_secret_recovery scan ./repository               # without installing the script
```

stdout carries only the JSON report. Diagnostics and errors go to stderr. Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, no secret found |
| `1` | Scan completed, secrets found |
| `2` | Usage error, invalid or malformed repository, or the report could not be written |

The tool refuses to write `--output` inside the scanned repository (work tree or
`.git`), so a scan never adds a file to it.

To try it on the fixture repository that hides fake secrets five different ways:

```sh
uv run python tests/fixtures/generate_repo.py ../demo-repo
uv run git-secret-recovery scan ../demo-repo
```

## Sample output

From the fixture, trimmed to two of the seven findings:

```json
{
  "schema_version": 1,
  "tool": {"name": "git-secret-recovery", "version": "0.1.0"},
  "repository": {"path": "/tmp/demo-repo", "head": "3d192a3a0ff3611b7505ad0ba078efad489da04a"},
  "scan": {"started_at": "2026-10-26T21:35:01.508449+00:00", "duration_seconds": 1.175},
  "summary": {
    "objects": 35,
    "objects_by_type": {"blob": 9, "commit": 11, "tree": 15},
    "objects_by_reachability": {"reachable": 17, "reflog_only": 14, "unreachable": 4},
    "blobs_scanned": 9,
    "binary_blobs": 1,
    "findings": 7,
    "occurrences": 8,
    "findings_by_type": {"aws_access_key_id": 2, "aws_secret_access_key": 2,
                         "github_classic_pat": 2, "private_key": 1},
    "occurrences_by_reachability": {"reachable": 2, "reflog_only": 5, "unreachable": 1}
  },
  "findings": [
    {
      "type": "private_key",
      "fingerprint_sha256": "1653950f3097c18f3e2b108554f9e77eeb0fe4c26a69ad8ca1b10163328d19d9",
      "redacted": "----…[886 chars]",
      "occurrences": 2,
      "locations": [
        {"blob_sha": "2262d1398ab864d304b73abb0ff389881783da90", "path": "deploy/id_rsa",
         "line": 1, "start_byte": 0, "end_byte": 886,
         "commit_sha": "5921d3e36d7d35aa9212dcefbc636c90dbcf32f2",
         "author_name": "Dave Deployer", "author_email": "dave.deployer@example.com",
         "date": "2026-01-01T14:00:00+00:00", "reachability": "reflog_only"},
        {"blob_sha": "2262d1398ab864d304b73abb0ff389881783da90", "path": "deploy/id_rsa",
         "line": 1, "start_byte": 0, "end_byte": 886,
         "commit_sha": "2612ffe90d6825bd2d17eca28efe198637a46223",
         "author_name": "Dave Deployer", "author_email": "dave.deployer@example.com",
         "date": "2026-01-01T16:00:00+00:00", "reachability": "reflog_only"}
      ]
    },
    {
      "type": "github_classic_pat",
      "fingerprint_sha256": "d01af376bb9cd8abe0986af29f74efb91a511024278163ca8d392ec4d5754070",
      "redacted": "ghp_…[40 chars]",
      "occurrences": 1,
      "locations": [
        {"blob_sha": "2a92d2b33c7736b5d4f81ec54e8ffa2ff775ebee", "path": ".env",
         "line": 1, "start_byte": 13, "end_byte": 53,
         "commit_sha": "920a95b2190ad8789c9e896cb411cf8e2c938a9c",
         "author_name": "Carol Coder", "author_email": "carol.coder@example.com",
         "date": "2026-01-01T09:00:00+00:00", "reachability": "reflog_only"}
      ]
    }
  ]
}
```

stderr: `git-secret-recovery: scanned 35 objects (9 blobs) in 1.175s: 7 secrets, 8 occurrences`

### Report schema

- Every key is always present. Unknown values are `null`. For example, a blob that was
  staged but never committed has `path`, `commit_sha`, `author_name`, `author_email`
  and `date` set to `null`.
- One entry in `findings` is one distinct secret, deduplicated by `(type, SHA-256)`.
  `locations` lists every historical occurrence: each (blob, path, commit, line), sorted
  oldest first.
- `reachability` is per occurrence and comes from the commit, because the same blob may
  also sit in a reachable commit:
  - `reachable`: from a branch, tag, stash or the index
  - `reflog_only`: kept alive only by a reflog (amend, rebase, deleted branch)
  - `unreachable`: no ref and no reflog; survives until garbage collection
- **No raw secret is ever written.** Each finding carries a fingerprint and a 4-character
  prefix only. Paths, author fields and error messages are also run through the
  detectors and masked, in case a secret was used as a file name or Git identity.
  Output is ASCII-only JSON, so it is valid on any console encoding.

## Architecture

```text
src/git_secret_recovery/
├── cli.py / __main__.py     argparse entry point: streams, exit codes, output guard
├── core/
│   ├── models.py            frozen dataclasses: GitObject, Commit, BlobLocation,
│   │                        SecretMatch, SecretLocation, Finding, ScanResult
│   └── scanner.py           scan_repository(): the pipeline below
├── git/                     Phase 1: read-only forensics
│   ├── repository.py        validation, shell-free run_git(), repository_dirs(), head_commit()
│   ├── objects.py           enumerate + classify every object, batched reads, commit parsing
│   └── history.py           refs, reflogs, blob -> path -> commit index
├── detection/               Phase 2: pure rules over raw bytes
│   ├── engine.py            scan_blob(bytes) -> list[SecretMatch] with byte offsets and lines
│   └── rules/               aws.py, github.py, private_key.py
├── attribution/resolver.py  dedup by fingerprint + expand every historical occurrence
└── reporting/               Phase 3
    ├── serializer.py        ScanResult -> JSON (schema_version 1)
    └── redaction.py         redact_text(): mask secrets in any free text
docs/credential_research.md  OpenAI API keys: detection, safe validation, ownership
```

Pipeline (`core/scanner.py`):

1. **Enumerate** every loose and packed object once, with
   `git cat-file --batch-all-objects`.
2. **Classify** each object with three `git fsck --connectivity-only` passes: reachable,
   reflog-only, unreachable, and dangling (an unreachable object no other object
   references).
3. **Scan** every blob's raw bytes with each detection rule, in batches of 256 through
   `git cat-file --batch`.
4. **Index** history by walking the tree of *every* commit object, including amended,
   rebased, deleted-branch and stash commits, to map blob → (path, commit).
5. **Resolve** matches into findings: one per distinct secret, with all of its
   occurrences.
6. **Serialize** the findings to JSON, redacting free text.

### Detection rules

| Rule | Detects | False-positive guard |
| --- | --- | --- |
| `aws` | `AKIA…` / `ASIA…` access key IDs (20 chars) | Word boundaries, upper-case only |
| `aws` | 40-char secret access keys | Must be assigned to a `secret_access_key`-style name **and** be identifiably AWS: an `aws` prefix, or an access key ID in the same blob |
| `github` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` + 36 chars; `github_pat_` 22 + `_` + 59 chars | Exact lengths, word boundaries |
| `private_key` | PEM / OpenSSH / PGP `PRIVATE KEY` blocks | BEGIN and END labels must match; the body (minus armor headers) must be valid base64 of at least 32 bytes. Handles CRLF and keys escaped as `\n` inside JSON strings |

### Fixture: five hiding scenarios

`tests/fixtures/generate_repo.py` builds a reproducible repository: identities, dates
and config are pinned, and the developer's global Git config is ignored. It uses only
fake credentials: AWS's published `…EXAMPLE` keys, `ghp_FAKE…` tokens, and a PEM
envelope around deterministic random bytes (not a valid key). It never runs `gc`,
`prune` or `repack -d`.

| Scenario | Secret | Path:line | Author | Occurrences | Reachability |
| --- | --- | --- | --- | --- | --- |
| File deletion | AWS key ID + secret #1 | `config/aws_credentials:2-3` | Bob Builder | 1 | reachable |
| Commit amend | GitHub PAT #1 | `.env:1` | Carol Coder | 1 | reflog_only |
| Rebase (drop) | Private key | `deploy/id_rsa:1` | Dave Deployer | 2 | reflog_only |
| Branch deletion | AWS key ID + secret #2 | `scripts/backup.sh:2-3` | Eve Experimenter | 1 | reflog_only |
| Stash drop | GitHub PAT #2 | `README.md:3` | Frank Forgetful | 1 | unreachable |

After `git reflog expire --expire=now --all`, every rewritten secret becomes
`unreachable` and is still recovered. The tests check this.

## Security properties

- **Offline.** No network access. Credentials are never validated against a service.
- **Read-only.** Git runs as an argument list (never `shell=True`), and only read-only
  plumbing commands are called. `GIT_OPTIONAL_LOCKS=0`, `gc.auto=0`,
  `maintenance.auto=false` and `core.fsmonitor=false` stop Git from writing to the
  scanned repository or running code from its config. Tests check that every file in
  the repository is byte-identical after a scan.
- **No disclosure.** Raw values exist only in memory (`SecretMatch.value`, which is
  left out of `repr`). JSON, stderr and error messages carry fingerprints and redacted
  prefixes only.

## Development

```sh
uv run pytest                                       # 139 unit + integration tests
uv run ruff format --check . && uv run ruff check .
```

CI (`.github/workflows/ci.yml`) runs both on Ubuntu and Windows.

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
- **Commit messages and tag annotations are not scanned.** Only blobs are.

### Git forensics

- **Garbage collection is final.** After `git gc --prune=now` (or the default 2-week
  prune), unreachable objects are deleted and cannot be recovered from the object store.
- **Never-committed data.** A staged-then-unstaged file *is* recovered, but it has no
  path, commit, author or date (reported as `null`). Working-tree changes that were never
  staged or stashed never became objects.
- **Remote-only history** (other clones, forks, hosting-side PR refs) is not visible
  locally.
- **Encoding.** Commit text is decoded as UTF-8 with replacement characters. The legacy
  `encoding` header is ignored.
- **Scale.** `fsck` runs three times, and `ls-tree` runs once per distinct root tree.
  Blob contents are read in batches of 256 objects. This is fine for typical repositories
  but slow on very large monorepos.
- **Not covered:** shallow or partial clones (missing objects are logged and skipped),
  objects borrowed through `alternates` (listed, not classified separately), and
  submodule contents (gitlinks are skipped).
- **Ownership checks.** Git's `safe.directory` check is not bypassed. Scanning a
  repository owned by another user exits with code `2`.
