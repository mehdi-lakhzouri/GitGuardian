"""Command-line interface: ``git-secret-recovery scan <repository> [--output FILE]``.

stdout carries only the JSON report (when no ``--output`` is given); every diagnostic
goes to stderr. Exit codes follow the usual secret-scanner convention so the tool can
gate a pipeline:

    0  scan completed, no secret found
    1  scan completed, secrets found
    2  usage error, invalid repository, or the scan/report could not be completed
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from git_secret_recovery import __version__
from git_secret_recovery.core.scanner import scan_repository
from git_secret_recovery.git.repository import GitError, repository_dirs, validate_repository
from git_secret_recovery.reporting.redaction import redact_text
from git_secret_recovery.reporting.serializer import TOOL_NAME, to_json

EXIT_CLEAN = 0
EXIT_SECRETS_FOUND = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Recover secrets from every object of a local Git repository, "
        "including commits no branch or log shows anymore. Offline and read-only.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = commands.add_parser("scan", help="scan a repository and report findings as JSON")
    scan.add_argument("repository", type=Path, help="path to a local Git repository")
    scan.add_argument(
        "-o", "--output", type=Path, help="write the JSON report to this file instead of stdout"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)  # exits with code 2 on usage errors
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        return _scan(args.repository, args.output)
    except (GitError, OSError) as exc:
        return _fail(str(exc))


def _scan(repository: Path, output: Path | None) -> int:
    repo = validate_repository(repository)
    if output is not None and _is_inside(output, repository_dirs(repo)):
        return _fail(f"refusing to write the report inside the scanned repository: {output}")

    result = scan_repository(repo)
    report = to_json(result)
    if output is None:
        sys.stdout.write(report)
    else:
        output.write_text(report, encoding="utf-8")

    occurrences = sum(len(f.locations) for f in result.findings)
    _diagnose(
        f"scanned {sum(result.objects_by_type.values())} objects "
        f"({result.blobs_scanned} blobs) in {result.duration_seconds}s: "
        f"{len(result.findings)} secrets, {occurrences} occurrences"
        + (f"; report written to {output}" if output else "")
    )
    return EXIT_SECRETS_FOUND if result.findings else EXIT_CLEAN


def _is_inside(path: Path, roots: Sequence[Path]) -> bool:
    target = os.path.normcase(path.resolve())
    for root in roots:
        base = os.path.normcase(root)
        if target == base or target.startswith(base.rstrip(os.sep) + os.sep):
            return True
    return False


def _fail(message: str) -> int:
    _diagnose(f"error: {message}")
    return EXIT_ERROR


def _diagnose(message: str) -> None:
    print(f"{TOOL_NAME}: {redact_text(message)}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
