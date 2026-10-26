"""Serialize a ``ScanResult`` to a stable JSON document.

Schema (``schema_version`` 1). Every key is always present; unknown values are ``null``.

    {
      "schema_version": 1,
      "tool": {"name", "version"},
      "repository": {"path", "head"},
      "scan": {"started_at", "duration_seconds"},
      "summary": {"objects", "objects_by_type", "objects_by_reachability", "blobs_scanned",
                  "binary_blobs", "findings", "occurrences", "findings_by_type",
                  "occurrences_by_reachability"},
      "findings": [{
        "type", "fingerprint_sha256", "redacted", "occurrences",
        "locations": [{"blob_sha", "path", "line", "start_byte", "end_byte", "commit_sha",
                       "author_name", "author_email", "date", "reachability"}]
      }]
    }

No raw secret is ever serialized: findings carry only a fingerprint and a redacted
prefix, and free-text fields go through ``redact_text``.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from typing import Any

from git_secret_recovery import __version__
from git_secret_recovery.core.models import Finding, ScanResult, SecretLocation
from git_secret_recovery.reporting.redaction import redact_optional, redact_text

SCHEMA_VERSION = 1
TOOL_NAME = "git-secret-recovery"


def report_dict(result: ScanResult) -> dict[str, Any]:
    occurrences = [loc for finding in result.findings for loc in finding.locations]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "repository": {"path": redact_text(str(result.repository)), "head": result.head},
        "scan": {
            "started_at": result.started_at.isoformat(),
            "duration_seconds": result.duration_seconds,
        },
        "summary": {
            "objects": sum(result.objects_by_type.values()),
            "objects_by_type": result.objects_by_type,
            "objects_by_reachability": result.objects_by_reachability,
            "blobs_scanned": result.blobs_scanned,
            "binary_blobs": result.binary_blobs,
            "findings": len(result.findings),
            "occurrences": len(occurrences),
            "findings_by_type": _count(f.secret_type for f in result.findings),
            "occurrences_by_reachability": _count(str(loc.reachability) for loc in occurrences),
        },
        "findings": [_finding(finding) for finding in result.findings],
    }


def to_json(result: ScanResult) -> str:
    # ensure_ascii keeps the document valid whatever the console or file encoding is.
    return json.dumps(report_dict(result), indent=2, ensure_ascii=True) + "\n"


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "type": finding.secret_type,
        "fingerprint_sha256": finding.fingerprint,
        "redacted": finding.redacted,
        "occurrences": len(finding.locations),
        "locations": [_location(loc) for loc in finding.locations],
    }


def _location(loc: SecretLocation) -> dict[str, Any]:
    commit = loc.commit
    authored_at = commit.authored_at if commit else None
    return {
        "blob_sha": loc.blob_sha,
        "path": redact_optional(loc.path),
        "line": loc.line,
        "start_byte": loc.start,
        "end_byte": loc.end,
        "commit_sha": commit.sha if commit else None,
        "author_name": redact_optional(commit.author_name) if commit else None,
        "author_email": redact_optional(commit.author_email) if commit else None,
        "date": authored_at.isoformat() if authored_at else None,
        "reachability": str(loc.reachability),
    }


def _count(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))
