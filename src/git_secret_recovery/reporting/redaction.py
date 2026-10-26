"""Keep secret values out of every string that leaves the tool.

Findings are already redacted, but free text such as file paths, author names or error
messages can contain a secret too (a token used as a file name, pasted into a Git
identity...). ``redact_text`` runs the same detectors over such text and masks matches.
"""

from __future__ import annotations

from git_secret_recovery.core.models import redact
from git_secret_recovery.detection.engine import scan_blob


def redact_text(text: str) -> str:
    """Return ``text`` with every detected secret replaced by its redacted form."""
    raw = text.encode("utf-8", errors="surrogateescape")
    matches = scan_blob(raw)
    if not matches:
        return text

    parts: list[bytes] = []
    cursor = 0
    for match in matches:
        if match.start < cursor:  # overlaps a span already masked
            continue
        parts += [raw[cursor : match.start], redact(match.value).encode()]
        cursor = match.end
    parts.append(raw[cursor:])
    return b"".join(parts).decode("utf-8", errors="replace")


def redact_optional(text: str | None) -> str | None:
    return None if text is None else redact_text(text)
