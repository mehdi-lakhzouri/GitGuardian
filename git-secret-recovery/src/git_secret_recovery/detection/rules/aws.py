"""AWS access key IDs and their secret access keys.

An access key ID has a fixed, recognisable prefix. A secret access key is just 40
base64-like characters, so on its own it would match far too much. It is reported only
when it is assigned to a ``secret_access_key``-style name *and* is identifiably AWS:
either the name says so (``aws_secret_access_key``) or the same blob holds an access key ID.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from git_secret_recovery.detection.rules import Hit

# AKIA = long-term IAM user key, ASIA = temporary STS key.
_ACCESS_KEY_ID = re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
_SECRET_ACCESS_KEY = re.compile(
    rb"(?i)(?P<aws>aws)?[_.-]?secret[_.-]?(?:access[_.-]?)?key[\"']?\s*[:=]\s*[\"']?"
    rb"(?P<key>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"
)


def detect(content: bytes) -> Iterator[Hit]:
    key_ids = list(_ACCESS_KEY_ID.finditer(content))
    for match in key_ids:
        yield "aws_access_key_id", match.start(), match.end()

    for match in _SECRET_ACCESS_KEY.finditer(content):
        if match["aws"] or key_ids:
            yield "aws_secret_access_key", match.start("key"), match.end("key")
