"""GitHub tokens: classic prefixed tokens (``ghp_``, ``gho_``...) and fine-grained PATs.

Formats: classic tokens are a prefix + 36 base62 characters; fine-grained PATs are
``github_pat_`` + 22 characters + ``_`` + 59 characters.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from git_secret_recovery.detection.rules import Hit

_TYPES = {
    b"ghp": "github_classic_pat",
    b"gho": "github_oauth_token",
    b"ghu": "github_app_user_token",
    b"ghs": "github_app_installation_token",
    b"ghr": "github_refresh_token",
}
_START, _STOP = rb"(?<![A-Za-z0-9_])", rb"(?![A-Za-z0-9_])"  # not inside a longer word
_CLASSIC = re.compile(_START + rb"(?P<prefix>gh[pousr])_[A-Za-z0-9]{36}" + _STOP)
_FINE_GRAINED = re.compile(_START + rb"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}" + _STOP)


def detect(content: bytes) -> Iterator[Hit]:
    for match in _CLASSIC.finditer(content):
        yield _TYPES[match["prefix"]], match.start(), match.end()
    for match in _FINE_GRAINED.finditer(content):
        yield "github_fine_grained_pat", match.start(), match.end()
