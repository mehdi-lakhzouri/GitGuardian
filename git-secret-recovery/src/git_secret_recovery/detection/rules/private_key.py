"""Multiline PEM / OpenSSH / PGP private key blocks with a basic structural check.

A block is reported only if its BEGIN and END labels match and its body, once armor
headers (``Proc-Type:``, ``Version:``...) and the PGP checksum line are removed, is
well-formed base64 decoding to at least ``_MIN_KEY_BYTES``. This rejects placeholders
such as ``-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----``.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator

from git_secret_recovery.detection.rules import Hit

_MIN_KEY_BYTES = 32  # far below any real key (an Ed25519 OpenSSH key is ~400 bytes)
_BLOCK = re.compile(
    rb"-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----"
    rb"(?P<body>(?:(?!-----).)*?)"  # never spans into another BEGIN/END line
    rb"-----END (?P=label)-----",
    re.DOTALL,
)
_ESCAPED_NEWLINE = re.compile(rb"\\r|\\n")  # keys pasted into JSON/YAML strings


def detect(content: bytes) -> Iterator[Hit]:
    for match in _BLOCK.finditer(content):
        if _has_key_material(match["body"]):
            yield "private_key", match.start(), match.end()


def _has_key_material(body: bytes) -> bool:
    lines = _ESCAPED_NEWLINE.sub(b"\n", body).splitlines()
    payload = b"".join(
        line.strip()
        for line in lines
        if b":" not in line  # armor header, e.g. "DEK-Info: AES-128-CBC,..."
        and not line.strip().startswith(b"=")  # PGP CRC24 checksum line
    )
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) >= _MIN_KEY_BYTES
