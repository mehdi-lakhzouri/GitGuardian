from __future__ import annotations

import base64

import pytest

from git_secret_recovery.detection.rules import private_key


def pem(label: str, size: int = 256, headers: str = "", newline: str = "\n") -> bytes:
    """A structurally valid but meaningless key block (deterministic bytes, not a key)."""
    body = base64.b64encode(bytes(i % 256 for i in range(size))).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    parts = [f"-----BEGIN {label}-----", *([headers] if headers else []), *lines]
    return newline.join([*parts, f"-----END {label}-----"]).encode()


def hits(content: bytes) -> list[bytes]:
    return [content[start:end] for _, start, end in private_key.detect(content)]


@pytest.mark.parametrize(
    "label",
    ["RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY"],
)
def test_detects_pem_blocks(label: str) -> None:
    block = pem(label)
    assert hits(b"prefix\n" + block + b"\nsuffix") == [block]


def test_detects_encrypted_pem_with_armor_headers() -> None:
    block = pem("RSA PRIVATE KEY", headers="Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n")
    assert hits(block) == [block]


def test_detects_key_with_crlf_line_endings() -> None:
    block = pem("PRIVATE KEY", newline="\r\n")
    assert hits(block) == [block]


def test_detects_key_escaped_inside_json_string() -> None:
    block = pem("PRIVATE KEY", newline="\\n")
    content = b'{"private_key": "' + block + b'\\n"}'
    assert hits(content) == [block]


def test_detects_every_key_in_a_blob() -> None:
    first, second = pem("RSA PRIVATE KEY"), pem("EC PRIVATE KEY", size=121)
    assert hits(first + b"\n\n" + second) == [first, second]


def test_unterminated_block_does_not_hide_a_following_key() -> None:
    valid = pem("RSA PRIVATE KEY")
    assert hits(b"-----BEGIN RSA PRIVATE KEY-----\ntruncated\n" + valid) == [valid]


@pytest.mark.parametrize(
    "content",
    [
        b"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",  # placeholder
        b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",  # empty
        b"-----BEGIN PRIVATE KEY-----\nnot base64 at all!\n-----END PRIVATE KEY-----",
        pem("PRIVATE KEY", size=16),  # decodes, but far too short for a key
        pem("RSA PRIVATE KEY").replace(b"END RSA", b"END EC"),  # mismatched labels
        pem("RSA PRIVATE KEY").rsplit(b"\n", 1)[0],  # no END line
        pem("PUBLIC KEY"),  # public keys are not secrets
        pem("CERTIFICATE"),
    ],
)
def test_rejects_invalid_or_non_private_blocks(content: bytes) -> None:
    assert hits(content) == []
