from __future__ import annotations

import pytest

from git_secret_recovery.detection.rules import aws

KEY_ID = b"AKIAIOSFODNN7EXAMPLE"  # AWS documentation example
TEMP_KEY_ID = b"ASIAIOSFODNN7EXAMPLE"
SECRET = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def hits(content: bytes) -> list[tuple[str, bytes]]:
    return [(kind, content[start:end]) for kind, start, end in aws.detect(content)]


@pytest.mark.parametrize("key_id", [KEY_ID, TEMP_KEY_ID])
def test_detects_access_key_ids(key_id: bytes) -> None:
    assert hits(b"key=" + key_id + b"\n") == [("aws_access_key_id", key_id)]


@pytest.mark.parametrize(
    "assignment",
    [
        b"aws_secret_access_key = %s",
        b"export AWS_SECRET_ACCESS_KEY=%s",
        b'"AWS_SECRET_ACCESS_KEY": "%s"',
        b"aws-secret-key: '%s'",
    ],
)
def test_detects_secret_key_named_as_aws(assignment: bytes) -> None:
    assert hits(assignment % SECRET) == [("aws_secret_access_key", SECRET)]


def test_generic_secret_key_is_associated_through_a_key_id_in_the_same_blob() -> None:
    content = b"access_key = " + KEY_ID + b"\nsecret_key = " + SECRET + b"\n"
    assert hits(content) == [("aws_access_key_id", KEY_ID), ("aws_secret_access_key", SECRET)]


@pytest.mark.parametrize(
    "content",
    [
        b"AKIAIOSFODNN7EXAMPL",  # 19 characters
        b"XAKIAIOSFODNN7EXAMPLE",  # embedded in a longer identifier
        b"AKIAIOSFODNN7EXAMPLEX",
        b"akiaiosfodnn7example",  # IDs are upper case
        b"AIDAIOSFODNN7EXAMPLE",  # IAM user *ID*, not a credential
        b"secret_key = " + SECRET,  # 40 chars but nothing says AWS
        b"aws_secret_access_key = " + SECRET + b"A",  # 41 characters
        b"aws_secret_access_key = short",
    ],
)
def test_ignores_lookalikes(content: bytes) -> None:
    assert hits(content) == []
