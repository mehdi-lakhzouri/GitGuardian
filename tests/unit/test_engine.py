from __future__ import annotations

from collections.abc import Iterator

from git_secret_recovery.core.models import SecretMatch, secret_fingerprint
from git_secret_recovery.detection.engine import scan_blob
from git_secret_recovery.detection.rules import Hit

TOKEN = b"ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0001"
KEY_ID = b"AKIAIOSFODNN7EXAMPLE"


def test_reports_type_offsets_and_lines() -> None:
    content = b"line one\nkey=" + KEY_ID + b"\n\ntoken=" + TOKEN + b"\n"
    matches = scan_blob(content)

    assert [(m.secret_type, m.line) for m in matches] == [
        ("aws_access_key_id", 2),
        ("github_classic_pat", 4),
    ]
    for match in matches:
        assert content[match.start : match.end].decode() == match.value


def test_finds_secrets_in_binary_content_with_byte_offsets() -> None:
    content = b"\x89PNG\x00\xff\xfe\n\x00garbage=" + TOKEN + b"\x00\xc3\x28"
    (match,) = scan_blob(content)
    assert match.secret_type == "github_classic_pat"
    assert content[match.start : match.end] == TOKEN
    assert match.start == content.index(TOKEN)
    assert match.line == 2


def test_repeated_secret_in_one_blob_keeps_each_occurrence() -> None:
    matches = scan_blob(TOKEN + b"\n\n" + TOKEN)
    assert [m.line for m in matches] == [1, 3]
    assert len({m.fingerprint for m in matches}) == 1


def test_empty_and_clean_content() -> None:
    assert scan_blob(b"") == []
    assert scan_blob(b"nothing to see here\n" * 100) == []


def test_identical_hits_from_several_rules_are_merged() -> None:
    def rule(content: bytes) -> Iterator[Hit]:
        yield "custom", 0, 4

    assert len(scan_blob(b"abcd", rules=[rule, rule])) == 1


def test_raw_value_never_appears_in_repr() -> None:
    (match,) = scan_blob(TOKEN)
    assert TOKEN.decode() not in repr(match)
    assert TOKEN.decode() not in match.redacted
    assert match.fingerprint == secret_fingerprint(TOKEN.decode())
    assert match == SecretMatch("github_classic_pat", TOKEN.decode(), 0, len(TOKEN), 1)
