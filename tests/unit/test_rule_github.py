from __future__ import annotations

import pytest

from git_secret_recovery.detection.rules import github

BODY = b"FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0001"  # 36 characters
FINE_GRAINED = b"github_pat_" + b"A1b2C3d4E5f6G7h8I9j0K1" + b"_" + b"Z" * 59


def hits(content: bytes) -> list[tuple[str, bytes]]:
    return [(kind, content[start:end]) for kind, start, end in github.detect(content)]


@pytest.mark.parametrize(
    ("prefix", "secret_type"),
    [
        (b"ghp", "github_classic_pat"),
        (b"gho", "github_oauth_token"),
        (b"ghu", "github_app_user_token"),
        (b"ghs", "github_app_installation_token"),
        (b"ghr", "github_refresh_token"),
    ],
)
def test_detects_prefixed_tokens(prefix: bytes, secret_type: str) -> None:
    token = prefix + b"_" + BODY
    assert hits(b"TOKEN=" + token + b"\n") == [(secret_type, token)]


def test_detects_fine_grained_pat() -> None:
    assert hits(b'token: "' + FINE_GRAINED + b'"') == [("github_fine_grained_pat", FINE_GRAINED)]


@pytest.mark.parametrize(
    "content",
    [
        b"ghp_" + BODY[:-1],  # 35 characters
        b"ghp_" + BODY + b"X",  # 37 characters
        b"ghx_" + BODY,  # unknown prefix
        b"xghp_" + BODY,  # inside a longer word
        b"ghp_" + BODY[:-1] + b"-",  # invalid character
        FINE_GRAINED[:-1],  # truncated fine-grained PAT
        b"github_pat_",
    ],
)
def test_ignores_lookalikes(content: bytes) -> None:
    assert hits(content) == []
