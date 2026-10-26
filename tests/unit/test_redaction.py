from __future__ import annotations

import pytest

from git_secret_recovery.reporting.redaction import redact_optional, redact_text

TOKEN = "ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0001"
KEY_ID = "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"secrets/{TOKEN}.txt", "secrets/ghp_…[40 chars].txt"),
        (f"error near {KEY_ID}: denied", "error near AKIA…[20 chars]: denied"),
        (f"{TOKEN} {TOKEN}", "ghp_…[40 chars] ghp_…[40 chars]"),
    ],
)
def test_masks_every_secret_in_free_text(text: str, expected: str) -> None:
    assert redact_text(text) == expected


@pytest.mark.parametrize("text", ["", "config/app.env", "Ünïcödé author", "ghp_short"])
def test_leaves_clean_text_untouched(text: str) -> None:
    assert redact_text(text) == text


def test_is_idempotent() -> None:
    once = redact_text(f"path/{TOKEN}")
    assert redact_text(once) == once


def test_preserves_non_ascii_around_a_secret() -> None:
    assert redact_text(f"café/{TOKEN}/é") == "café/ghp_…[40 chars]/é"


def test_optional_passes_none_through() -> None:
    assert redact_optional(None) is None
    assert redact_optional(TOKEN) == "ghp_…[40 chars]"
