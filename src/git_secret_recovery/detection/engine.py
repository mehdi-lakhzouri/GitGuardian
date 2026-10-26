"""Run every detection rule over a blob and return typed, positioned matches."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from git_secret_recovery.core.models import SecretMatch
from git_secret_recovery.detection.rules import Hit, aws, github, private_key

Rule = Callable[[bytes], Iterable[Hit]]

RULES: tuple[Rule, ...] = (aws.detect, github.detect, private_key.detect)


def scan_blob(content: bytes, rules: Iterable[Rule] = RULES) -> list[SecretMatch]:
    """Return every match in ``content``, ordered by byte offset.

    Rules are independent; a hit reported twice for the same span and type is kept once.
    Binary content is scanned as-is: secrets are ASCII, so they are found in any bytes.
    """
    hits = {hit for rule in rules for hit in rule(content)}
    return [
        SecretMatch(
            secret_type=secret_type,
            value=content[start:end].decode("ascii", errors="replace"),
            start=start,
            end=end,
            line=content.count(b"\n", 0, start) + 1,
        )
        for secret_type, start, end in sorted(hits, key=lambda hit: (hit[1], hit[2], hit[0]))
    ]
