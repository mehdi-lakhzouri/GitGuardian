from __future__ import annotations

from datetime import timedelta

from git_secret_recovery.git.objects import is_binary, parse_commit

TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def test_parse_commit_extracts_author_and_timezone() -> None:
    raw = (
        f"tree {TREE}\n"
        "parent aaaa\nparent bbbb\n"
        "author Ada Lovelace <ada@example.com> 1767225600 +0130\n"
        "committer Ada Lovelace <ada@example.com> 1767225600 +0130\n"
        "\nSubject line\n\nBody\n"
    ).encode()
    commit = parse_commit("c0ffee", raw)
    assert commit.tree == TREE
    assert commit.parents == ("aaaa", "bbbb")
    assert commit.author_name == "Ada Lovelace"
    assert commit.author_email == "ada@example.com"
    assert commit.authored_at is not None
    assert commit.authored_at.utcoffset() == timedelta(hours=1, minutes=30)
    assert commit.authored_at.timestamp() == 1767225600
    assert commit.message == "Subject line\n\nBody"


def test_parse_commit_tolerates_missing_or_malformed_author() -> None:
    no_author = parse_commit("1", f"tree {TREE}\n\nmsg".encode())
    garbage = parse_commit("2", f"tree {TREE}\nauthor ???\n\nmsg".encode())
    for commit in (no_author, garbage):
        assert commit.author_name is None
        assert commit.author_email is None
        assert commit.authored_at is None


def test_parse_commit_survives_invalid_utf8_and_signatures() -> None:
    raw = (
        f"tree {TREE}\n".encode()
        + b"author J\xe9r\xf4me <j@example.com> 0 -0500\n"
        + b"gpgsig -----BEGIN PGP SIGNATURE-----\n abc\n -----END PGP SIGNATURE-----\n"
        + b"\n\xff message\n"
    )
    commit = parse_commit("3", raw)
    assert commit.author_name is not None and "�" in commit.author_name
    assert commit.authored_at is not None
    assert commit.authored_at.utcoffset() == -timedelta(hours=5)
    assert commit.message.endswith("message")


def test_is_binary() -> None:
    assert is_binary(b"PNG\x00\x01")
    assert not is_binary(b"plain text\n")
