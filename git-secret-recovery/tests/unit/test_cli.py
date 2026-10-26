from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from git_secret_recovery import __version__
from git_secret_recovery.cli import EXIT_CLEAN, EXIT_ERROR, build_parser, main


def test_parser_reads_scan_arguments() -> None:
    args = build_parser().parse_args(["scan", "repo", "--output", "out.json"])
    assert (args.command, args.repository, args.output) == ("scan", Path("repo"), Path("out.json"))


@pytest.mark.parametrize("argv", [[], ["scan"], ["unknown"], ["scan", "repo", "--bogus"]])
def test_usage_errors_exit_2_on_stderr(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == EXIT_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage:" in captured.err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_missing_path_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path / "nope")]) == EXIT_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error: not a directory" in captured.err


def test_plain_directory_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR
    assert "not a Git repository" in capsys.readouterr().err


def test_malformed_repository_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / ".git").write_text("gitdir: ./does-not-exist\n")  # broken gitdir link
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err


def test_empty_repository_is_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S607
    assert main(["scan", str(tmp_path)]) == EXIT_CLEAN
    captured = capsys.readouterr()
    assert '"findings": []' in captured.out
    assert "0 secrets" in captured.err


def test_unwritable_output_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # noqa: S607
    assert main(["scan", str(repo), "-o", str(tmp_path / "missing-dir" / "out.json")]) == 2
    assert "error:" in capsys.readouterr().err


def test_errors_never_echo_a_secret(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    token = "ghp_FAKE0TOKEN0FOR0GITGUARDIAN0TESTS0001"
    assert main(["scan", str(tmp_path / token)]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert token not in err
    assert "ghp_…[40 chars]" in err
