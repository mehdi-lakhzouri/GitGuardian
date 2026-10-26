from __future__ import annotations

from pathlib import Path

import pytest
from fixtures.generate_repo import generate_repo
from fixtures.scan import Scan, scan_repository


@pytest.fixture(scope="session")
def fixture_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_repo(tmp_path_factory.mktemp("fixture") / "repo")


@pytest.fixture(scope="session")
def scan(fixture_repo: Path) -> Scan:
    return scan_repository(fixture_repo)
