"""Recover secrets that Git history and object storage still remember."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("git-secret-recovery")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0.0.0"
