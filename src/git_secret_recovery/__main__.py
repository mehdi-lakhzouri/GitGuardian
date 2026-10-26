"""Allow ``python -m git_secret_recovery``."""

import sys

from git_secret_recovery.cli import main

sys.exit(main())
