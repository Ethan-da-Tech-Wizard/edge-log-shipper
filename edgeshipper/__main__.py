"""
Module execution entrypoint for python -m edgeshipper.
"""

from __future__ import annotations

import sys
from edgeshipper.cli import main

if __name__ == "__main__":
    sys.exit(main())
