# ==============================================================================
# Program: __main__.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Module execution entrypoint for running edge-log-shipper via
#          , dispatching command-line arguments to the CLI handler.
# ==============================================================================
"""
Module execution entrypoint for python -m edgeshipper.
"""

from __future__ import annotations

import sys
from edgeshipper.cli import main

# Step 1: Forward invocation to CLI main entrypoint
if __name__ == "__main__":
    sys.exit(main())
