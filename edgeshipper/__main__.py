# Program: edge-log-shipper - __main__.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Lets the package run with python -m edgeshipper by handing control to the command-line main() function.
"""
Module execution entrypoint for python -m edgeshipper.
"""

from __future__ import annotations

# sys is used for sys.exit so the program's return code reaches the shell.
import sys
# main() parses command-line arguments and runs the chosen subcommand.
from edgeshipper.cli import main

# Only run when started as a program (python -m edgeshipper), not when imported.
if __name__ == "__main__":
    sys.exit(main())
