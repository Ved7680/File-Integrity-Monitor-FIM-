"""Allows running the package directly: ``python -m fim``."""

import sys

from fim.cli import main

if __name__ == '__main__':
    sys.exit(main())
