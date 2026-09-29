"""Entry point for python -m password_generator."""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
