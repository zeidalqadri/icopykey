"""
Entry point for running the x100_decrypt CLI via ``python -m``.
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())