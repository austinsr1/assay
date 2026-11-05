"""``python3 -m tenable_email`` -- the reviewer's entry point.

Thin by design: :func:`tenable_email.cli.main` holds the argument handling and
returns the exit code, so the console script ``tenable-email`` and this module do
exactly the same thing. Nothing here reads configuration, and nothing here opens
a socket.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
