#!/usr/bin/env python3
"""Entry point for running iStrip — double-click or run from terminal."""

import sys

try:
    from istrip.main import main
    main()
except Exception as exc:
    print(f"\nFatal error: {exc}")
    input("\nPress Enter to close...")
    sys.exit(1)
