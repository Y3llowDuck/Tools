#!/usr/bin/env python3
"""SmartCheckAgent entry point.

Thin wrapper so the tool runs as `python agent.py ...` per the spec.
All logic lives in the `smartcheck` package.
"""
import sys

from smartcheck.cli import main

if __name__ == "__main__":
    sys.exit(main())
