#!/usr/bin/env python3
"""
Serial Console — interactive serial-port console with command handling.

Run this file directly:
    python main.py

Or install the package and use the console script:
    serial-console
"""

from __future__ import annotations

import asyncio
import sys

from serial_console.app import Application


def main() -> int:
    """Create the application and run the asyncio event loop."""
    # print("\033[91mHello, world!\033[0m")
    app = Application()
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass
    finally:
        print("\nGoodbye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
