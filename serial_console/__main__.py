"""Allow running as ``python -m serial_console``."""

from __future__ import annotations

import asyncio
import sys

from .app import Application


def main() -> int:
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
