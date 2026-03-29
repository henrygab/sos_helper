"""
Application orchestrator.

The :class:`Application` wires the serial manager, logging subsystem, command
registry, and interactive shell into a single cohesive runtime.  It owns the
asyncio lifecycle and handles startup / shutdown sequencing.

Why a separate class?
    Keeping the wiring in one place (rather than spread across ``main.py``)
    makes it straightforward to instantiate the application from alternative
    entry points (tests, embedding experiments, …) or to swap subsystem
    implementations.
"""

from __future__ import annotations

from .serial_manager import SerialManager
from .logging_subsystem import LogManager
from .command_registry import CommandRegistry
from .shell import InteractiveShell
from .commands.builtin import register_builtin_commands
from .commands.examples import register_example_commands
from .commands.sword_of_secrets import register_sword_of_secrets_commands
from .commands.sword_of_secrets_spoilers_1 import register_sword_of_secrets_spoilers_1
from .commands.sword_of_secrets_spoilers_2 import register_sword_of_secrets_spoilers_2
#from .commands.sword_of_secrets_spoilers_3 import register_sword_of_secrets_spoilers_3
#from .commands.sword_of_secrets_spoilers_4 import register_sword_of_secrets_spoilers_4
#from .commands.sword_of_secrets_spoilers_5 import register_sword_of_secrets_spoilers_5
#from .commands.sword_of_secrets_spoilers_6 import register_sword_of_secrets_spoilers_6
#from .commands.sword_of_secrets_spoilers_7 import register_sword_of_secrets_spoilers_7

class Application:
    """Top‑level application that owns every subsystem."""

    def __init__(self) -> None:
        # --- subsystems (order matters for wiring) --------------------------
        self.serial_manager = SerialManager()
        self.log_manager = LogManager()
        self.command_registry = CommandRegistry()
        # The shell needs a reference to *self* so it can access the other
        # subsystems.  This circular reference is intentional and mirrors the
        # "mediator" pattern.
        self.shell = InteractiveShell(self)

        # --- wire serial‑manager callbacks to the logging subsystem ---------
        self.serial_manager.add_rx_callback(self._on_rx)
        self.serial_manager.add_tx_callback(self._on_tx)

        # --- populate the command registry ----------------------------------
        register_builtin_commands(self.command_registry)
        register_example_commands(self.command_registry)
        register_sword_of_secrets_commands(self.command_registry)
        register_sword_of_secrets_spoilers_1(self.command_registry)
        register_sword_of_secrets_spoilers_2(self.command_registry)
        #register_sword_of_secrets_spoilers_3(self.command_registry)
        #register_sword_of_secrets_spoilers_4(self.command_registry)
        #register_sword_of_secrets_spoilers_5(self.command_registry)
        #register_sword_of_secrets_spoilers_6(self.command_registry)
        #register_sword_of_secrets_spoilers_7(self.command_registry)
        
    # -- serial → logging bridge ---------------------------------------------

    def _on_rx(self, data: bytes) -> None:
        self.log_manager.log_rx(data)

    def _on_tx(self, data: bytes) -> None:
        self.log_manager.log_tx(data)

    # -- lifecycle -----------------------------------------------------------

    async def run(self) -> None:
        """Run the interactive session.  Blocks until the user quits."""
        try:
            await self.shell.run()
        finally:
            # Ensure a clean shutdown regardless of how we exit.
            await self.serial_manager.disconnect()
            self.log_manager.close()
