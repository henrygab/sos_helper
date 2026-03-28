"""
Command registry — registration, look‑up, and execution of commands.

Design decisions
~~~~~~~~~~~~~~~~
* A **CommandInfo** dataclass holds everything the framework needs: handler,
  help text, usage string, category, and an optional completions callback.
* Handlers are plain ``async`` functions with the signature::

      async def handler(args: str, ctx: CommandContext) -> None

  *args* is the raw string after the command name.  The handler is responsible
  for parsing it (``str.split``, ``shlex.split``, etc.).
* **CommandContext** wraps the :class:`~serial_console.app.Application` to give
  commands a stable, convenient API without coupling them to the application
  internals.
* Commands are **case‑insensitive**.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

if TYPE_CHECKING:
    from .app import Application


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CommandInfo:
    """Metadata for a single registered command."""

    name: str
    handler: Callable  # async (args: str, ctx: CommandContext) -> None
    help_text: str
    usage: str = ""
    category: str = "General"
    completions: Optional[Callable[[], List[str]]] = None


# ---------------------------------------------------------------------------
# Context passed to handlers
# ---------------------------------------------------------------------------

class CommandContext:
    """Execution context provided to every command handler.

    This is the *only* interface a command should use to interact with the
    rest of the framework.  It intentionally hides the raw ``Application``
    object so that commands remain decoupled and testable.
    """

    def __init__(self, app: Application) -> None:
        self.app = app
        self.serial = app.serial_manager
        self.log = app.log_manager
        self.registry = app.command_registry
        self.shell = app.shell

    # -- convenience printing helpers ----------------------------------------
    # def print_local(
    #         self,
    #         *values: object,
    #         style: str = "",
    #         sep: str | None = " ",
    #         end: str | None = "\n",
    #         flush: bool = False
    #         ) -> None:
    def print(self, *values: object, style: str = "", sep: str | None = " ", end: str | None = "\n", flush: bool = False) -> None:
        """Print *message* to the local terminal (not the serial port)."""
        self.shell.print_local(*values, style = style, sep = sep, end = end, flush = flush)

    def print_error  (self, *values: object, sep: str | None = " ", end: str | None = "\n", flush: bool = False) -> None:
        self.shell.print_local(*values, style = "error", sep = sep, end = end, flush = flush)

    def print_success(self, *values: object, sep: str | None = " ", end: str | None = "\n", flush: bool = False) -> None:
        self.shell.print_local(*values, style = "success", sep = sep, end = end, flush = flush)

    def print_info   (self, *values: object, sep: str | None = " ", end: str | None = "\n", flush: bool = False) -> None:
        self.shell.print_local(*values, style = "info", sep = sep, end = end, flush = flush)

    def print_warning(self, *values: object, sep: str | None = " ", end: str | None = "\n", flush: bool = False) -> None:
        self.shell.print_local(*values, style = "warning", sep = sep, end = end, flush = flush)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class CommandRegistry:
    """Name → handler registry with help, completion, and dispatch."""

    def __init__(self) -> None:
        self._commands: Dict[str, CommandInfo] = {}

    # -- registration --------------------------------------------------------

    def register(
        self,
        name: str,
        handler: Callable,
        help_text: str,
        usage: str = "",
        category: str = "General",
        completions: Optional[Callable[[], List[str]]] = None,
    ) -> None:
        """Register a new command (overwrites any existing command with the
        same name)."""
        self._commands[name.lower()] = CommandInfo(
            name=name.lower(),
            handler=handler,
            help_text=help_text,
            usage=usage,
            category=category,
            completions=completions,
        )

    # -- look‑up -------------------------------------------------------------

    def has_command(self, name: str) -> bool:
        return name.lower() in self._commands

    def get_command(self, name: str) -> Optional[CommandInfo]:
        return self._commands.get(name.lower())

    def command_names(self) -> List[str]:
        """Sorted list of all registered command names."""
        return sorted(self._commands.keys())

    def commands_by_category(self) -> Dict[str, List[CommandInfo]]:
        """Group commands by their category (for help display)."""
        categories: Dict[str, List[CommandInfo]] = {}
        for cmd in self._commands.values():
            categories.setdefault(cmd.category, []).append(cmd)
        for cmds in categories.values():
            cmds.sort(key=lambda c: c.name)
        return categories

    # -- execution -----------------------------------------------------------

    async def execute(self, name: str, args_str: str, app: Application) -> None:
        """Look up *name* and invoke its handler with a fresh context."""
        cmd = self.get_command(name)
        if cmd is None:
            app.shell.print_local(
                f"Unknown command: {name}. Type 'help' for a list.", style="error"
            )
            return

        ctx = CommandContext(app)
        try:
            await cmd.handler(args_str, ctx)
        except ConnectionError as exc:
            app.shell.print_local(f"Connection error: {exc}", style="error")
        except Exception as exc:
            app.shell.print_local(f"Command '{name}' failed: {exc}", style="error")
