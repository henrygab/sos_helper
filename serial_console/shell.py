"""
prompt_toolkit‑based interactive shell with live serial‑output streaming.

Design decisions
~~~~~~~~~~~~~~~~
* **prompt_toolkit** provides readline‑quality editing (history, tab
  completion, multi‑line cursor movement) with full asyncio support.
* ``patch_stdout()`` intercepts all ``sys.stdout`` writes while a prompt is
  displayed and renders them *above* the editing line.  This is the mechanism
  that lets the serial reader task print incoming data without corrupting the
  prompt.
* The prompt is **dynamic**: it shows ``[port]`` when connected and
  ``[disconnected]`` otherwise.  Colour is applied via prompt_toolkit's HTML
  markup, which works on all supported platforms.
* **Local messages** (errors, status, help) are printed with ANSI colour codes
  for easy visual separation from raw serial output.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from contextlib import contextmanager
if TYPE_CHECKING:
    from .app import Application


# ---------------------------------------------------------------------------
# ANSI colour helpers for local (non‑serial) output
# ---------------------------------------------------------------------------

_STYLES = {
    "error":   "", # "\033[91m",   # bright red
    "success": "", # "\033[92m",   # bright green
    "info":    "", # "\033[96m",   # bright cyan
    "warning": "", # "\033[93m",   # bright yellow
    "status":  "", # "\033[95m",   # bright magenta
}
_RESET = "" # "\033[0m"


# ---------------------------------------------------------------------------
# Tab completer
# ---------------------------------------------------------------------------

class CommandCompleter(Completer):
    """Provide tab completions for command names and, where available, their
    arguments."""

    def __init__(self, app: Application) -> None:
        self._app = app

    def get_completions(self, document, complete_event):  # type: ignore[override]
        text = document.text_before_cursor
        words = text.split()

        if len(words) == 0 or (len(words) == 1 and not text.endswith(" ")):
            # --- complete the command name ----------------------------------
            prefix = words[0].lower() if words else ""
            for name in self._app.command_registry.command_names():
                if name.startswith(prefix):
                    yield Completion(name, start_position=-len(prefix))
        else:
            # --- complete arguments (delegate to the command) ---------------
            cmd_name = words[0].lower()
            cmd = self._app.command_registry.get_command(cmd_name)
            if cmd is not None and cmd.completions is not None:
                try:
                    options = cmd.completions()
                except Exception:
                    return
                partial = words[-1] if not text.endswith(" ") else ""
                for option in options:
                    if option.lower().startswith(partial.lower()):
                        yield Completion(option, start_position=-len(partial))


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------

class InteractiveShell:
    """Line‑oriented shell that multiplexes user input with live serial
    output."""

    def __init__(self, app: Application) -> None:
        self._app = app
        self._session: Optional[PromptSession[str]] = None
        self._running: bool = False
        self._display_serial: bool = True # this toggles on/off with connected state
        self._suppress_serial_output_count: int = 0

        # Register ourselves as a serial‑data observer so that RX bytes are
        # printed to the terminal in real time.
        self._app.serial_manager.add_rx_callback(self._on_serial_rx)
        self._app.serial_manager.add_status_callback(self._on_status_change)

    # -- lifecycle -----------------------------------------------------------

    @contextmanager
    def suppress_serial_output(self):
        """Temporarily suppress serial output from being printed to the terminal.

        This is useful when running a command that needs to print local status
        messages without interleaving raw serial data.  The suppression is
        temporary and only applies while the context manager is active.  Serial
        data received during this time is DISCARDED, not buffered.
        """
        self._suppress_serial_output_count += 1
        try:
            yield
        finally:
            self._suppress_serial_output_count -= 1

    async def run(self) -> None:
        """Enter the interactive prompt loop.  Blocks until the user quits."""
        self._session = self._create_session()
        self._running = True

        self.print_local("Serial Console v0.1.0", style="info")
        self.print_local("Type 'help' for available commands.\n", style="info")

        # patch_stdout keeps the prompt visually correct while background
        # tasks (serial reader) write to stdout.
        with patch_stdout():
            while self._running:
                try:
                    line = await self._session.prompt_async(
                        self._get_prompt,  # callable → re‑evaluated each time
                    )
                    await self._handle_input(line)
                except EOFError:
                    # Ctrl‑D → quit
                    self._running = False
                    break
                except KeyboardInterrupt:
                    # Ctrl‑C → discard current line, stay in the loop
                    continue

    def stop(self) -> None:
        """Signal the shell to exit after the current prompt returns."""
        self._running = False
        self._display_serial = False

    # -- output helpers ------------------------------------------------------
    def print_local(
            self,
            *values: object,
            style: str = "",
            sep: str | None = " ",
            end: str | None = "\n",
            flush: bool = False
            ) -> None:
        """Print a framework message with optional ANSI colour.

        This is for *local* messages only (help, errors, status).  Serial
        output is printed raw by :meth:`_on_serial_rx`.
        """
        if style in _STYLES:
            print(f"{_STYLES[style]}", end = "")
            print(*values, sep = sep, end = "")
            print(f"{_RESET}", end = end, flush = flush)
        else:
            print(*values, sep = sep, end = end, flush = flush)

    # -- internals -----------------------------------------------------------

    def _create_session(self) -> PromptSession[str]:
        style = Style.from_dict(
            {
                "prompt.port": "#00aa00 bold",
                "prompt.disconnected": "#aa0000 bold",
                "prompt.arrow": "#00aaaa",
            }
        )
        return PromptSession(
            history=FileHistory(".serial_console_history"),
            completer=CommandCompleter(self._app),
            style=style,
            complete_while_typing=False,
            enable_history_search=True,
        )

    def _get_prompt(self) -> HTML:
        """Build the dynamic prompt text (called before every input line)."""
        if self._app.serial_manager.connected:
            port = self._app.serial_manager.port
            return HTML(
                f'<style fg="ansigreen" bold="true">[{port}]</style>'
                f' <style fg="ansicyan">\u25b8</style> '
            )
        return HTML(
            '<style fg="ansired" bold="true">[disconnected]</style>'
            ' <style fg="ansicyan">\u25b8</style> '
        )

    async def _handle_input(self, line: str) -> None:
        """Route a line of user input to a command or to the serial port."""
        line = line.strip()
        if not line:
            return

        parts = line.split(None, 1)
        cmd_name = parts[0].lower()
        args_str = parts[1] if len(parts) > 1 else ""

        if self._app.command_registry.has_command(cmd_name):
            await self._app.command_registry.execute(cmd_name, args_str, self._app)
        else:
            self.print_local("Unknown command.", style="error")

    # -- serial callbacks (run on the reader task) ---------------------------

    def _on_serial_rx(self, data: bytes) -> None:
        """Display incoming serial data verbatim (no formatting)."""
        if self._display_serial and (self._suppress_serial_output_count == 0):
            # sys.stdout is patched by patch_stdout() — writes appear above
            # the editing prompt automatically.
            sys.stdout.write(data.decode(encoding="latin-1", errors="ignore"))
            sys.stdout.flush()

    def _on_status_change(self, event: str, detail: str) -> None:
        """Print a coloured status line when the connection state changes."""
        messages = {
            "connected":    ("success", f"\u2713 Connected: {detail}"),
            "disconnected": ("status",  f"\u2717 Disconnected: {detail}"),
            "lost":         ("warning", f"\u26a0 Connection lost: {detail}"),
            "reconnected":  ("success", f"\u2713 Reconnected: {detail}"),
        }
        style, text = messages.get(event, ("info", f"{event}: {detail}"))
        self.print_local(text, style=style)
        if event == "lost" and self._app.serial_manager.auto_reconnect:
            self.print_local(
                "  Auto‑reconnect enabled — waiting for device…", style="info"
            )
