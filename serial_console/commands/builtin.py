"""
Built‑in commands — always‑available housekeeping commands.

These cover connection management, port enumeration, logging configuration,
and the help / quit essentials.
"""

from __future__ import annotations

from typing import List

import serial.tools.list_ports

from ..command_registry import CommandContext, CommandRegistry
from ..logging_subsystem import Direction, FileLogHandler


# ---------------------------------------------------------------------------
# Registration entry point (called by Application.__init__)
# ---------------------------------------------------------------------------

def register_builtin_commands(registry: CommandRegistry) -> None:
    """Populate *registry* with all built‑in commands."""
    registry.register(
        "help", cmd_help,
        "Show available commands or detailed help for one command",
        usage="help [command]", category="Built‑in",
    )
    registry.register(
        "quit", cmd_quit,
        "Exit the console",
        usage="quit", category="Built‑in",
    )
    registry.register(
        "q", cmd_quit,
        "Exit the console (alias for quit)",
        usage="quit", category="Built‑in",
    )
    registry.register(
        "x", cmd_quit,
        "Exit the console (alias for quit)",
        usage="quit", category="Built‑in",
    )
    registry.register(
        "exit", cmd_quit,
        "Exit the console (alias for quit)",
        usage="exit", category="Built‑in",
    )
    registry.register(
        "connect", cmd_connect,
        "Connect to a serial port",
        usage="connect <port> [baudrate]", category="Serial",
        completions=_list_port_names,
    )
    registry.register(
        "disconnect", cmd_disconnect,
        "Disconnect from the serial port",
        usage="disconnect", category="Serial",
    )
    registry.register(
        "ports", cmd_ports,
        "List available serial ports",
        usage="ports", category="Serial",
    )
    registry.register(
        "status", cmd_status,
        "Show connection status and settings",
        usage="status", category="Serial",
    )
    registry.register(
        "baudrate", cmd_baudrate,
        "View or change the baud rate (reconnects if already connected)",
        usage="baudrate [rate]", category="Serial",
    )
    registry.register(
        "log", cmd_log,
        "Configure the logging subsystem",
        usage="log <start|stop|status> [options]", category="Logging",
    )


# ---------------------------------------------------------------------------
# Completion helper
# ---------------------------------------------------------------------------

def _list_port_names() -> List[str]:
    """Return device names of all available serial ports (for tab completion)."""
    return [p.device for p in serial.tools.list_ports.comports()]


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def cmd_help(args: str, ctx: CommandContext) -> None:
    """Display a summary of all commands, or detailed help for one command."""
    target = args.strip()

    if target:
        cmd = ctx.registry.get_command(target)
        if cmd is None:
            ctx.print_error(f"Unknown command: {target}")
            return
        ctx.print_info(f"  {cmd.name} — {cmd.help_text}")
        if cmd.usage:
            ctx.print_info(f"  Usage: {cmd.usage}")
        return

    ctx.print_info("\n  Available Commands:")
    ctx.print_info("  " + "\u2500" * 50)

    for category, commands in ctx.registry.commands_by_category().items():
        ctx.print_info(f"\n  [{category}]")
        for cmd in commands:
            padding = " " * max(1, 16 - len(cmd.name))
            ctx.print_info(f"    {cmd.name}{padding}{cmd.help_text}")

    ctx.print_info("")
    ctx.print_info("  Type 'help <command>' for detailed usage.\n")


async def cmd_quit(args: str, ctx: CommandContext) -> None:
    """Signal the shell to exit."""
    ctx.print_info("Exiting...")
    ctx.shell.stop()


async def cmd_connect(args: str, ctx: CommandContext) -> None:
    """Open a serial port."""
    parts = args.strip().split()
    if not parts:
        ctx.print_error("Usage: connect <port> [baudrate]")
        ctx.print_info("Available ports:")
        for p in ctx.serial.list_ports():
            ctx.print(f"  {p['device']:20s} {p['description']}")
        return

    port = parts[0]
    baudrate = 115200
    if len(parts) > 1:
        try:
            baudrate = int(parts[1])
        except ValueError:
            ctx.print_error(f"Invalid baud rate: {parts[1]}")
            return

    ctx.print_info(f"Connecting to {port} at {baudrate} baud…")
    try:
        await ctx.serial.connect(port, baudrate)
    except ConnectionError as exc:
        ctx.print_error(str(exc))


async def cmd_disconnect(args: str, ctx: CommandContext) -> None:
    """Close the serial port."""
    if not ctx.serial.connected:
        ctx.print_info("Not connected.")
        return
    await ctx.serial.disconnect()


async def cmd_ports(args: str, ctx: CommandContext) -> None:
    """Enumerate available serial ports."""
    ports = ctx.serial.list_ports()
    if not ports:
        ctx.print_info("No serial ports found.")
        return

    ctx.print_info("\n  Available Serial Ports:")
    for p in ports:
        active = (
            " \u25c4 connected"
            if ctx.serial.connected and ctx.serial.port == p["device"]
            else ""
        )
        ctx.print(f"    {p['device']:20s} {p['description']}{active}")
    ctx.print("")


async def cmd_status(args: str, ctx: CommandContext) -> None:
    """Print connection status and configuration."""
    if ctx.serial.connected:
        ctx.print_success(
            f"Connected: {ctx.serial.port} @ {ctx.serial.baudrate} baud"
        )
        ctx.print_info(
            f"  Auto‑reconnect : {'enabled' if ctx.serial.auto_reconnect else 'disabled'}"
        )
        ctx.print_info(f"  Line ending     : {ctx.serial.line_ending!r}")
    else:
        ctx.print_info("Not connected.")
        if ctx.serial.port:
            ctx.print_info(f"  Last port: {ctx.serial.port}")


async def cmd_baudrate(args: str, ctx: CommandContext) -> None:
    """View or change the baud rate."""
    rate_str = args.strip()
    if not rate_str:
        ctx.print_info(f"Current baud rate: {ctx.serial.baudrate}")
        ctx.print_info("Usage: baudrate <rate>")
        return

    try:
        rate = int(rate_str)
    except ValueError:
        ctx.print_error(f"Invalid baud rate: {rate_str}")
        return

    if ctx.serial.connected:
        # Reconnect with the new rate.
        port = ctx.serial.port
        assert port is not None
        await ctx.serial.disconnect()
        try:
            await ctx.serial.connect(port, rate)
        except ConnectionError as exc:
            ctx.print_error(str(exc))
    else:
        # Just update the stored value for the next connect.
        ctx.serial.baudrate = rate
        ctx.print_info(f"Baud rate set to {rate} (will apply on next connect)")


async def cmd_log(args: str, ctx: CommandContext) -> None:
    """Configure the logging subsystem (start / stop / status)."""
    parts = args.strip().split()
    if not parts:
        ctx.print_error("Usage: log <start|stop|status> [options]")
        ctx.print_info("  log start <file>            Log TX+RX to file")
        ctx.print_info("  log start <file> tx         Log TX only")
        ctx.print_info("  log start <file> rx         Log RX only")
        ctx.print_info("  log stop                    Remove all log handlers")
        ctx.print_info("  log status                  Show active handlers")
        return

    action = parts[0].lower()

    if action == "start":
        if len(parts) < 2:
            ctx.print_error("Usage: log start <filename> [tx|rx]")
            return
        filename = parts[1]
        directions = None
        if len(parts) > 2:
            d = parts[2].lower()
            if d == "tx":
                directions = {Direction.TX}
            elif d == "rx":
                directions = {Direction.RX}
            else:
                ctx.print_error(f"Unknown direction '{d}'. Use 'tx' or 'rx'.")
                return
        handler = FileLogHandler(filename, directions)
        ctx.log.add_handler(handler)
        label = f" ({parts[2].upper()} only)" if directions else " (TX+RX)"
        ctx.print_success(f"Logging to {filename}{label}")

    elif action == "stop":
        ctx.log.close()
        ctx.print_info("All log handlers removed.")

    elif action == "status":
        handlers = ctx.log.handlers
        if not handlers:
            ctx.print_info("No active log handlers.")
        else:
            ctx.print_info(f"Active log handlers: {len(handlers)}")
            for i, h in enumerate(handlers):
                ctx.print(f"  [{i}] {h!r}")

    else:
        ctx.print_error(f"Unknown log action: {action}")
