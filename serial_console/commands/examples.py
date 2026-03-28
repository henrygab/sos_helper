"""
Example commands demonstrating the command framework.

Three commands are provided, one for each common interaction pattern:

1. **send**    — simple TX: fire‑and‑forget a text line.
2. **query**   — TX/RX interaction: send a line, capture the response.
3. **monitor** — long‑running operation: collect serial data for *n* seconds.
"""

from __future__ import annotations

import asyncio

from ..command_registry import CommandContext, CommandRegistry


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_example_commands(registry: CommandRegistry) -> None:
    """Populate *registry* with the three example commands."""
    registry.register(
        "send", cmd_send,
        "Send a text string to the serial port",
        usage="send <text>",
        category="Examples",
    )


# ---------------------------------------------------------------------------
# 1. Simple TX
# ---------------------------------------------------------------------------

async def cmd_send(args: str, ctx: CommandContext) -> None:
    """Send a text string to the serial port.

    This is the simplest possible command: it encodes the user's text, appends
    the configured line ending, and writes it to the port.  No response is
    expected or captured.
    """
    text = args.strip()
    if not text:
        ctx.print_error("Usage: send <text>")
        return
    if not ctx.serial.connected:
        ctx.print_error("Not connected.")
        return

    await ctx.serial.write_line(text)
    ctx.print_info(f"Sent: {text}")


# ---------------------------------------------------------------------------
# 2. TX/RX interaction
# ---------------------------------------------------------------------------

async def cmd_query(args: str, ctx: CommandContext) -> None:
    """Send a command and wait for a single‑line response.

    Demonstrates the :meth:`response_collector` context manager.  While the
    collector is active, incoming serial data is *both* printed to the terminal
    (via the normal RX callback) **and** buffered inside the collector so that
    this handler can inspect it programmatically.

    Usage::

        query AT                → send "AT", wait up to 5 s for a line
        query AT+VER 10         → send "AT+VER", wait up to 10 s
    """
    parts = args.strip().split()
    if not parts:
        ctx.print_error("Usage: query <text> [timeout_seconds]")
        return
    if not ctx.serial.connected:
        ctx.print_error("Not connected.")
        return

    # The last token is treated as a timeout if it parses as a float.
    timeout = 5.0
    text_parts = parts
    if len(parts) > 1:
        try:
            timeout = float(parts[-1])
            text_parts = parts[:-1]
        except ValueError:
            pass  # not a number → it's part of the command text

    text = " ".join(text_parts)
    ctx.print_info(f"Querying: {text}  (timeout {timeout:.1f} s)")

    async with ctx.serial.response_collector() as collector:
        await ctx.serial.write_line(text)
        response = await collector.readline(timeout=timeout)

    if response:
        ctx.print_success(f"Response: {response}")
    else:
        ctx.print_warning("No response received (timeout).")


# ---------------------------------------------------------------------------
# 3. Long‑running operation
# ---------------------------------------------------------------------------

async def cmd_monitor(args: str, ctx: CommandContext) -> None:
    """Monitor serial output for a fixed duration.

    This demonstrates a command that occupies the console for an extended
    period.  Serial data continues to stream live to the terminal (via the
    normal RX display callback); the collector simultaneously captures it so
    that we can report statistics when the monitoring window closes.

    Usage::

        monitor 30        → watch serial output for 30 seconds
    """
    duration_str = args.strip()
    if not duration_str:
        ctx.print_error("Usage: monitor <seconds>")
        return

    try:
        duration = float(duration_str)
    except ValueError:
        ctx.print_error(f"Invalid duration: {duration_str}")
        return

    if duration <= 0 or duration > 3600:
        ctx.print_error("Duration must be between 0 and 3600 seconds.")
        return

    if not ctx.serial.connected:
        ctx.print_error("Not connected.")
        return

    ctx.print_info(
        f"Monitoring for {duration:.1f} s — serial output streams live below."
    )

    byte_count = 0
    line_count = 0

    async with ctx.serial.response_collector() as collector:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + duration
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            chunk = await collector.read_chunk(timeout=min(remaining, 1.0))
            if chunk:
                byte_count += len(chunk)
                line_count += chunk.count(b"\n")

    ctx.print_info(f"\nMonitoring complete.")
    ctx.print_info(f"  Duration : {duration:.1f} s")
    ctx.print_info(f"  Received : {byte_count} bytes, ~{line_count} lines")
