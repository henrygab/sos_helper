# Overview

## How to Run

```bash
# Create a virtual environment
python3 -m venv venv
# Load that virtual env
source ./venv/bin/activate
# Install dependencies into the virtual env
pip install -r requirements
# Run it!
python main.py          # or: python -m serial_console
```

## How to extend

Add a new async handler, register it via registry.register(...).
Look at existing handlers for examples.

## Issues

Exiting using Ctrl-C may leave the Sword of Secrets in
a state where it's still transferring data.

Use `send REBOOT` until communication is restored.

## Project Structure

Subsystem        | File                 | Role
-----------------|----------------------|---------
SerialManager    | `serial_manager.py`    | serial_asyncio streams, dedicated reader task for zero-loss capture, response_collector() context manager for commands, automatic reconnect loop
LogManager       | `logging_subsystem.py` | Fan-out to pluggable handlers — FileLogHandler, MemoryLogHandler, CallbackLogHandler; per-direction filtering for separate TX/RX or unified logs
CommandRegistry  | `command_registry.py`  | Name → async handler mapping; CommandContext gives handlers a decoupled API to serial, logging, and shell
InteractiveShell | `shell.py`             | prompt_toolkit PromptSession with patch_stdout() so the serial reader can print live data above the editing line; history, tab completion, ANSI-coloured local output

