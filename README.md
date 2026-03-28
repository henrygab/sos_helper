# Serial Console

An interactive, line‑oriented serial‑port console specifically designed
to simplify programmatic interaction with the Sword of Secrets
hardware CTF.

Built on **asyncio**, **pySerial**, and **prompt\_toolkit**.

---

## Features

| Area | Details |
|------|---------|
| **Interactive shell**  | prompt\_toolkit – command history, tab completion, colored local output |
| **Live serial output** | Streams to the terminal while you type the next command |
| **Command framework**  | Extensible registry – each command is an `async` Python function |
| **Serial manager**     | Auto‑reconnect, zero‑loss buffering, asyncio reader/writer |
| **Logging**            | Pluggable handlers – file, in‑memory buffer, user callback; separate or unified TX/RX |
| **Cross‑platform**     | Windows, Linux, macOS, WSL |

---

## Quick Start

### 1. Install dependencies

```bash
# Create a virtual environment
python3 -m venv venv
# Load that virtual env
source ./venv/bin/activate
# Install dependencies into the virtual env
pip install -r requirements
```

### 2. Run

```bash
# If not still in the virtual environment...
source ./venv/bin/activate
# Option A – run the entry‑point script directly
python main.py
# Option B – run as a Python module
# python -m serial_console
```

### 3. Connect to a device

```text
[disconnected] ▸ ports
  /dev/ttyUSB0         USB Serial Device

[disconnected] ▸ connect /dev/ttyUSB0 115200
✓ Connected: /dev/ttyUSB0 @ 115200

[/dev/ttyUSB0] ▸
```

---

## Built‑in Commands

| Command                     | Description                                  |
|-----------------------------|----------------------------------------------|
| `help [cmd]`                | Show all commands or detailed help for *cmd* |
| `quit` / `exit`             | Exit the console                             |
| `connect <port> [baud]`     | Open a serial port (default 115 200)         |
| `disconnect`                | Close the serial port                        |
| `ports`                     | List available serial ports                  |
| `status`                    | Show connection info                         |
| `baudrate <rate>`           | Change baud rate (reconnects if connected)   |
| `log start <file> [tx\|rx]` | Start logging to a file                      |
| `log stop`                  | Stop all log handlers                        |
| `log status`                | Show active log handlers                     |

### Base Sword of Secrets Commands

| Command | Description |
|---------|-------------|
| `send <text>`                        | Simple TX – send a line to the device |
| `read_flash <address> [length=0x40]` | Read SPI flash on Sword               |
| `write_flash <address> <hex data>`   | Write SPI flash on Sword              |
| `erase_flash_4k <address>`           | Erase 4k of the SPI flash on Sword    |
| `dump_flash`                         | Prints non-empty areas of SPI flash   |
---


