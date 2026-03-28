"""
Serial‑port manager with async I/O, auto‑reconnect, and zero‑loss buffering.

Design decisions
~~~~~~~~~~~~~~~~
* **serial_asyncio** provides native asyncio ``StreamReader`` / ``StreamWriter``
  on top of pySerial.  This avoids thread pools and keeps everything on one
  event loop.
* A dedicated **reader task** continuously drains the OS serial buffer so that
  no data is ever lost — even while the user is typing or a command is running.
* **Callbacks** (synchronous, on the reader task) deliver every received byte
  to the display layer and the logging subsystem with minimal latency.
* A **ResponseCollector** (obtained via the ``response_collector()`` async
  context manager) lets commands capture serial responses without interfering
  with display or logging.  Data is dispatched to *both* callbacks and the
  collector simultaneously.
* **Auto‑reconnect** polls for the port at a configurable interval after
  detecting a disconnection.  It is enabled automatically on ``connect()`` and
  disabled on explicit ``disconnect()``.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable, List, Optional

try:
    import serial
    import serial.tools.list_ports
except ImportError as exc:
    raise ImportError(
        "pyserial is required (pip install pyserial); "
        "failed to import serial.tools.list_ports."
    ) from exc


# ---------------------------------------------------------------------------
# ResponseCollector — temporary tap into the RX data stream
# ---------------------------------------------------------------------------

class ResponseCollector:
    """Capture incoming serial data for a command's use.

    Created by :meth:`SerialManager.response_collector`.  Data is *also*
    dispatched to display/logging callbacks — the collector receives a
    **copy**, not an exclusive claim.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer: bytearray = bytearray()

    # -- called by the reader task ----------------------------------------

    def feed(self, data: bytes) -> None:
        """Enqueue a chunk of received data (called by the reader task)."""
        self._queue.put_nowait(data)

    # -- public API for command authors -----------------------------------

    async def read_until_anyof(self, patterns: list[bytes], timeout: float = 5.0) -> tuple[int, bytes]:
        """Read until one of the listed *patterns* appears in the stream or *timeout* expires.
        returns tuple<-1,buffer> if the timeout expired without finding any of the patterns.
        returns tuple<index,buffer> if one of the patterns was found, where index is the index of the pattern in the input list.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                self._buffer.extend(chunk)
                # check if the buffer now contains any of the provided patterns, in order
                for i, pattern in enumerate(patterns):
                    idx = self._buffer.find(pattern)
                    if idx >= 0:
                        end = idx + len(pattern)
                        result = bytes(self._buffer[:end])
                        self._buffer = self._buffer[end:]
                        return (i, result)
            except asyncio.TimeoutError:
                break
        result = bytes(self._buffer)
        self._buffer.clear()
        return (-1, result)

    async def read(self, timeout: float = 5.0) -> bytes:
        """Accumulate all data that arrives within *timeout* seconds."""
        return (await self.read_until_anyof([], timeout=timeout))[1]

    async def readline(self, timeout: float = 5.0) -> str:
        """Read until a newline (``\\n``) is received or *timeout* expires.

        Returns the decoded, stripped line — or whatever partial data was
        collected before the deadline.
        """
        tmp = await self.read_until_anyof([ b"\n" ], timeout=timeout)
        line = tmp[1]
        return line.decode(encoding="latin-1", errors="ignore").strip()

    async def read_until(self, pattern: bytes, timeout: float = 5.0) -> bytes:
        """Read until *pattern* appears in the stream or *timeout* expires."""
        return (await self.read_until_anyof([pattern], timeout=timeout))[1]

    async def read_chunk(self, timeout: float = 1.0) -> bytes:
        """Return the next available chunk (one ``read()`` worth of data)."""
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return b""

    def drain(self) -> bytes:
        """Return (and clear) all buffered data without blocking."""
        while not self._queue.empty():
            try:
                self._buffer.extend(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        result = bytes(self._buffer)
        self._buffer.clear()
        return result


# ---------------------------------------------------------------------------
# SerialManager
# ---------------------------------------------------------------------------

class SerialManager:
    """Manage a single serial‑port connection over asyncio.

    Public surface:

    * ``connect`` / ``disconnect`` — lifecycle.
    * ``write`` / ``write_line`` — transmit data.
    * ``response_collector()`` — context manager for capturing replies.
    * ``add_rx_callback`` / ``add_tx_callback`` — observe data flow.
    * ``add_status_callback`` — observe connect/disconnect events.
    * ``list_ports()`` — class helper to enumerate OS serial ports.
    """

    def __init__(self) -> None:
        # -- connection state ------------------------------------------------
        self._port: Optional[str] = None
        self._baudrate: int = 115200
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected: bool = False

        # -- task management -------------------------------------------------
        self._running: bool = False  # True while we *want* to be active
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._reconnect_task: Optional[asyncio.Task[None]] = None

        # -- callbacks -------------------------------------------------------
        self._rx_callbacks: List[Callable[[bytes], None]] = []
        self._tx_callbacks: List[Callable[[bytes], None]] = []
        self._status_callbacks: List[Callable[[str, str], None]] = []

        # -- response collection ---------------------------------------------
        self._active_collector: Optional[ResponseCollector] = None

        # -- configuration ---------------------------------------------------
        self.auto_reconnect: bool = True
        self.reconnect_interval: float = 2.0
        self.line_ending: bytes = b"\n"

        # -- TX throttling (work-around for slow device UART) ----------------
        # When > 0, insert this many seconds of delay between each byte
        # transmitted.  Set to 0 to disable (full-speed burst writes).
        # A value of ~0.001 (1 ms) is a safe starting point for devices
        # whose UART FIFO overflows at sustained 115 200 baud.
        self.tx_byte_delay: float = 0.001

    # -- properties ----------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def port(self) -> Optional[str]:
        return self._port

    @property
    def baudrate(self) -> int:
        return self._baudrate

    @baudrate.setter
    def baudrate(self, value: int) -> None:
        self._baudrate = value

    # -- callback registration -----------------------------------------------

    def add_rx_callback(self, callback: Callable[[bytes], None]) -> None:
        """Register a callback invoked on every received byte chunk."""
        self._rx_callbacks.append(callback)

    def remove_rx_callback(self, callback: Callable[[bytes], None]) -> None:
        self._rx_callbacks.remove(callback)

    def add_tx_callback(self, callback: Callable[[bytes], None]) -> None:
        """Register a callback invoked on every transmitted byte chunk."""
        self._tx_callbacks.append(callback)

    def remove_tx_callback(self, callback: Callable[[bytes], None]) -> None:
        self._tx_callbacks.remove(callback)

    def add_status_callback(self, callback: Callable[[str, str], None]) -> None:
        """Register a callback for connection status changes.

        The callback signature is ``callback(event, detail)`` where *event* is
        one of ``"connected"``, ``"disconnected"``, ``"lost"``, or
        ``"reconnected"``.
        """
        self._status_callbacks.append(callback)

    # -- connect / disconnect ------------------------------------------------

    async def connect(self, port: str, baudrate: int = 115200) -> None:
        """Open *port* and start the background reader.

        Raises :class:`ConnectionError` if the port cannot be opened.
        """
        if self._connected:
            await self.disconnect()

        self._port = port
        self._baudrate = baudrate
        self._running = True
        self.auto_reconnect = True

        await self._open_port()
        self._notify_status("connected", f"{self._port} @ {self._baudrate}")

    async def disconnect(self) -> None:
        """Close the serial port and cancel all background tasks.

        Also disables auto‑reconnect (since this is an explicit user action).
        """
        self._running = False
        self.auto_reconnect = False

        # Cancel the reconnect poller if it is running.
        if self._reconnect_task is not None and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None

        # Cancel the reader task.
        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        # Close the transport.
        self._close_transport()

        if self._connected:
            self._connected = False
            self._notify_status("disconnected", self._port or "")
        else:
            self._connected = False

    # -- write ---------------------------------------------------------------

    async def write(self, data: bytes) -> None:
        """Write raw bytes to the serial port.

        When :attr:`tx_byte_delay` is positive, bytes are sent one at a
        time with an inter-byte pause so that slow devices can keep up.

        Raises :class:`ConnectionError` on failure.
        """
        if not self._connected or self._writer is None:
            raise ConnectionError("Not connected to a serial port")
        try:
            if self.tx_byte_delay > 0:
                # Drip-feed one byte at a time to avoid overflowing the
                # device's UART receive FIFO.
                for i in range(len(data)):
                    self._writer.write(data[i:i+1])
                    await self._writer.drain()
                    if i < len(data) - 1:
                        await asyncio.sleep(self.tx_byte_delay)
            else:
                self._writer.write(data)
                await self._writer.drain()
            self._dispatch_tx(data)
        except (serial.SerialException, OSError) as exc:
            await self._handle_disconnect(str(exc))
            raise ConnectionError(f"Write failed: {exc}") from exc

    async def write_line(self, line: str, encoding: str = "ascii") -> None:
        """Encode *line*, append the configured line ending, and transmit."""
        data = line.encode(encoding, errors="replace") + self.line_ending
        await self.write(data)

    # -- response collection -------------------------------------------------

    @asynccontextmanager
    async def response_collector(self) -> AsyncIterator[ResponseCollector]:
        """Yield a :class:`ResponseCollector` that receives a copy of all
        incoming serial data while the context is active.

        Usage::

            async with serial_mgr.response_collector() as collector:
                await serial_mgr.write_line("AT")
                line = await collector.readline(timeout=3.0)
        """
        collector = ResponseCollector()
        self._active_collector = collector
        try:
            yield collector
        finally:
            self._active_collector = None

    # -- port enumeration (static helper) ------------------------------------

    @staticmethod
    def list_ports() -> list[dict[str, str]]:
        """Return a list of available serial ports as dicts."""
        return [
            {
                "device": p.device,
                "description": p.description,
                "hwid": p.hwid,
            }
            for p in serial.tools.list_ports.comports()
        ]

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    async def _open_port(self) -> None:
        """Open the serial transport and start the reader task.

        Raises :class:`ConnectionError` on failure.
        """
        import serial_asyncio  # deferred import — only needed when connecting

        try:
            self._reader, self._writer = await serial_asyncio.open_serial_connection(
                url=self._port,
                baudrate=self._baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )
        except (serial.SerialException, OSError) as exc:
            self._connected = False
            raise ConnectionError(f"Cannot open {self._port}: {exc}") from exc

        self._connected = True
        self._reader_task = asyncio.create_task(
            self._reader_loop(), name="serial-reader"
        )

    def _close_transport(self) -> None:
        """Close writer/reader without sending status notifications."""
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
        self._reader = None

    # -- reader task ---------------------------------------------------------

    async def _reader_loop(self) -> None:
        """Continuously read from the serial port and dispatch data.

        Exits when the connection is lost or the task is cancelled.
        """
        while self._running and self._connected:
            try:
                if self._reader is None:
                    await asyncio.sleep(0.05)
                    continue

                data = await self._reader.read(4096)
                if not data:
                    # EOF — the device was probably unplugged.
                    await self._handle_disconnect("Device returned EOF")
                    return

                self._dispatch_rx(data)

            except asyncio.CancelledError:
                return
            except (serial.SerialException, OSError) as exc:
                if self._running:
                    await self._handle_disconnect(str(exc))
                return
            except Exception as exc:  # pragma: no cover — safety net
                if self._running:
                    await self._handle_disconnect(f"Unexpected: {exc}")
                return

    # -- dispatchers ---------------------------------------------------------

    def _dispatch_rx(self, data: bytes) -> None:
        for cb in self._rx_callbacks:
            try:
                cb(data)
            except Exception:
                pass
        if self._active_collector is not None:
            self._active_collector.feed(data)

    def _dispatch_tx(self, data: bytes) -> None:
        for cb in self._tx_callbacks:
            try:
                cb(data)
            except Exception:
                pass

    # -- disconnect / reconnect ----------------------------------------------

    async def _handle_disconnect(self, reason: str = "") -> None:
        """React to an unexpected connection loss."""
        was_connected = self._connected
        self._connected = False
        self._close_transport()

        if was_connected:
            self._notify_status("lost", reason)

        if self.auto_reconnect and self._port:
            self._start_reconnect()

    def _start_reconnect(self) -> None:
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return  # already running
        self._reconnect_task = asyncio.create_task(
            self._reconnect_loop(), name="serial-reconnect"
        )

    async def _reconnect_loop(self) -> None:
        """Poll for the port and attempt to reopen it."""
        while self._running and self.auto_reconnect:
            await asyncio.sleep(self.reconnect_interval)

            if self._connected:
                return  # someone else reconnected

            if not self._port_available():
                continue

            try:
                await self._open_port()
                self._notify_status("reconnected", f"{self._port} @ {self._baudrate}")
                return
            except ConnectionError:
                continue
            except asyncio.CancelledError:
                return

    def _port_available(self) -> bool:
        """Return ``True`` if the configured port is present on the OS."""
        if not self._port:
            return False
        available = {p.device for p in serial.tools.list_ports.comports()}
        return self._port in available

    # -- status notifications ------------------------------------------------

    def _notify_status(self, event: str, detail: str = "") -> None:
        for cb in self._status_callbacks:
            try:
                cb(event, detail)
            except Exception:
                pass
