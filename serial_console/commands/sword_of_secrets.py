"""
Commands to simplify working through the Sword of Secrets hardware CTF.

Commands include:

1. **send**    — simple TX: fire‑and‑forget a text line.
2. **query**   — TX/RX interaction: send a line, capture the response.
3. **monitor** — long‑running operation: collect serial data for *n* seconds.
"""

from __future__ import annotations

import asyncio
from binascii import Error

from ..command_registry import CommandContext, CommandRegistry
from enum import Enum
from typing import Literal, Optional, Sequence, Tuple, Type, overload, TypeAlias, Protocol

# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_sword_of_secrets_commands(registry: CommandRegistry) -> None:
    """Populate *registry* with the three example commands."""
    registry.register(
        "dump_flash", cmd_dump_all_flash,
        "Dump the full flash contents for manual review. (takes significant time...)",
        usage="dump_flash",
        category="Sword of Secrets",
    )
    registry.register(
        "read_flash", cmd_read_flash,
        "Read flash data from specific area of the connected Sword of Secrets device",
        usage="read_flash <address> [length=0x40]",
        category="Sword of Secrets",
    )
    registry.register(
        "erase_flash_4k", cmd_erase_flash_4k,
        "Erase 4K flash sector of the connected Sword of Secrets device.",
        usage="erase_flash_4k <address>",
        category="Sword of Secrets",
    )
    registry.register(
        "write_flash", cmd_write_flash,
        "Write flash data to the connected Sword of Secrets device",
        usage="write_flash <address> <hex_data>",
        category="Sword of Secrets",
    )

# ---------------------------------------------------------------------------
# Enums and types
# ---------------------------------------------------------------------------

class StatusRegisterType(Enum):
    SR1 = 1
    SR2 = 2
    SR3 = 4
    SR1_and_SR2 = 3 # used to write SR1 and SR2 in one command

class StatusRegisterBase:
    def __init__(self, value: int):
        self._value = value & 0xFF

    @property
    def StatusRegisterType(self) -> StatusRegisterType:
        raise NotImplementedError("Subclasses must implement StatusRegisterType property.")
    @property
    def value(self) -> int:
        return self._value & 0xFF
    @value.setter
    def value(self, new_value: int):
        self._value = new_value & 0xFF
class StatusRegister1(StatusRegisterBase):
    @property
    def StatusRegisterType(self) -> StatusRegisterType:
        return StatusRegisterType.SR1
    @property
    def SRP(self) -> bool:
        return (self.value & 0x80) != 0
    @property
    def SEC(self) -> bool:
        return (self.value & 0x40) != 0    
    @property
    def TB(self) -> bool:
        return (self.value & 0x20) != 0
    @property
    def BP(self) -> int:
        return (self.value >> 2) & 0x7
    @property
    def BP2(self) -> bool:
        return (self.value & 0x10) != 0
    @property
    def BP1(self) -> bool:
        return (self.value & 0x08) != 0
    @property
    def BP0(self) -> bool:
        return (self.value & 0x04) != 0
    @property
    def WEL(self) -> bool:
        return (self.value & 0x02) != 0
    @property
    def BUSY(self) -> bool:
        return (self.value & 0x01) != 0
    # The writable Status Register bits include:
    #   Status Register 1: mask 0b0111'1100: SEC (0x40), TB (0x20), BP[2:0] (0x1C)
    @SEC.setter
    def SEC(self, enabled: bool):
        if enabled:
            self.value |= 0x40
        else:
            self.value &= 0xBF
    @TB.setter
    def TB(self, enabled: bool):
        if enabled:
            self.value |= 0x20
        else:
            self.value &= 0xDF
    @BP.setter
    def BP(self, value: int):
        if value < 0 or value > 7:
            raise ValueError("BP value must be between 0 and 7.")
        self.value = (self.value & 0xE3) | ((value << 2) & 0x1C)
    @BP2.setter
    def BP2(self, enabled: bool):
        if enabled:
            self.value |= 0x10
        else:
            self.value &= 0xEF
    @BP1.setter
    def BP1(self, enabled: bool):
        if enabled:
            self.value |= 0x08
        else:
            self.value &= 0xF7
    @BP0.setter
    def BP0(self, enabled: bool):
        if enabled:
            self.value |= 0x04
        else:
            self.value &= 0xFB
class StatusRegister2(StatusRegisterBase):
    @property
    def StatusRegisterType(self) -> StatusRegisterType:
        return StatusRegisterType.SR2
    @property
    def SUS(self) -> bool:
        return (self.value & 0x80) != 0
    @property
    def CMP(self) -> bool:
        return (self.value & 0x40) != 0
    @property
    def LB(self) -> int:
        return (self.value >> 3) & 0x7
    @property
    def LB3(self) -> bool:
        return (self.value & 0x20) != 0
    @property
    def LB2(self) -> bool:
        return (self.value & 0x10) != 0
    @property
    def LB1(self) -> bool:
        return (self.value & 0x08) != 0
    @property
    def QE(self) -> bool:
        return (self.value & 0x02) != 0
    @property
    def SRL(self) -> bool:
        """SRL is the Status Register Lock bit, used with SR1's SRP bit to define write protection for the status registers"""
        return (self.value & 0x01) != 0
    # The writable Status Register bits include:
    #   Status Register 2: mask 0b0111'1011: CMP (0x40), LB[3:1] (0x38), QE (0x02), SRL (0x01)
    @CMP.setter
    def CMP(self, enabled: bool):
        if enabled:
            self.value |= 0x40
        else:
            self.value &= 0xBF
    @LB.setter
    def LB(self, value: int):
        if value < 0 or value > 7:
            raise ValueError("LB value must be between 0 and 7.")
        if value != 0:
            raise ValueError("LB[3:1] bits in Status Register 2 are OTP bits ... refusing for safety to set those bits to 1.")
        self.value = (self.value & 0xC7) | ((value << 3) & 0x38)
    @LB3.setter
    def LB3(self, enabled: bool):
        if enabled:
            raise ValueError("LB3 bit in Status Register 2 is an OTP bit ... refusing for safety to set that bit to 1.")
        if enabled:
            self.value |= 0x20
        else:
            self.value &= 0xDF
    @LB2.setter
    def LB2(self, enabled: bool):
        if enabled:
            raise ValueError("LB2 bit in Status Register 2 is an OTP bit ... refusing for safety to set that bit to 1.")
        if enabled:
            self.value |= 0x10
        else:
            self.value &= 0xEF
    @LB1.setter
    def LB1(self, enabled: bool):
        if enabled:
            raise ValueError("LB1 bit in Status Register 2 is an OTP bit ... refusing for safety to set that bit to 1.")
        if enabled:
            self.value |= 0x08
        else:
            self.value &= 0xF7
    @QE.setter
    def QE(self, enabled: bool):
        if enabled:
            self.value |= 0x02
        else:
            self.value &= 0xFD
    @SRL.setter
    def SRL(self, enabled: bool):
        if enabled:
            self.value |= 0x01
        else:
            self.value &= 0xFE
class StatusRegister3(StatusRegisterBase):
    @property
    def StatusRegisterType(self) -> StatusRegisterType:
        return StatusRegisterType.SR3

    @property
    def DRV(self) -> int:
        return (self.value >> 5) & 0x3
    # Note: the data sheet is inconsistent on which DRV bits are which
    @property
    def WPS(self) -> bool:
        return (self.value & 0x04) != 0
    @WPS.setter
    def WPS(self, enabled: bool):
        if enabled:
            self.value |= 0x04
        else:
            self.value &= 0xFB

class WriteProtectionType(Enum):
    # First, all the combinations with WPS=0 and CMP=0
    NONE                            = 0b0000000            # WPS = 0, CMP = 0, SEC = x, TB = x, BP[2:0] = 0
    PROTECT_FC0000h_TO_FFFFFFh      = 0b0000001            # WPS = 0, CMP = 0, SEC = 0, TB = 0, BP[2:0] = 1
    PROTECT_F80000h_TO_FFFFFFh      = 0b0000010            # WPS = 0, CMP = 0, SEC = 0, TB = 0, BP[2:0] = 2
    PROTECT_F00000h_TO_FFFFFFh      = 0b0000011            # WPS = 0, CMP = 0, SEC = 0, TB = 0, BP[2:0] = 3
    PROTECT_E00000h_TO_FFFFFFh      = 0b0000100            # WPS = 0, CMP = 0, SEC = 0, TB = 0, BP[2:0] = 4
    PROTECT_C00000h_TO_FFFFFFh      = 0b0000101            # WPS = 0, CMP = 0, SEC = 0, TB = 0, BP[2:0] = 5
    PROTECT_800000h_TO_FFFFFFh      = 0b0000110            # WPS = 0, CMP = 0, SEC = 0, TB = 0, BP[2:0] = 6
    PROTECT_ALL                     = 0b0000111            # WPS = 0, CMP = 0, SEC = 0, TB = 0, BP[2:0] = 7
    NONE_alt1                       = 0b0001000            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 0
    PROTECT_000000h_TO_03FFFFh      = 0b0001001            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 1
    PROTECT_000000h_TO_07FFFFh      = 0b0001010            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 1
    PROTECT_000000h_TO_0FFFFFh      = 0b0001011            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 1
    PROTECT_000000h_TO_1FFFFFh      = 0b0001100            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 1
    PROTECT_000000h_TO_3FFFFFh      = 0b0001101            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 1
    PROTECT_000000h_TO_7FFFFFh      = 0b0001110            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 1
    PROTECT_ALL_alt1                = 0b0001111            # WPS = 0, CMP = 0, SEC = 0, TB = 1, BP[2:0] = 1
    NONE_alt2                       = 0b0010000            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 0
    PROTECT_FFF000h_TO_FFFFFFh      = 0b0010001            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 1
    PROTECT_FFE000h_TO_FFFFFFh      = 0b0010010            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 2
    PROTECT_FFC000h_TO_FFFFFFh      = 0b0010011            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 3
    PROTECT_FF8000h_TO_FFFFFFh      = 0b0010100            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 4
    PROTECT_FF8000h_TO_FFFFFFh_alt1 = 0b0010101            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 5
    #                                 0b0010110            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 6 - not a valid protection range
    PROTECT_ALL_alt2                = 0b0010111            # WPS = 0, CMP = 0, SEC = 1, TB = 0, BP[2:0] = 7
    NONE_alt3                       = 0b0011000            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 0
    PROTECT_000000h_TO_000FFFh      = 0b0011001            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 1
    PROTECT_000000h_TO_001FFFh      = 0b0011010            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 2
    PROTECT_000000h_TO_003FFFh      = 0b0011011            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 3
    PROTECT_000000h_TO_007FFFh      = 0b0011100            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 4
    PROTECT_000000h_TO_007FFFh_alt  = 0b0011101            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 5
    #                                 0b0011110            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 6 - not a valid protection range
    PROTECT_ALL_alt3                = 0b0011111            # WPS = 0, CMP = 0, SEC = 1, TB = 1, BP[2:0] = 7
    # Next, all the combinations with WPS=0 and CMP=1
    PROTECT_ALL_alt4                = 0b0100000            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 0
    PROTECT_000000h_TO_FBFFFFh      = 0b0100001            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 1
    PROTECT_000000h_TO_F7FFFFh      = 0b0100010            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 2
    PROTECT_000000h_TO_EFFFFFh      = 0b0100011            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 3
    PROTECT_000000h_TO_DFFFFFh      = 0b0100100            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 4
    PROTECT_000000h_TO_BFFFFFh      = 0b0100101            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 5
    PROTECT_000000h_TO_7FFFFFh_alt1 = 0b0100110            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 6
    NONE_alt4                       = 0b0100111            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 7

    PROTECT_ALL_alt5                = 0b0101000            # WPS = 0, CMP = 1, SEC = 0, TB = 1, BP[2:0] = 0
    PROTECT_040000h_TO_FFFFFFh      = 0b0101001            # WPS = 0, CMP = 1, SEC = 0, TB = 1, BP[2:0] = 1
    PROTECT_080000h_TO_FFFFFFh      = 0b0101010            # WPS = 0, CMP = 1, SEC = 0, TB = 1, BP[2:0] = 2
    PROTECT_100000h_TO_FFFFFFh      = 0b0101011            # WPS = 0, CMP = 1, SEC = 0, TB = 1, BP[2:0] = 3
    PROTECT_200000h_TO_FFFFFFh      = 0b0101100            # WPS = 0, CMP = 1, SEC = 0, TB = 1, BP[2:0] = 4
    PROTECT_400000h_TO_FFFFFFh      = 0b0101101            # WPS = 0, CMP = 1, SEC = 0, TB = 1, BP[2:0] = 5
    PROTECT_800000h_TO_FFFFFFh_alt1 = 0b0101110            # WPS = 0, CMP = 1, SEC = 0, TB = 1, BP[2:0] = 6
    NONE_alt5                       = 0b0101111            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 7

    PROTECT_ALL_alt6                = 0b0110000            # WPS = 0, CMP = 1, SEC = 1, TB = 0, BP[2:0] = 0
    PROTECT_000000h_TO_FFEFFFh      = 0b0110001            # WPS = 0, CMP = 1, SEC = 1, TB = 0, BP[2:0] = 1
    PROTECT_000000h_TO_FDFFFFh      = 0b0110010            # WPS = 0, CMP = 1, SEC = 1, TB = 0, BP[2:0] = 2
    PROTECT_000000h_TO_FBFFFFh_alt1 = 0b0110011            # WPS = 0, CMP = 1, SEC = 1, TB = 0, BP[2:0] = 3
    PROTECT_000000h_TO_F7FFFFh_alt2 = 0b0110100            # WPS = 0, CMP = 1, SEC = 1, TB = 0, BP[2:0] = 4
    PROTECT_000000h_TO_F7FFFFh_alt3 = 0b0110101            # WPS = 0, CMP = 1, SEC = 1, TB = 0, BP[2:0] = 5
    #                                 0b0110110            # WPS = 0, CMP = 1, SEC = 1, TB = 0, BP[2:0] = 6 - not a valid protection range
    NONE_alt6                       = 0b0110111            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 7

    PROTECT_ALL_alt7                = 0b0111000            # WPS = 0, CMP = 1, SEC = 1, TB = 1, BP[2:0] = 0
    PROTECT_001000h_TO_FFFFFFh      = 0b0111001            # WPS = 0, CMP = 1, SEC = 1, TB = 1, BP[2:0] = 1
    PROTECT_002000h_TO_FFFFFFh      = 0b0111010            # WPS = 0, CMP = 1, SEC = 1, TB = 1, BP[2:0] = 2
    PROTECT_004000h_TO_FFFFFFh      = 0b0111011            # WPS = 0, CMP = 1, SEC = 1, TB = 1, BP[2:0] = 3
    PROTECT_008000h_TO_FFFFFFh      = 0b0111100            # WPS = 0, CMP = 1, SEC = 1, TB = 1, BP[2:0] = 4
    PROTECT_008000h_TO_FFFFFFh_alt1 = 0b0111101            # WPS = 0, CMP = 1, SEC = 1, TB = 1, BP[2:0] = 5
    #                                 0b0111110            # WPS = 0, CMP = 1, SEC = 1, TB = 1, BP[2:0] = 6 - not a valid protection range
    NONE_alt7                       = 0b0111111            # WPS = 0, CMP = 1, SEC = 0, TB = 0, BP[2:0] = 7

    INDIVIDUAL_BLOCK_PROTECT        = 0b1000000            # WPS = 1, all other bits are zero (don't care, technically)

    # Helper properties to extract status-register fields from enum value.
    @property
    def WPS(self) -> bool:
        return bool((self.value >> 6) & 0b1)

    @property
    def CMP(self) -> bool:
        return bool((self.value >> 5) & 0b1)

    @property
    def SEC(self) -> bool:
        return bool((self.value >> 4) & 0b1)

    @property
    def TB(self) -> bool:
        return bool((self.value >> 3) & 0b1)

    @property
    def BP(self) -> int:
        return self.value & 0b111

    @property
    def IsNoWriteProtection(self) -> int:
        return (not self.WPS) and ((not self.CMP and self.BP == 0) or (self.CMP and self.BP == 7))

    @property
    def IsFullWriteProtection(self) -> int:
        return (not self.WPS) and ((not self.CMP and self.BP == 7) or (self.CMP and self.BP == 0))

StatusRegisters: TypeAlias = StatusRegister1 | StatusRegister2 | StatusRegister3

class util_timer:
    """Helper context manager to time an operation."""
    def __init__(self, ctx: CommandContext, description: str = "Operation"):
        self.ctx = ctx
        self.description = description
    def __enter__(self):
        self.start_time = asyncio.get_event_loop().time()
        return self
    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object]
    ) -> Optional[bool]:
        end_time = asyncio.get_event_loop().time()
        elapsed = end_time - self.start_time
        self.ctx.print(f"{self.description:>50} {elapsed:6.1f} seconds).")
        return None

# ---------------------------------------------------------------------------
# Global (const) data
# ---------------------------------------------------------------------------

FLASH_WALK = bytes(
    b'\xFF\xFE\xFC\xF8\xF0\xE0\xC0\x80\x00\x7F\x7E\x7C\x78\x70\x60\x40' +
    b'\xBF\xBE\xBC\xB8\xB0\xA0\x20\xDF\xDE\xDC\xD8\xD0\x90\x10\xEF\xEE' +
    b'\xEC\xE8\xC8\x88\x08\xF7\xF6\xF4\xE4\xC4\x84\x04\xFB\xFA\xF2\xE2' +
    b'\xC2\x82\x02\xFD\xF9\xF1\xE1\xC1\x81\x01\x3F\x3E\x3C\x38\x30\x5F' +
    b'\x5E\x5C\x58\x50\x6F\x6E\x6C\x68\x48\x77\x76\x74\x64\x44\x7B\x7A' +
    b'\x72\x62\x42\x7D\x79\x71\x61\x41\x9F\x9E\x9C\x98\x18\xAF\xAE\xAC' +
    b'\xA8\x28\xB7\xB6\xB4\xA4\x24\xBB\xBA\xB2\xA2\x22\xBD\xB9\xB1\xA1' +
    b'\x21\xCF\xCE\xCC\x8C\x0C\xD7\xD6\xD4\x94\x14\xDB\xDA\xD2\x92\x12' +
    b'\xDD\xD9\xD1\x91\x11\xE7\xE6\xC6\x86\x06\xEB\xEA\xCA\x8A\x0A\xED' +
    b'\xE9\xC9\x89\x09\xF3\xE3\xC3\x83\x03\xF5\xE5\xC5\x85\x05\x1F\x1E' +
    b'\x1C\x2F\x2E\x2C\x37\x36\x34\x3B\x3A\x32\x3D\x39\x31\x4F\x4E\x4C' +
    b'\x57\x56\x54\x5B\x5A\x52\x5D\x59\x51\x67\x66\x46\x6B\x6A\x4A\x6D' +
    b'\x69\x49\x73\x63\x43\x75\x65\x45\x8F\x8E\x0E\x97\x96\x16\x9B\x9A' +
    b'\x1A\x9D\x99\x19\xA7\xA6\x26\xAB\xAA\x2A\xAD\xA9\x29\xB3\xA3\x23' +
    b'\xB5\xA5\x25\xC7\x87\x07\xCB\x8B\x0B\xCD\x8D\x0D\xD3\x93\x13\xD5' +
    b'\x95\x15\x0F\x17\x1B\x1D\x27\x2B\x2D\x33\x35\x47\x4B\x4D\x53\x55'
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

async def util_hex_dump(ctx: CommandContext, data: bytes, base_address: int = 0) -> None:
    """Helper to print a hex dump of *data* to the console."""
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        ascii_bytes = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)
        ctx.print(f"{base_address + i:06x}  {hex_bytes:<48}  {ascii_bytes}")

async def util_send_command(args: str, ctx: CommandContext) -> list[str]:
    """Helper to send a command and wait for the prompt (which indicates the command has completed)."""
    if not ctx.serial.connected:
        ctx.print_error("Not connected.")
        return []
    async with ctx.serial.response_collector() as collector:
        await ctx.serial.write_line(args)
        multiline = await collector.read_until(b'>>')

    # split the multiline response on \r\n or \n
    # and remove empty lines, and remove final line that is just the prompt
    # and remove the first line that matches the command sent
    results = list[str]()
    firstLine : bool = True
    for line in multiline.decode(encoding="latin-1", errors="ignore").splitlines():
        if line.strip() == '':
            continue # skip blank lines
        if firstLine and line.find(args) != -1:
            firstLine = False
            continue # skip the command echo
        if line.startswith('>>'):
            continue # skip the prompt
        results.append(line)
    return results

async def read_flash(address:int, length:int, ctx: CommandContext) -> bytes:
    """Helper to read flash data from the device."""
    results = bytearray(length)

    # Sends a number of commands to the device.
    # each command will cause some response data to be sent back by the device,
    # which in these first few steps we ignore.
    l = await util_send_command("BEGIN", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command(f"DATA 03 {((address >> 16) & 0xFF):02x} {((address >> 8) & 0xFF):02x} {(address & 0xFF):02x}", ctx)

    for i in range(0, length, 16):
        expected_chars = min(16, length - i)
        hex_str = ' '.join(f"0" for _ in range(expected_chars))
        tmp = await util_send_command(f"DATA {hex_str}", ctx)
        if len(tmp) != 1:
            raise ValueError(f"Unexpected response length: {len(tmp)} lines (expected 1)")
        # convert from a line of hex chars such as "72 b d9 0 d7 6b ed c8 d1 d1 47 34 81 46 9a 24" to corresponding bytes
        # storing the bytes in result[i:i+16]
        hex_chars = tmp[0].split()
        if len(hex_chars) != expected_chars:
            raise ValueError(f"Unexpected response format: {tmp[0]} (expected {expected_chars} hex bytes)")
        for j in range(expected_chars):
            results[i+j] = int(hex_chars[j], 16)

    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("END", ctx)

    return bytes(results)

# Callback for reading flash with callback function
class ReadFlashDataChunkCallback(Protocol):
    async def __call__(self, ctx: CommandContext, address: int, data: bytes) -> None: ...
class ReadFlashProgressCallback(Protocol):
    async def __call__(self, ctx: CommandContext, address_read_through_exclusive: int) -> None: ...

async def read_flash_with_callback(ctx : CommandContext, start_address : int, length : int, data_callback : ReadFlashDataChunkCallback, progress_callback : ReadFlashProgressCallback | None = None, chunk_size : int = 0x10) -> None:

    if chunk_size < 0x10 or chunk_size > 0x10000:
        raise ValueError("Chunk size must be between 16 and 65536 bytes.")
    if chunk_size % 0x10 != 0:
        # This greatly simplifies the implementation, because
        # the buffer will be read in chunks of 16 bytes,
        # and thus never need to shuffle data around due to
        # callback only using part of the read data / only
        # having space in callback buffer for part of the read data.
        raise ValueError("Chunk size must be a multiple of 16 bytes.")

    if progress_callback is not None:
        await progress_callback(ctx, 0)

    await util_send_command("BEGIN", ctx)
    await util_send_command("ASSERT", ctx)
    await util_send_command(f"DATA 03 {((start_address >> 16) & 0xFF):02x} {((start_address >> 8) & 0xFF):02x} {(start_address & 0xFF):02x}", ctx)

    chunk_buffer : bytearray = bytearray(chunk_size)
    chunk_idx : int = 0

    for i in range(0, length, 0x10):
        current_address = start_address + i
        if (chunk_idx + 0x10 > len(chunk_buffer)):
            raise AssertionError("Code logic error: chunk_idx + 0x10 should never exceed chunk_buffer length here.")

        expected_bytes = min(16, length - i)
        hex_str = ' '.join(f"0" for _ in range(expected_bytes))

        tmp = await util_send_command(f"DATA {hex_str}", ctx)
        if len(tmp) != 1:
            # expect exactly one line of response that is not filtered by util_send_command
            # (which filters out blank lines, command echo, and prompt)
            raise ValueError(f"Unexpected response length: {len(tmp)} lines (expected 1) at address {current_address:06x}")
        if progress_callback is not None:
            await progress_callback(ctx, current_address)

        # convert from a line of hex chars such as "72 b d9 0 d7 6b ed c8 d1 d1 47 34 81 46 9a 24" to corresponding bytes
        # storing the bytes in chunk_buffer[chunk_idx:chunk_idx+expected_bytes]
        hex_as_chars = tmp[0].split()
        if len(hex_as_chars) != expected_bytes:
            raise ValueError(f"Unexpected response format: {tmp[0]} (expected {expected_bytes} hex bytes) at address {current_address:06x}")

        for j in range(expected_bytes):
            chunk_buffer[chunk_idx] = int(hex_as_chars[j], 16)
            chunk_idx += 1
        if chunk_idx == len(chunk_buffer):
            # Call the callback with the current chunk buffer (up to chunk_idx bytes)
            await data_callback(ctx, current_address, bytes(chunk_buffer[:chunk_idx]))
            chunk_idx = 0

    # Partial chunk at the end?
    if chunk_idx > 0:
        current_address = start_address + length - chunk_idx
        await data_callback(ctx, current_address, bytes(chunk_buffer[:chunk_idx]))

    await util_send_command("RELEASE", ctx)
    await util_send_command("END", ctx)

    # Always callback with final address to allow 100% progress indication
    if progress_callback is not None:
        await progress_callback(ctx, start_address + length)    

async def _write_flash_impl(address:int, data:bytes, ctx: CommandContext) -> None:
    """Helper to write flash data to the device."""
    if len(data) < 1 or len(data) > 256:
        raise ValueError("Data length must be between 1 and 256 bytes.")
    if address & 0xFF != 0:
        raise ValueError("Address must be aligned to 256-byte boundary (mask 0xFF).")
    l = await util_send_command("BEGIN", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command("DATA 06", ctx) # Write Enable
    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command(f"DATA 02 {((address >> 16) & 0xFF):02x} {((address >> 8) & 0xFF):02x} {(address & 0xFF):02x}", ctx)

    for i in range(0, len(data), 16):
        expected_chars = min(16, len(data) - i)
        hex_str = ' '.join(f"{b:02x}" for b in data[i:i+16])
        l = await util_send_command(f"DATA {hex_str}", ctx)
        # convert from a line of hex chars such as "72 b d9 0 d7 6b ed c8 d1 d1 47 34 81 46 9a 24" to corresponding bytes
        # storing the bytes in result[i:i+16]
        if len(l) != 1:
            raise ValueError(f"Unexpected response length: {len(l)} lines (expected 1)")
        hex_chars = l[0].split()
        if len(hex_chars) != expected_chars:
            raise ValueError(f"Unexpected response format: {l[0]} (expected {expected_chars} hex bytes)")

    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("END", ctx)
    await wait_for_flash_nonbusy(ctx)

    # Verify after write ... because there's really no other way to check if
    # data made it to the device correctly.
    if True:
        read_back = await read_flash(address, len(data), ctx)
        if read_back != data:
            raise ValueError("Verification failed: data read back does not match data written.")

# NOTE: This function will erase 4k on failed write; set max_retries to zero to disable this.
async def write_flash(address: int, data: bytes, ctx: CommandContext, max_retries: int = 5) -> None:
    """Helper to write flash data to the device, with erase + write retry on failure."""
    if (address % 0x100) != 0:
        raise ValueError(f"Address must be aligned to 256-byte boundary (mask 0xFF).") 
    for attempt in range(max_retries):
        try:
            for i in range(0, len(data), 256):
                chunk_address = address + i
                chunk_data = data[i:i+256]
                await _write_flash_impl(chunk_address, chunk_data, ctx)
            return # success
        except (ValueError, Error) as e:
            ctx.print_error(f"Write attempt {attempt+1} failed: {e}")
            if attempt < max_retries:
                ctx.print_info("Retrying...")
                # NO, it is NOT normally a good idea to erase larger area on write.
                # For SoS usage, it's fine....
                erase_address = address & ~0xFFF # align down to 4K boundary
                await erase_flash_4k(erase_address, ctx) 
            else:
                ctx.print_error("Max retries reached. Write failed.")
                raise

async def wait_for_flash_nonbusy(ctx: CommandContext) -> None:
    """Helper to wait until the flash is no longer busy."""
    l = await util_send_command("BEGIN", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command("DATA 05", ctx) # Read Status Register
    while True:
        l = await util_send_command("DATA 00", ctx) # dummy byte to read the status
        if len(l) != 1:
            raise ValueError(f"Unexpected response length: {len(l)} lines (expected 1)")
        hex_chars = l[0].split()
        if len(hex_chars) != 1:
            raise ValueError(f"Unexpected response format: {l[0]} (expected 1 hex byte)")
        status = int(hex_chars[0], 16)
        if (status & 0x01) == 0:
            break # not busy
        await asyncio.sleep(0.1) # wait a bit before checking again
    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("END", ctx)

async def erase_flash_4k(address:int, ctx: CommandContext) -> None:
    """Helper to erase flash data on the device."""
    if (address % 4096) != 0:
        raise ValueError(f"Address must be aligned to 4K (mask 0xFFF) boundary")
    
    l = await util_send_command("BEGIN", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command("DATA 06", ctx) # Write Enable
    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command(f"DATA 20 {((address >> 16) & 0xFF):02x} {((address >> 8) & 0xFF):02x} {(address & 0xFF):02x}", ctx)
    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("END", ctx)
    await wait_for_flash_nonbusy(ctx) # wait for the erase to complete before returning

@overload
async def read_status_register(status_register_number : Literal[StatusRegisterType.SR1], ctx: CommandContext) -> StatusRegister1: ...
@overload
async def read_status_register(status_register_number : Literal[StatusRegisterType.SR2], ctx: CommandContext) -> StatusRegister2: ...
@overload
async def read_status_register(status_register_number : Literal[StatusRegisterType.SR3], ctx: CommandContext) -> StatusRegister3: ...

async def read_status_register(status_register_number : StatusRegisterType, ctx: CommandContext) -> StatusRegisters:
    if status_register_number == StatusRegisterType.SR1:
        cmd = 0x05
    elif status_register_number == StatusRegisterType.SR2:
        cmd = 0x35
    elif status_register_number == StatusRegisterType.SR3:
        cmd = 0x15
    else:
        raise ValueError(f"Status register invalid for read: {status_register_number}")
    l = await util_send_command("BEGIN", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command(f"DATA {cmd:02x}", ctx) # Read Status Register
    l = await util_send_command("DATA 00", ctx) # dummy byte to read the status
    if len(l) != 1:
        raise ValueError(f"Unexpected response length: {len(l)} lines (expected 1)")
    hex_chars = l[0].split()
    if len(hex_chars) != 1:
        raise ValueError(f"Unexpected response format: {l[0]} (expected 1 hex byte)")
    status = int(hex_chars[0], 16)
    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("END", ctx)
    if status_register_number == StatusRegisterType.SR1:
        return StatusRegister1(status)
    elif status_register_number == StatusRegisterType.SR2:
        return StatusRegister2(status)
    elif status_register_number == StatusRegisterType.SR3:
        return StatusRegister3(status)
    raise ValueError(f"Status register invalid for read: {status_register_number}")

async def read_status_register1(ctx: CommandContext) -> StatusRegister1:
    return await read_status_register(StatusRegisterType.SR1, ctx)
async def read_status_register2(ctx: CommandContext) -> StatusRegister2:
    return await read_status_register(StatusRegisterType.SR2, ctx)
async def read_status_register3(ctx: CommandContext) -> StatusRegister3:
    return await read_status_register(StatusRegisterType.SR3, ctx)


@overload
async def write_status_register(status_register_number : Literal[StatusRegisterType.SR1], data : Tuple[StatusRegister1], ctx: CommandContext) -> None: ...
@overload
async def write_status_register(status_register_number : Literal[StatusRegisterType.SR2], data : Tuple[StatusRegister2], ctx: CommandContext) -> None: ...
@overload
async def write_status_register(status_register_number : Literal[StatusRegisterType.SR1_and_SR2], data : Tuple[StatusRegister1, StatusRegister2], ctx: CommandContext) -> None: ...
@overload
async def write_status_register(status_register_number : Literal[StatusRegisterType.SR3], data : Tuple[StatusRegister3], ctx: CommandContext) -> None: ...

async def write_status_register(status_register_number : StatusRegisterType, data : Sequence[StatusRegisters], ctx: CommandContext) -> None:
    # The writable Status Register bits include:
    #   Status Register 1: mask 0b0111'1100: SEC (0x40), TB (0x20), BP[2:0] (0x1C)
    #   Status Register 2: mask 0b0111'1011: CMP (0x40), LB[3:1] (0x38), QE (0x02), SRL (0x01)
    #   Status Register 3: mask 0b0110'0100: DRV1 (0x40), DRV0 (0x20), WPS (0x04)
    if status_register_number == StatusRegisterType.SR1:
        if len(data) != 1:
            raise ValueError("Data length must be 1 byte for writing Status Register 1.")
        if not isinstance(data[0], StatusRegister1):
            raise ValueError("Data must be of type StatusRegister1 for writing Status Register 1.")
        cmd = 0x01
    elif status_register_number == StatusRegisterType.SR2:
        if len(data) != 1:
            raise ValueError("Data length must be 1 byte for writing Status Register 2.")
        if not isinstance(data[0], StatusRegister2):
            raise ValueError("Data must be of type StatusRegister2 for writing Status Register 2.")
        if data[0].LB != 0:
            raise ValueError("LB[3:1] bits in Status Register 2 are OTP bits ... refusing for safety to set those bits to 1.")
        cmd = 0x31
    elif status_register_number == StatusRegisterType.SR1_and_SR2:
        if len(data) != 2:
            raise ValueError("Data length must be 2 bytes for writing Status Register 1 and 2 together.")
        if not isinstance(data[0], StatusRegister1):
            raise ValueError("First byte of data must be of type StatusRegister1 for writing Status Register 1 and 2 together.")
        if not isinstance(data[1], StatusRegister2):
            raise ValueError("Second byte of data must be of type StatusRegister2 for writing Status Register 1 and 2 together.")
        if data[1].LB != 0:
            raise ValueError("LB[3:1] bits in Status Register 2 are OTP bits ... refusing for safety to set those bits to 1.")
        cmd = 0x01 # when writing both SR1 and SR2 together, the command is still 0x01, but we send both bytes of data
    elif status_register_number == StatusRegisterType.SR3:
        if len(data) != 1:
            raise ValueError("Data length must be 1 byte for writing Status Register 3.")
        if not isinstance(data[0], StatusRegister3):
            raise ValueError("Data must be of type StatusRegister3 for writing Status Register 3.")
        cmd = 0x11
    l = await util_send_command("BEGIN", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command("DATA 06", ctx) # Write Enable
    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("ASSERT", ctx)
    l = await util_send_command(f"DATA {cmd:02x} {' '.join(f'{b.value:02x}' for b in data)}", ctx)
    l = await util_send_command("RELEASE", ctx)
    l = await util_send_command("END", ctx)
    return None
async def write_status_register1(data: StatusRegister1, ctx: CommandContext) -> None:
    return await write_status_register(StatusRegisterType.SR1, (data,), ctx)
async def write_status_register2(data: StatusRegister2, ctx: CommandContext) -> None:
    return await write_status_register(StatusRegisterType.SR2, (data,), ctx)
async def write_status_register1_and_2(data1: StatusRegister1, data2: StatusRegister2, ctx: CommandContext) -> None:
    return await write_status_register(StatusRegisterType.SR1_and_SR2, (data1, data2), ctx)
async def write_status_register3(data: StatusRegister3, ctx: CommandContext) -> None:
    return await write_status_register(StatusRegisterType.SR3, (data,), ctx)
async def set_write_protect_state(write_protection_type: WriteProtectionType, ctx: CommandContext) -> None:
    # raise an error unless the enum is a valid option (e.g., has a name in the enum, and thus isn't one of the invalid protection ranges)
    if write_protection_type not in WriteProtectionType:
        raise ValueError(f"Invalid write protection type: {write_protection_type}")
    if write_protection_type.IsNoWriteProtection:
        ctx.print_info("Setting write protection to NONE (no write protection).")
        write_protection_type = WriteProtectionType.NONE

    sr1 : StatusRegister1 = await read_status_register(StatusRegisterType.SR1, ctx)
    sr2 : StatusRegister2 = await read_status_register(StatusRegisterType.SR2, ctx)
    sr3 : StatusRegister3 = await read_status_register(StatusRegisterType.SR3, ctx)

    if sr3.WPS and not write_protection_type.WPS:
        sr3.WPS = False
        await write_status_register3(sr3, ctx)

    sr2.CMP = write_protection_type.CMP
    sr1.SEC = write_protection_type.SEC
    sr1.TB = write_protection_type.TB
    sr1.BP = write_protection_type.BP
    await write_status_register1_and_2(sr1, sr2, ctx)

    if not sr3.WPS and write_protection_type.WPS:
        sr3.WPS = True
        await write_status_register3(sr3, ctx)

async def is_pkcs7_padding_valid(data: bytes) -> bool:
    if len(data) < 16:
        raise ValueError("Data length must be at least 16 bytes for PKCS7 padding validation.")
    if len(data) % 16 != 0:
        raise ValueError("Data length must be a multiple of 16 for PKCS7 padding validation.")
    padding_value = data[-1]
    if padding_value <= 0 or padding_value > 16:
        return False
    if data[-padding_value:] != bytes([padding_value] * padding_value):
        return False
    return True

# ---------------------------------------------------------------------------
# Commands registered with serial console
# ---------------------------------------------------------------------------

async def cmd_dump_all_flash(_:str, ctx: CommandContext) -> None:
    """Dump the full flash contents for manual review."""
    # most of the flash is erased and empty (0xFF).
    # keep list of addresses that have non-0xFF data, and discard all the rest.

    total_flash_size = 0x100000
    address_progress_fmt : str = "0x{address:06x} / 0x{total_flash_size:06x}  {percent:6.2f}%  "
                                # .. ..-...      .1...    .-....            2.  ...-..      ..3
    address_progress_expected_chars : int = 30

    # define the local variable prior to the callback function
    # so the callback can update this object (storing relevant data)
    flash_data : dict[int, bytes] = dict()


    # define a local function to output the progress
    # include equivalent of a local static variable to track spinner state
    def make_spinner() -> ReadFlashProgressCallback:
        spinner : Tuple[str, ...] = ("|", "/", "-", "\\")
        spinner_idx : int = 0
        spinner_max_length : int = max(len(s) for s in spinner)
        next_address_progress_update : int = -1

        async def update_spinner(ctx : CommandContext, address_read_through_exclusive : int) -> None:
            nonlocal spinner_idx
            nonlocal next_address_progress_update
            # all updates are fixed-length, so don't have to explicitly overwrite with spaces after backspace
            if address_read_through_exclusive >= next_address_progress_update:
                next_address_progress_update = address_read_through_exclusive + 0x100 # update full progress line every 0x400 bytes read
                ctx.print('\b' * (address_progress_expected_chars + spinner_max_length), end="")
                addr_update = address_progress_fmt.format(address=address_read_through_exclusive, total_flash_size=total_flash_size, percent=address_read_through_exclusive / total_flash_size * 100)
                ctx.print(addr_update, end="")
            else:
                ctx.print('\b' * spinner_max_length, end="")

            spinner_idx = (spinner_idx + 1) % len(spinner)
            ctx.print(spinner[spinner_idx].rjust(spinner_max_length), end="", flush=True)
        return update_spinner
    update_spinner = make_spinner()

    # async def read_flash_with_callback(ctx: CommandContext, address:int, length:int, callback: ReadFlashCallback, spinner_callback : ReadSpinnerCallback | None = None, chunk_size: int = 0x16) -> None:
    async def callback_datachunk(ctx: CommandContext, address: int, data: bytes) -> None:
        # This callback is called for each chunk of data read from flash.
        if any(b != 0xFF for b in bytes(data)):
            # update the flash_data dict in the outer scope with the new data
            flash_data[address] = data
        return

    with ctx.shell.suppress_serial_output():
        # create an empty hash, index is integer (address), and value will be bytes
        # Declare the types for the dict to be address (int) to data (bytes)
        ctx.print_info("Dumping full flash contents for manual review...")

        await read_flash_with_callback(ctx, 0, total_flash_size, data_callback = callback_datachunk, progress_callback=update_spinner)

        next_consecutive_address : int = -1
        for address, saved_data in sorted(flash_data.items()):
            if address != next_consecutive_address:
                ctx.print_info("-" * 73)
            hex_str = ' '.join(f"{b:02x}" for b in saved_data)
            ascii_str = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in saved_data)
            ctx.print_info(f"0x{address:05x}: {hex_str}  {ascii_str}")
            next_consecutive_address = address + len(saved_data)
        if len(flash_data) != 0:
            ctx.print_info("-" * 73)
async def cmd_read_flash(args: str, ctx: CommandContext) -> None:
    """Read flash data.

    Reads flash memory from the connected Sword of Secrets device.
    Usage::

        read_flash <address> [length=0x100]
    """
    text = args.strip().split()
    if not text or len(text) < 1 or len(text) > 2:
        ctx.print_error("Usage: read_flash <address> [length]")
        return
    if not ctx.serial.connected:
        ctx.print_error("Not connected.")
        return
    try:
        address = int(text[0], 0)
    except ValueError:
        ctx.print_error("Invalid address.")
        return
    if len(text) > 1:
        try:
            length = int(text[1], 0)
        except ValueError:
            ctx.print_error("Invalid length.")
            return
        if length <= 0 or length > 512:
            ctx.print_error("Length must be between 1 and 512.")
            return
    else:
        length = 0x40

    with ctx.shell.suppress_serial_output():
        data = await read_flash(address, length, ctx)
        ctx.print_info(f"Read {len(data)} bytes from 0x{address:06x}:")
        # print the data in hex, 16 bytes per line
        for i in range(0, len(data), 16):
            line_data = data[i:i+16]
            hex_str = ' '.join(f"{b:02x}" for b in line_data)
            ctx.print_info(f"  {hex_str}")
async def cmd_write_flash(args: str, ctx: CommandContext) -> None:
    """Write flash data.

    Writes flash memory on the connected Sword of Secrets device.
    Usage::
        write_flash <address> <hex_data>
    where <hex_data> is a string of hex bytes such as 01 02 03 04

    Note: Generally limited to writing maximum 256 bytes at a time

    """
    text = args.strip().split()
    if len(text) < 2:
        ctx.print_error("Usage: write_flash <address> <hex_data>")
        return
    if not ctx.serial.connected:
        ctx.print_error("Not connected.")
        return
    try:
        address = int(text[0], 0)
    except ValueError:
        ctx.print_error("Invalid address.")
        return
    if address % 0x100 != 0:
        ctx.print_error("Address must be aligned to 0x100 byte boundary.")
        return

    try:
        data = bytes(int(b, 16) for b in text[1:])
    except ValueError:
        ctx.print_error("Invalid hex data.")
        return
    if len(data) == 0 or len(data) > 256:
        ctx.print_error("Data length must be between 1 and 256 bytes.")
        return
    
    with ctx.shell.suppress_serial_output():
        await write_flash(address, data, ctx)
        ctx.print_info(f"Wrote {len(data)} bytes to 0x{address:06x}.")
async def cmd_erase_flash_4k(args: str, ctx: CommandContext) -> None:
    """Erase a 4K block of flash.

    Usage::
        erase_flash_4k <address>
    where <address> is the starting address of the 4K block to erase (must be multiple of 0x1000)
    """
    text = args.strip().split()
    if len(text) != 1:
        ctx.print_error("Usage: erase_flash_4k <address>")
        return
    if not ctx.serial.connected:
        ctx.print_error("Not connected.")
        return
    try:
        address = int(text[0], 0)
    except ValueError:
        ctx.print_error("Invalid address.")
        return
    if address % 0x1000 != 0:
        ctx.print_error("Address must be a multiple of 0x1000.")
        return
    
    with ctx.shell.suppress_serial_output():
        await erase_flash_4k(address, ctx)
        ctx.print_info(f"Erased 4K block of flash at address 0x{address:06x}.")

# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------

