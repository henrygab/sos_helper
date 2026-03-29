"""
Walkthrough to solve the Sword of Secrets hardware CTF.

This is SPOILER RICH content.  Do NOT read if you wish
to enjoy the challenge of the CTF on your own!
"""

from __future__ import annotations

from binascii import Error

from ..command_registry import CommandContext, CommandRegistry
from enum import Enum
from typing import Literal, Sequence, Tuple, overload, TypeAlias
from . import sword_of_secrets as sos


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_sword_of_secrets_spoilers_2(registry: CommandRegistry) -> None:
    registry.register(
        "sos2_autosolve", cmd_sos2_autosolve,
        "Writes the solution for stage 2 to the flash on the device.",
        usage="sos2_autosolve",
        category="Sword of Secrets - Stage 2 Spoilers",
    )

# ---------------------------------------------------------------------------
# Enums and types
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Global (const) data
# ---------------------------------------------------------------------------

STAGE2_ORIGINAL_FLASH_DATA : bytes = bytes(
    b'\x4b\x40\x6f\xe6\xa3\xd4\x32\x1b\x26\x28\xb7\xc6\xff\xf5\xfc\x9f' +
    b'\x6e\x61\x71\x38\x48\x3e\xf9\x86\x9c\xb8\x4c\x9c\xc0\xd2\x72\xa3' +
    b'\xde\x90\xe7\xd0\xae\x83\x38\xb0\x7a\xac\x38\x94\x75\x74\x69\x00' +
    b'\x41\x5d\x39\x41\xde\xd0\xe4\xe3\xad\xc5\x45\x98\x42\xdc\xa5\x8d'
)
STAGE2_SOLVED_DATA = bytes(
    b'\xDE\x90\xE7\xD0\xAE\x83\x38\xB0\x7A\xAC\x38\x94\x75\x74\x69\x00' +
    b'\x41\x5D\x39\x41\xDE\xD0\xE4\xE3\xAD\xC5\x45\x98\x42\xDC\xA5\x8D' +
    b'\xDE\x90\xE7\xD0\xAE\x83\x38\xB0\x7A\xAC\x38\x94\x75\x74\x69\x00' +
    b'\x41\x5D\x39\x41\xDE\xD0\xE4\xE3\xAD\xC5\x45\x98\x42\xDC\xA5\x8D'
)

# ---------------------------------------------------------------------------
# Auto-solve stage
# ---------------------------------------------------------------------------

async def write_stage2_solution(ctx: CommandContext) -> None:
    """Helper to write the stage 2 solution to the device."""
    # this is the data that needs to be written to the device to solve stage 2 of the CTF

    await sos.erase_flash_4k(0x20000, ctx)
    await sos.write_flash(0x20000, STAGE2_SOLVED_DATA, ctx)
    ctx.print_info("Stage 2 solution written to flash at address 0x20000.")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Nothing really to do here ... once you understand how the blocks can
# be shuffled, the solution is straightforward.

# ---------------------------------------------------------------------------
# Commands registered with serial console
# ---------------------------------------------------------------------------

async def cmd_sos2_autosolve(args: str, ctx: CommandContext) -> None:
    """Helper to write the stage 1 solution to the device."""
    await write_stage2_solution(ctx)

# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------
