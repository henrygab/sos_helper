"""
Walkthrough to solve the Sword of Secrets hardware CTF.

This is SPOILER RICH content.  Do NOT read if you wish
to enjoy the challenge of the CTF on your own!
"""

from __future__ import annotations

from ..command_registry import CommandContext, CommandRegistry
from . import sword_of_secrets as sos

# ---------------------------------------------------------------------------
# Enums and types
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_sword_of_secrets_spoilers_1(registry: CommandRegistry) -> None:
    registry.register(
        "sos1_try_key", cmd_sos1_try_key,
        "XOR the stage 1 flash data with a given set of eight hex bytes (or eight ASCII characters).",
        usage="sos1_try_key < 34 45 56 67 76 65 54 43 | ABCDEFGH >",
        category="Sword of Secrets - Stage 1 Spoilers",
    )
    registry.register(
        "sos1_show_key_calculation", cmd_sos1_show_key_calculation,
        "Explain the calculation of the XOR key for stage 1.",
        usage="sos1_show_key_calculation",
        category="Sword of Secrets - Stage 1 Spoilers",
    )
    registry.register(
        "sos1_autosolve", cmd_sos1_autosolve,
        "Writes the solution for stage 1 to the flash on the device.",
        usage="sos1_autosolve",
        category="Sword of Secrets - Stage 1 Spoilers",
    )


# ---------------------------------------------------------------------------
# Global (const) data
# ---------------------------------------------------------------------------
STAGE1_EXPECTED_PLAINTEXT_DATA_WITH_UNDERSCORES : bytes = bytes(
    b'____CLIB{No one can break this! 0x_____}\0'
)

STAGE1_ORIGINAL_FLASH_DATA : bytes = bytes(
    b'\x00\x00\x00\x00\x0e\x05\x13\x07' +
    b'\x36\x0f\x37\x69\x22\x27\x3f\x65' +
    b'\x2e\x20\x36\x69\x2f\x3b\x3f\x24' +
    b'\x26\x61\x2c\x21\x24\x3a\x7b\x65' +
    b'\x7d\x39\x6a\x79\x7d\x79\x6a\x38' +
    b'\x4d'
)
STAGE1_SOLVED_DATA : bytes = bytes(
    b'\x00\x00\x1F\x00\x0E\x05\x13\x07' +
    b'\x36\x0F\x37\x69\x22\x27\x3F\x65' +
    b'\x2E\x20\x36\x69\x2F\x3B\x3F\x24' +
    b'\x26\x61\x2C\x21\x24\x3A\x7B\x65' +
    b'\x7D\x39\x6A\x79\x7D\x79\x6A\x38' +
    b'\x4D'
)

# ---------------------------------------------------------------------------
# Auto-solve stage
# ---------------------------------------------------------------------------

async def write_stage1_solution(ctx: CommandContext) -> None:
    """Helper to write the stage 1 solution to the device."""
    # this is the data that needs to be written to the device to solve stage 1 of the CTF

    await sos.erase_flash_4k(0x10000, ctx)
    await sos.write_flash(0x10000, STAGE1_SOLVED_DATA, ctx)
    ctx.print_info("Stage 1 solution written to flash at address 0x10000.")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

async def stage1_xor_original_flash_data(ctx: CommandContext, xorkey : bytes) -> bytes:
    """XOR the original flash data with the specified XOR key."""
    if len(xorkey) != 8:
        raise ValueError(f"Invalid XOR key length: {len(xorkey)} (expected 8 bytes)")

    # create xor_data array corresponding to the length of the original flash dataiterate over xorkey bytes, using both the byte and its index
    xor_data = bytearray(len(STAGE1_ORIGINAL_FLASH_DATA))
    for i in range(len(xor_data)):
        xor_data[i] = xorkey[i % len(xorkey)]
    # xor the original flash data with the specified XOR key, and return the modified data
    modified_data = bytes(b ^ xor_value for b, xor_value in zip(STAGE1_ORIGINAL_FLASH_DATA, xor_data))
    return modified_data

async def stage1_calculate_xorkey_retaining_underscores(ctx: CommandContext) -> bytes:
    """Calculates EXPECTED_PLAINTEXT_DATA ^ ORIGINAL_FLASH_DATA, except leaves underscores as underscores"""
    modified_data = bytes(
        p ^ c if p != ord('_') else ord('_') for p, c in zip(STAGE1_EXPECTED_PLAINTEXT_DATA_WITH_UNDERSCORES, STAGE1_ORIGINAL_FLASH_DATA)
    )
    return modified_data

async def stage1_check_xorkey_manual_review(ctx: CommandContext, xorkey : bytes) -> None:
    """Helper to check if a given XOR key is correct by showing the user the resulting modified flash data and expected plaintext."""

    ctx.print(f"Using XOR key:")
    await sos.util_hex_dump(ctx=ctx, data=xorkey, base_address=0x00000)
    ctx.print_info("")

    ctx.print(f"Original stage 1 flash data at 0x10000:")
    await sos.util_hex_dump(ctx=ctx, data=STAGE1_ORIGINAL_FLASH_DATA, base_address=0x10000)

    ctx.print(f"Expected plaintext data (underscores == unknown data):")
    await sos.util_hex_dump(ctx=ctx, data=STAGE1_EXPECTED_PLAINTEXT_DATA_WITH_UNDERSCORES, base_address=0x10000)
    ctx.print_info("")

    # generate `modified_data` which is XOR of `data` and `xor_data`
    # at corresponding byte positions, and hex dump for the user to review
    ctx.print(f"If XOR the original stage 1 flash data with that XOR key, you get:")
    modified_data = await stage1_xor_original_flash_data(ctx, xorkey)
    await sos.util_hex_dump(ctx=ctx, data=modified_data, base_address=0x10000)

async def stage1_show_xorkey_via_calculation(ctx: CommandContext) -> None:
    """Helper to show the user how xorkey can be calculated from partial plaintext and partial ciphertext"""
    # STAGE1_EXPECTED_PLAINTEXT_DATA_WITH_UNDERSCORES, STAGE1_ORIGINAL_FLASH_DATA

    ctx.print("")
    ctx.print(f"Since XOR is reversible, can XOR the partial plaintext with the ciphertext")
    ctx.print(f"to get the XOR key (with underscores retained as unknown bytes).  Here's")
    ctx.print(f"the calculation, showing expected plaintext, then original flash data,")
    ctx.print(f"then a separator line, and then the result of XORing those two.")
    ctx.print("")
    xor_result : bytes = await stage1_calculate_xorkey_retaining_underscores(ctx)
    for i in range(0,len(STAGE1_EXPECTED_PLAINTEXT_DATA_WITH_UNDERSCORES),0x10):
        chunk_plaintext = STAGE1_EXPECTED_PLAINTEXT_DATA_WITH_UNDERSCORES[i:i+0x10]
        chunk_flashdata = STAGE1_ORIGINAL_FLASH_DATA[i:i+0x10]
        chunk_xor_result = xor_result[i:i+0x10]
        await sos.util_hex_dump(ctx=ctx, data=chunk_plaintext, base_address=0x10000 + i)
        await sos.util_hex_dump(ctx=ctx, data=chunk_flashdata, base_address=0x10000 + i)
        ctx.print("-" * 80)
        await sos.util_hex_dump(ctx=ctx, data=chunk_xor_result, base_address=0x10000 + i)
        ctx.print("")

# ---------------------------------------------------------------------------
# Commands registered with serial console
# ---------------------------------------------------------------------------

async def cmd_sos1_try_key(args: str, ctx: CommandContext) -> None:
    """Helper to XOR the stage 1 flash data with a given set of eight hex bytes."""
    text = args.strip().split()
    xor_key = bytearray(8)

    if len(text) == 1 and len(text[0]) == 8:
        # they provided an 8-character string
        for i in range(len(xor_key)):
            xor_key[i] = ord(text[0][i])
    elif len(text) == 8:
        for i in range(len(xor_key)):
            try:
                tmp : int = int(text[i], 16)
            except ValueError:
                ctx.print_error(f"Invalid hex value at position {i} ('{text[i]}'). Please provide valid hex bytes (e.g., '0xFF').")
                return
            if tmp < 0x00 or tmp > 0xFF:
                ctx.print_error(f"Byte value at position {i} out of range. Please provide values between 0x00 and 0xFF.")
                return
            xor_key[i] = tmp
    else:
        ctx.print_error("Usage: sos1_xor_flash_data < 34 45 56 67 67 56 45 34 | ABCDEFGH >")
        return
    await stage1_check_xorkey_manual_review(ctx, bytes(xor_key))

async def cmd_sos1_show_key_calculation(_: str, ctx: CommandContext) -> None:
    """Helper to show the user how xorkey can be calculated from partial plaintext and partial ciphertext"""
    await stage1_show_xorkey_via_calculation(ctx)

async def cmd_sos1_autosolve(_: str, ctx: CommandContext) -> None:
    """Helper to write the stage 1 solution to the device."""
    await write_stage1_solution(ctx)


# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------
