"""
Walkthrough to solve the Sword of Secrets hardware CTF.

This is SPOILER RICH content.  Do NOT read if you wish
to enjoy the challenge of the CTF on your own!
"""

from __future__ import annotations

import asyncio

from ..command_registry import CommandContext, CommandRegistry
from enum import Enum
from typing import Literal, overload, Protocol
from . import sword_of_secrets as sos

# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_sword_of_secrets_spoilers_3(registry: CommandRegistry) -> None:
    """Populate *registry* with the three example commands."""
    registry.register(
        "sos3_1_brute_initial_padding", cmd_sos3_brute_force_initial_padding,
        "brute forces the last bytes of the penultimate AES-CBC block until the oracle indicates valid padding.  This is the first step (of four)in solving stage 3.",
        usage="sos3_1_brute_initial_padding",
        category="Sword of Secrets - Stage 3 Spoilers",
    )
    registry.register(
        "sos3_2_ensure_full_padding", cmd_sos3_get_to_full_padding,
        "Helper to get the stage 3 ciphertext to a state with valid 16-byte padding.  This is steps one and two (of four) in solving stage 3.",
        usage="sos3_2_ensure_full_padding",
        category="Sword of Secrets - Stage 3 Spoilers",        
    )
    registry.register(
        "sos3_3_decrypt_final_block", cmd_sos3_decrypt_final_block,
        "Helper to decrypt the final block of the stage 3 ciphertext.  This is steps one through three (of four)in solving stage 3",
        usage="sos3_3_decrypt_final_block",
        category="Sword of Secrets - Stage 3 Spoilers",
    )
    registry.register(
        "sos3_4_full_solution", cmd_sos3_full_solution,
        "Calculates solution for stage 3 and writes solution to flash.  This is steps one through four (of four) in solving stage 3.",
        usage="sos3_4_full_solution",
        category="Sword of Secrets - Stage 3 Spoilers",
    )
    registry.register(
        "sos3_autosolve", cmd_sos3_autosolve,
        "Writes the solution for stage 3 to the flash on the device.",
        usage="sos3_autosolve",
        category="Sword of Secrets - Stage 3 Spoilers",
    )

# ---------------------------------------------------------------------------
# Enums and types
# ---------------------------------------------------------------------------

# Define tri-state enum for oracle response: bad_padding, good_padding, and successful_response.
# We need to distinguish between these three cases because the stage 3 solution requires us to
# expand the padded size of the second sector, and we can only detect that by checking if the
# oracle response changes from "Invalid padding" to "Error in response.".
# However, there is a third case, where the padding is correct AND the response data is also
# correct, and which should not raise an error.

class OracleResponse(Enum):
    BAD_PADDING = 0
    GOOD_PADDING = 1
    MANUAL_REVIEW_REQUIRED = 2

class Stage3SolutionStage(Enum):
    NOT_STARTED = 0
    BRUTE_FORCE_INITIAL_PADDING = 1  # 16 max steps
    DETECT_PADDING_LENGTH = 2        # 256 max steps
    EXPANDING_PADDING = 3            # 16 bytes max, each with 256 max steps
    DECRYPTING_FINAL_BLOCK = 4        # 1 step (trivial)

# Define a struct-like class for tracking the progress of the stage 3 solution.
class Stage3SolutionProgress:
    def __init__(self) -> None:
        self.stage: Stage3SolutionStage = Stage3SolutionStage.NOT_STARTED
        self.stage_final_result: bool = False # if true, current_blob reflects a result
        self.brute_force_initial_padding_steps: int = 0
        self.detect_padding_length_steps: int = 0 # up to 16 iterations to detect the padding length
        self.current_known_padding_bytes: int = 0 # zero until padding length is detected, then 1-16
        self.next_padding_byte_iterations: int = 0 # cycles from zero ... 255, until found valid, then may return to zero as current_known_padding_bytes is incremented
        self.decrypting_final_block_done: bool = False # if this is true, it's essentially solved.
        self.current_blob: bytes | None = None # stage specific blob of bytes being worked on

class Stage3Callback(Protocol):
    async def __call__(self, ctx: CommandContext, progress: Stage3SolutionProgress) -> None: ...


# ---------------------------------------------------------------------------
# Global (const) data
# ---------------------------------------------------------------------------


STAGE3_ORIGINAL_CIPHERTEXT = bytes(
    # first AES-CBC block
    b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e' +
    b'\x96\xf5\x9e\x31\x72\x0b\xd9\x00' +
    # Corrupted byte ---------------^^

    # second AES-CBC block
    b'\xd7\x6b\xed\xc8\xd1\xd1\x47\x34' +
    b'\x81\x46\x9a\x24\xbf\xaa\x90\x22'
)
STAGE3_SOME_VALID_PADDING : dict[int, bytes] = {
    1:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xf5\x9e\x31\x72\x0b\xd9\x32\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    2:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xf5\x9e\x31\x72\x0b\xa6\x31\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    3:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xf5\x9e\x31\x72\x38\xa7\x30\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    4:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xf5\x9e\x31\x46\x3f\xa0\x37\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    5:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xf5\x9e\x04\x47\x3e\xa1\x36\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    6:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xf5\xa8\x07\x44\x3d\xa2\x35\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    7:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xc7\xa9\x06\x45\x3c\xa3\x34\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    8:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\xe6\xc8\xa6\x09\x4a\x33\xac\x3b\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    9:  bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x39\x47\xe7\xc9\xa7\x08\x4b\x32\xad\x3a\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    10: bytes( b'\xf7\x60\x4a\x1f\x5e\x96\x13\x44\xe4\xca\xa4\x0b\x48\x31\xae\x39\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    11: bytes( b'\xf7\x60\x4a\x1f\x5e\xaa\x12\x45\xe5\xcb\xa5\x0a\x49\x30\xaf\x38\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    12: bytes( b'\xf7\x60\x4a\x1f\x61\xad\x15\x42\xe2\xcc\xa2\x0d\x4e\x37\xa8\x3f\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    13: bytes( b'\xf7\x60\x4a\x40\x60\xac\x14\x43\xe3\xcd\xa3\x0c\x4f\x36\xa9\x3e\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    14: bytes( b'\xf7\x60\x77\x43\x63\xaf\x17\x40\xe0\xce\xa0\x0f\x4c\x35\xaa\x3d\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    15: bytes( b'\xf7\x5a\x76\x42\x62\xae\x16\x41\xe1\xcf\xa1\x0e\x4d\x34\xab\x3c\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
    16: bytes( b'\xc7\x45\x69\x5d\x7d\xb1\x09\x5e\xfe\xd0\xbe\x11\x52\x2b\xb4\x23\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22'),
}
STAGE3_FINAL_BLOCK_PLAINTEXT = bytes(
    # " 53R37 0x50000}\x01" -- one byte of PKCS#7 padding
    #   ^^^^^^^^^^^^^----- The solution string is "53R37 0x50000"
    b'\x20\x35\x33\x52\x33\x37\x20\x30\x78\x35\x30\x30\x30\x30\x7d\x01'
)
STAGE3_SOLVED_FLASH_DATA = bytes(
    b'\x20\x00\x00\x00' +
    # first AES-CBC block (corrected byte)
    b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e' +
    b'\x96\xf5\x9e\x31\x72\x0b\xd9\x32' +
    # second AES-CBC block
    b'\xd7\x6b\xed\xc8\xd1\xd1\x47\x34' +
    b'\x81\x46\x9a\x24\xbf\xaa\x90\x22' +
    # Solution cleartext... no PKCS#7
    b'\x35\x33\x52\x33\x37\x20\x30\x78' +
    b'\x35\x30\x30\x30\x30'
)

async def Stage3ValidateImplementationCallback(ctx: CommandContext, progress: Stage3SolutionProgress) -> None:
    if not progress.stage_final_result:
        return
    if progress.current_blob is None:
        # allows asserting current_blob is non-null, if stage_final_result is True
        ctx.print_error(f"ERROR in stage {progress.stage}: No data blob for stage ")
    elif progress.stage == Stage3SolutionStage.BRUTE_FORCE_INITIAL_PADDING:
        if len(progress.current_blob) != len(STAGE3_ORIGINAL_CIPHERTEXT):
            ctx.print_error(f"ERROR in stage {progress.stage}: blob length of {len(progress.current_blob)}, expected {len(STAGE3_ORIGINAL_CIPHERTEXT)}")
    elif progress.stage == Stage3SolutionStage.DETECT_PADDING_LENGTH:
        if len(progress.current_blob) != len(STAGE3_ORIGINAL_CIPHERTEXT):
            ctx.print_error(f"ERROR in stage {progress.stage}: blob length of {len(progress.current_blob)}, expected {len(STAGE3_ORIGINAL_CIPHERTEXT)}")
    elif progress.stage == Stage3SolutionStage.EXPANDING_PADDING:
        if len(progress.current_blob) != len(STAGE3_ORIGINAL_CIPHERTEXT):
            ctx.print_error(f"ERROR in stage {progress.stage}: blob length of {len(progress.current_blob)}, expected {len(STAGE3_ORIGINAL_CIPHERTEXT)}")
        idx = progress.current_known_padding_bytes
        if progress.current_blob == STAGE3_SOME_VALID_PADDING[idx]:
            ctx.print(f"Validated padding length {idx} directly")
        elif progress.current_blob == STAGE3_SOME_VALID_PADDING[idx+1]:
            ctx.print(f"Validated padding length {idx} using {idx+1}")
        else:
            ctx.print_error(f"ERROR in stage {progress.stage}: data mismatch for padding idx {idx}")
    elif progress.stage == Stage3SolutionStage.DECRYPTING_FINAL_BLOCK:
        if progress.current_blob != STAGE3_FINAL_BLOCK_PLAINTEXT:
            ctx.print_error(f"ERROR in stage {progress.stage}: plaintext result mismatch")
    elif progress.stage == Stage3SolutionStage.NOT_STARTED:
        pass
    else:
        ctx.print_warning(f"ERROR in unknown stage {progress.stage} -- stage not defined")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


async def clear_current_line(ctx: CommandContext, chars_to_clear: int) -> None:
    """Helper to clear the current line in the console."""
    ctx.print('\b' * chars_to_clear, end='') # move cursor back
    ctx.print(' '  * chars_to_clear, end='') # overwrite with spaces
    ctx.print('\b' * chars_to_clear, end='', flush=True) # move cursor back again

# TODO: Define valid_pkcs7_padding_length (via hints) as [1..16].
# TODO: use overloads to define hints that, if throw_if_no_padding is True,
#       then range of results is:     [1..16] aka valid_pkcs7_padding_length
#       else range of results is: 0 | [1..16] aka valid_pkcs7_padding_length
async def get_pkcs7_padding_length(ctx: CommandContext, plaintext: bytes, throw_if_no_padding: bool = True ) -> int:
    if len(plaintext) != 0x10:
        raise ValueError(f"Unexpected plaintext length: 0x{len(plaintext):02x} (expected 0x10)")
    
    padding_length = plaintext[-1]
    if padding_length >= 1 and padding_length <= 0x10:
        if all(b == padding_length for b in plaintext[-padding_length:]):
            return padding_length

    if throw_if_no_padding:
        raise ValueError(f"Invalid PKCS#7 padding: last byte indicates {padding_length} bytes of padding, but the last {padding_length} bytes are not all 0x{padding_length:02x}")
    return 0


async def write_stage3_ciphertext(ctx: CommandContext, ciphertext: bytes, erase: bool = True) -> None:
    datalen = len(ciphertext)
    if datalen % 0x10 != 0:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected multiple of 0x10)")
    if datalen < 0x20:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at least 0x20)")
    if datalen > 0x80:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at most 0x80)")
    sector_data : bytearray = bytearray(
        int.to_bytes(len(ciphertext), length=4, byteorder='little') +
        ciphertext
    )
    if erase:
        await sos.erase_flash_4k(0x30000, ctx)
    await sos.write_flash(0x30000, sector_data, ctx)

async def stage3_check_oracle(ctx: CommandContext) -> OracleResponse:
    """Helper to check the stage 3 padding oracle response."""
    multilines = await sos.util_send_command("SOLVE", ctx)

    if len(multilines) != 3:
        raise ValueError(f"Unexpected response length: {len(multilines)} lines (expected 3)")
    if not multilines[0].startswith("MAGICLIB{"):
        raise ValueError(f"Unexpected response line 0: `{multilines[0]}` (expected to start with `MAGICLIB{{`)")
    if not multilines[0].endswith("}"):
        raise ValueError(f"Unexpected response line 0: `{multilines[0]}` (expected to end with `}}`)")
    if not multilines[1].startswith("MAGICLIB{"):
        raise ValueError(f"Unexpected response line 1: `{multilines[1]}` (expected to start with `MAGICLIB{{`)")
    if not '}' in multilines[1][-2:]:
        raise ValueError(f"Unexpected response line 1: `{multilines[1]}` (expected to find `}}` in last two characters)")
    if multilines[2].strip() == "Invalid padding":
        return OracleResponse.BAD_PADDING
    if multilines[2].strip() == "Error in response.":
        return OracleResponse.GOOD_PADDING
    ctx.print_warning(f"Unexpected oracle response: `{multilines[2]}` (expected `Invalid padding` or `Error in response.`)")
    return OracleResponse.MANUAL_REVIEW_REQUIRED

@overload
async def stage3_brute_force_initial_padding_destructive(ctx: CommandContext, initial_ciphertext: bytes) -> bytes: ...
@overload
async def stage3_brute_force_initial_padding_destructive(ctx: CommandContext, initial_ciphertext: bytes, callback: Literal[None]) -> bytes: ...
@overload
async def stage3_brute_force_initial_padding_destructive(ctx: CommandContext, initial_ciphertext: bytes, callback: Stage3Callback) -> bytes: ...

async def stage3_brute_force_initial_padding_destructive(ctx: CommandContext, initial_ciphertext: bytes, callback: Stage3Callback | None = None) -> bytes:
    """
    The sector at 0x30000 is overwritten by this function.

    The provided initial_ciphertext is used as the
    initial ciphertext (WITHOUT explicit length field).

    The penultimate AES block has its last byte exhaustively
    changed until the oracle indicates that a valid padding
    was found.

    ciphertext with valid padding is returned to the caller.

    NOTE: there is no guarantee that the returned ciphertext
          will only use a single padding byte.  It is the
          caller's responsibility to check the padding length.

    There are no guarantees about the state of the data at
    0x30000 after calling this function.
    """

    if len(initial_ciphertext) % 0x10 != 0:
        raise ValueError(f"Unexpected initial ciphertext length: 0x{len(initial_ciphertext):02x} (expected multiple of 0x10)")
    if len(initial_ciphertext) < 0x20:
        raise ValueError(f"Unexpected initial ciphertext length: 0x{len(initial_ciphertext):02x} (expected at least 0x20)")
    if len(initial_ciphertext) > 0x80:
        raise ValueError(f"Unexpected initial ciphertext length: 0x{len(initial_ciphertext):02x} (expected at most 0x80)")

    tmp : bytearray = bytearray(
        initial_ciphertext
    )

    TEST_BYTE_OFFSET = len(tmp) - 0x20 + 0x0F # last byte of penultimate block
    tmp[TEST_BYTE_OFFSET] = 0xFF # set to 0xFF as starting value for efficient traversal

    progress : Stage3SolutionProgress = Stage3SolutionProgress()
    progress.stage = Stage3SolutionStage.BRUTE_FORCE_INITIAL_PADDING
    progress.brute_force_initial_padding_steps = 0
    progress.current_blob = bytes(tmp)
    if callback is not None:
        await callback(ctx, progress)

    await write_stage3_ciphertext(ctx, tmp)

    for next_test in sos.FLASH_WALK:
        # update and write the next test value to the flash
        need_erase = (tmp[TEST_BYTE_OFFSET] & next_test != next_test)
        tmp[TEST_BYTE_OFFSET] = next_test

        progress.brute_force_initial_padding_steps += 1
        progress.current_blob = bytes(tmp)
        if callback is not None:
            await callback(ctx, progress)

        await write_stage3_ciphertext(ctx, tmp, erase=need_erase)

        # check the oracle response ... end when padding is OK
        resp = await stage3_check_oracle(ctx)
        if resp == OracleResponse.GOOD_PADDING:
            progress.stage_final_result = True
            progress.current_blob = bytes(tmp)
            if callback is not None:
                await callback(ctx, progress)
            return bytes(tmp)
        elif resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
            raise ValueError("Unexpected oracle response during padding expansion. Please review manually.")

    raise ValueError("Could not find valid padding byte value. Internal error?")


@overload
async def stage3_detect_padding_length_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes) -> int: ...
@overload
async def stage3_detect_padding_length_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, callback: Literal[None]) -> int: ...
@overload
async def stage3_detect_padding_length_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, callback: Stage3Callback) -> int: ...

async def stage3_detect_padding_length_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, callback: Stage3Callback | None = None) -> int:
    """Helper to detect count of padding bytes for current stage 3 flash contents."""

    progress : Stage3SolutionProgress = Stage3SolutionProgress()
    progress.stage = Stage3SolutionStage.DETECT_PADDING_LENGTH
    progress.detect_padding_length_steps = 0

    datalen = len(some_valid_padding_ciphertext)
    if datalen % 0x10 != 0:
        raise ValueError(f"Unexpected data length format: 0x{datalen:02x} (expected multiple of 0x10)")
    if datalen < 0x20:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at least 0x20)")
    if datalen > 0x80:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at most 0x80)")

    await write_stage3_ciphertext(ctx, some_valid_padding_ciphertext)

    # This function presumes that the flash currently contains data with valid PKCS#7 padding
    resp = await stage3_check_oracle(ctx)
    if resp == OracleResponse.BAD_PADDING:
        raise ValueError("Current padding is incorrect. Unable to proceed.")
    if resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
        raise ValueError("Unexpected oracle response. Please review manually.")

    tmp = bytearray(some_valid_padding_ciphertext)
    penultimate_block_offset = len(tmp) - 0x20
    
    # Detect how many padding bytes are currently correct.
    # starting at offset 0 of penultimate block, change the byte, check oracle response
    # NOTE: Could optimize this by bisecting instead of linear search,
    #       but let's keep it simple since we expect at most 16 iterations here.
    for offset in range(0, 0x10):
        if callback is not None:
            progress.detect_padding_length_steps = offset
            progress.current_blob = bytes(tmp)
            await callback(ctx, progress)
        else:
            ctx.print(f"Checking if byte 0x{offset:02x} is padding...")
        byte_offset = penultimate_block_offset + offset
        tmp[byte_offset] ^= 0xFF # flip all bits to ensure bits changed to invalid padding

        await write_stage3_ciphertext(ctx, tmp)

        resp = await stage3_check_oracle(ctx)
        if resp == OracleResponse.BAD_PADDING:
            progress.stage_final_result = True
            progress.detect_padding_length_steps = offset
            progress.current_blob = bytes(tmp)
            if callback is not None:
                await callback(ctx, progress)
            return 0x10 - offset
        if resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
            raise ValueError("Unexpected oracle response during padding byte detection. Please review manually.")

    raise ValueError("Could not discover padding byte count. Please review manually.")


@overload
async def stage3_calculate_one_byte_padding_expansion_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, valid_padding_byte_count: int) -> bytes: ...
@overload
async def stage3_calculate_one_byte_padding_expansion_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, valid_padding_byte_count: int, callback: Literal[None]) -> bytes: ...
@overload
async def stage3_calculate_one_byte_padding_expansion_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, valid_padding_byte_count: int, callback: Stage3Callback) -> bytes: ...

async def stage3_calculate_one_byte_padding_expansion_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, valid_padding_byte_count: int, callback: Stage3Callback | None = None) -> bytes:
    """
    The sector at 0x30000 is overwritten by this function.

    The provided some_valid_padding_ciphertext is used as
    the initial ciphertext that contains valid PKCS#7 padding,
    and valid_padding_byte_count indicates how many bytes of
    PKCS#7 exist in the provided some_valid_padding_ciphertext.

    On success, returns a modified ciphertext of the same
    length, where the number of valid PKCS#7 padding bytes
    has been increased by one.

    If the padding is already 16 bytes long, raise an error
    since the padding cannot be expanded.

    There are no guarantees about the state of the data at
    0x30000 after calling this function.
    """

    if len(some_valid_padding_ciphertext) % 0x10 != 0:
        raise ValueError(f"Unexpected initial ciphertext length: 0x{len(some_valid_padding_ciphertext):02x} (expected multiple of 0x10)")
    if len(some_valid_padding_ciphertext) < 0x20:
        raise ValueError(f"Unexpected initial ciphertext length: 0x{len(some_valid_padding_ciphertext):02x} (expected at least 0x20)")
    if len(some_valid_padding_ciphertext) > 0x80:
        raise ValueError(f"Unexpected initial ciphertext length: 0x{len(some_valid_padding_ciphertext):02x} (expected at most 0x80)")
    if valid_padding_byte_count < 1 or valid_padding_byte_count > 16:
        raise ValueError(f"Invalid valid_padding_byte_count value: {valid_padding_byte_count} (expected 1-16)")

    padding_byte_count = valid_padding_byte_count + 1
    penultimate_block_offset = len(some_valid_padding_ciphertext) - 0x20
    tmp = bytearray(some_valid_padding_ciphertext)

    # which byte will be exhaustively changed to find the plaintext with larger padding?
    TEST_BYTE_OFFSET = penultimate_block_offset + 0x10 - padding_byte_count

    # Modify the current PCKS#7 padding bytes from N to N+1:
    XOR_EXISTING_PADDING = padding_byte_count ^ (padding_byte_count - 1)
    for i in range(penultimate_block_offset, penultimate_block_offset+0x10):
        if i == TEST_BYTE_OFFSET:
            # this is the next byte to be find a valid padding encoding for
            # start value doesn't really matter ... overwritten below
            tmp[i] = 0xFF
        elif i > TEST_BYTE_OFFSET:
            # have to adjust the existing padding bytes
            tmp[i] ^= XOR_EXISTING_PADDING

    progress : Stage3SolutionProgress = Stage3SolutionProgress()
    progress.stage = Stage3SolutionStage.EXPANDING_PADDING
    progress.current_known_padding_bytes = padding_byte_count - 1
    progress.next_padding_byte_iterations = 0
    progress.current_blob = bytes(tmp)
    if callback is not None:
        await callback(ctx, progress)

    # the FLASH_WALK array provides a sequence of byte values that can be
    # efficiently written to the flash without always first erasing the
    # sector.  (73 erases vs. 256 erases)
    step_out_of_256 : int = 0
    for next_test in sos.FLASH_WALK:
        # update and write the next test value to the flash
        # always erase the first iteration ... no knowledge of existing flash data
        need_erase : bool = step_out_of_256 == 0
        # Erase is also needed if need to convert at least one
        # existing bit from 0 --> 1 ... only possible via erase
        if tmp[TEST_BYTE_OFFSET] & next_test != next_test:
            need_erase = True
        # Set the byte to that next value
        tmp[TEST_BYTE_OFFSET] = next_test

        if callback is not None:
            progress.next_padding_byte_iterations = step_out_of_256 + 1
            progress.current_blob = bytes(tmp)
            await callback(ctx, progress)

        await write_stage3_ciphertext(ctx, tmp, erase=need_erase)

        # check the oracle response ... end when padding is OK
        resp = await stage3_check_oracle(ctx)
        if resp == OracleResponse.GOOD_PADDING:
            # SUCCESS! return the valid ciphertext with the expanded padding
            if callback is not None:
                progress.stage_final_result = True
                await callback(ctx, progress)
            return bytes(tmp)
        elif resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
            raise ValueError("Unexpected oracle response during padding expansion. Please review manually.")
        step_out_of_256 = step_out_of_256 + 1

    # unexpected ... should have found a valid padding.
    # await sos.util_hex_dump(ctx, baseline[:0x04 + datalen], 0x30000)
    raise ValueError(f"Could not find valid padding byte value for padding byte count {padding_byte_count}. Please review manually.")

@overload
async def stage3_ensure_16_byte_padding_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes) -> bytes: ...
@overload
async def stage3_ensure_16_byte_padding_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, callback: Literal[None]) -> bytes: ...
@overload
async def stage3_ensure_16_byte_padding_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, callback: Stage3Callback) -> bytes: ...

async def stage3_ensure_16_byte_padding_destructive(ctx: CommandContext, some_valid_padding_ciphertext: bytes, callback: Stage3Callback | None = None) -> bytes:
    """
    Helper function to expand the padding of the given
    some_valid_padding_ciphertext to 16 bytes.

    The sector at 0x30000 is overwritten by this function,
    and there are no guarantees about the state of that
    4k sector after calling this function.

    On success, returns a modified ciphertext of the same
    length, where the last AES block of the plaintext is
    entirely used for PKCS#7 padding.  Note that this method
    requires corrupting the plaintext for the block just
    prior to the padding block.

    Thus, the last plaintext block corresponding to the
    returned ciphertextwill have the contents:
    `b'\x10' * 0x10`
    """
    # Determine how many valid padding bytes from the brute-force step
    padding_count = await stage3_detect_padding_length_destructive(ctx, some_valid_padding_ciphertext, callback)

    padding_dict: dict[int, bytes] = {}
    padding_dict[padding_count] = some_valid_padding_ciphertext

    # Now expand until the entire block is padding
    while padding_count < 16:

        if callback is None:
            ctx.print(f"Expanding padding from {padding_count:2d} bytes to {(padding_count + 1):2d} bytes...")
            await sos.util_hex_dump(ctx, some_valid_padding_ciphertext, 0x30004)

        next = await stage3_calculate_one_byte_padding_expansion_destructive(ctx, some_valid_padding_ciphertext, padding_count, callback)
        padding_count = padding_count + 1
        padding_dict[padding_count] = next
        some_valid_padding_ciphertext = next

    if 16 not in padding_dict:
        raise AssertionError("Logic error: failed to obtain 16-byte padding ciphertext after expansion loop.")

    if callback is None:
        ctx.print("Successfully expanded padding to 16 bytes!")
        await sos.util_hex_dump(ctx, padding_dict[16], 0x30004)
        ctx.print("\n")
        for key, value in padding_dict.items():
            ctx.print(f"Padding byte count: {key:2d}  ", end='')
            await sos.util_hex_dump(ctx, value[-32:16], 0x30004)

    # return the ciphertext that results in a full 16-byte padding block
    return padding_dict[16]

@overload
async def stage3_decrypt_final_aes_block(ctx: CommandContext, original_valid_ciphertext: bytes, ciphertext_with_full_padding_block: bytes) -> bytes: ...
@overload
async def stage3_decrypt_final_aes_block(ctx: CommandContext, original_valid_ciphertext: bytes, ciphertext_with_full_padding_block: bytes, callback: Literal[None]) -> bytes: ...
@overload
async def stage3_decrypt_final_aes_block(ctx: CommandContext, original_valid_ciphertext: bytes, ciphertext_with_full_padding_block: bytes, callback: Stage3Callback) -> bytes: ...

async def stage3_decrypt_final_aes_block(ctx: CommandContext, original_valid_ciphertext: bytes, ciphertext_with_full_padding_block: bytes, callback: Stage3Callback | None = None) -> bytes:
    """
    Helper function to decrypt the original contents of the ultimate AES block.

    This function does not access the device.
    """

    if len(original_valid_ciphertext) % 0x10 != 0:
        raise ValueError(f"Unexpected original_valid_ciphertext length: 0x{len(original_valid_ciphertext):02x} (expected multiple of 0x10)")
    if len(original_valid_ciphertext) < 0x20:
        raise ValueError(f"Unexpected original_valid_ciphertext length: 0x{len(original_valid_ciphertext):02x} (expected at least 0x20)")
    if len(original_valid_ciphertext) > 0x80:
        raise ValueError(f"Unexpected original_valid_ciphertext length: 0x{len(original_valid_ciphertext):02x} (expected at most 0x80)")
    if len(ciphertext_with_full_padding_block) != len(original_valid_ciphertext):
        raise ValueError(f"Unexpected ciphertext length mismatch: original_valid_ciphertext length is 0x{len(original_valid_ciphertext):02x}, but ciphertext_with_full_padding_block length is 0x{len(ciphertext_with_full_padding_block):02x} (expected to be the same)")  
    if ciphertext_with_full_padding_block[-0x10:] != original_valid_ciphertext[-0x10:]:
        raise ValueError("Unexpected ciphertext mismatch: the last 16 bytes of ciphertext_with_full_padding_block do not match the last 16 bytes of original_valid_ciphertext (expected to be the same)")

    progress : Stage3SolutionProgress = Stage3SolutionProgress()
    progress.stage = Stage3SolutionStage.DECRYPTING_FINAL_BLOCK
    progress.current_blob = bytes(ciphertext_with_full_padding_block)
    if callback is not None:
        await callback(ctx, progress)

    """
    Known:
        * orig == original_valid_ciphertext
        * padded == ciphertext_with_full_padding_block
        * orig[ last_block ] === padded[ last_block ]
        * AES_CBC_D( padded[ last_block ]) === b'\x10' * 0x10
        * AES_CBC_D( padded[ last_block ] ) ===
          Dk( padded[ last_block ] ) XOR padded[ prior_block ]
        * AES_CBC_D( orig[ last_block ] ) ===
          Dk( orig[ last_block ] ) XOR orig[ prior_block]
    Goal:
        Determine AES_CBC_D( orig[ last_block ] )
    Solution:
        A. Solve for Dk( padded[ last_block ] ):
            1. Start with a definition from above:
               AES_CBC_D( padded[ last_block ] )          === Dk( padded[ last_block ] ) XOR padded[ prior_block ]
            2. replace AES_CBC_D( padded[ last_block ] ) with its known plaintext
               (b'0x10' * 0x10)                           === Dk( padded[ last_block ] ) XOR padded[ prior_block ]
            3. XOR both sides with padded[ prior_block ]
               (b'0x10' * 0x10) XOR padded[ prior_block ] === Dk( padded[ last_block ] ) XOR padded[ prior_block ] XOR padded[ prior_block ]
            4. Simplify since  `A ^ A === 0`
               (b'0x10' * 0x10) XOR padded[ prior_block ] === Dk( padded[ last_block ] )
            5. Swap the two sides for clarity
               Dk( padded[ last_block ] )                 === (b'0x10' * 0x10) XOR padded[ prior_block ] 
        B. Solve for AES_CBC_D( orig[ last_block ] ):
            1. Start with a definition from above:
               AES_CBC_D( orig[ last_block ] ) === Dk( orig  [ last_block ] ) XOR orig[ prior_block ]
            2. Since orig[ last_block ] === padded[ last_block ], can swap it out
               AES_CBC_D( orig[ last_block ] ) === Dk( padded[ last_block ] ) XOR orig[ prior_block ]
            3. Replace Dk( padded[ last_block ] ) with the result from part A
               AES_CBC_D( orig[ last_block ] ) === (b'0x10' * 0x10) XOR padded[ prior_block ] XOR orig[ prior_block ]
            4. All values on the right-hand side are known values ...
               allowing AES_CBC_D( orig[ last_block ] ) to be calculated
               without ever knowing the AES key!
    """
    """
    Thus, original[last_block] can be decrypted using only known values:
        (b'0x10' * 0x10) XOR padded[ prior_block ] XOR orig[ prior_block ]
    """
    
    idx_pb = len(ciphertext_with_full_padding_block) - 0x20

    # Calculate 0x10 ^ orig ^ fully_padded for each byte of the PENULTIMATE block,
    # as described in the above proof.
    result = bytes(
        0x10 ^ a ^ b for a, b in zip(
            ciphertext_with_full_padding_block[idx_pb:idx_pb + 0x10],
            original_valid_ciphertext[idx_pb:idx_pb + 0x10]
        )
    )

    if callback is not None:
        progress.current_blob = bytes(result)
        progress.stage_final_result = True
        await callback(ctx, progress)

    # NOTE: the result may include PKCS#7 padding bytes.
    #       It's the caller's responsibility to check for
    #       and remove that padding, if it exists, if desired.
    return result

# ---------------------------------------------------------------------------
# Commands registered with serial console
# ---------------------------------------------------------------------------

async def Stage3GeneralCallback(ctx: CommandContext, progress: Stage3SolutionProgress) -> None:
    if progress.stage_final_result:
        assert progress.current_blob is not None, "Logic error: stage_final_result is True but current_blob is None"
        await clear_current_line(ctx, 80)
        match progress.stage:
            case Stage3SolutionStage.BRUTE_FORCE_INITIAL_PADDING:
                ctx.print("Successfully found a valid padding byte! Resulting ciphertext with valid padding:")
                await sos.util_hex_dump(ctx, progress.current_blob, 0x30004)
            case Stage3SolutionStage.DETECT_PADDING_LENGTH:
                ctx.print(f"Padding Length == {0x10 - progress.detect_padding_length_steps:2d} bytes")
            case Stage3SolutionStage.EXPANDING_PADDING:
                ctx.print(f"Padding for length {(progress.current_known_padding_bytes+1):2d}:")
                await sos.util_hex_dump(ctx, progress.current_blob, 0x30004)
            case Stage3SolutionStage.DECRYPTING_FINAL_BLOCK:
                ctx.print("Decryption complete! Final block plaintext:")
                await sos.util_hex_dump(ctx, progress.current_blob, 0)
            case Stage3SolutionStage.NOT_STARTED:
                ctx.print_warning("Logic error: stage_final_result is True but stage is NOT_STARTED")
            case _:
                ctx.print_warning(f"Unknown progress stage: {progress.stage}")
        return

    if progress.stage == Stage3SolutionStage.BRUTE_FORCE_INITIAL_PADDING:
        if progress.brute_force_initial_padding_steps == 0:
            ctx.print("Brute-forcing initial padding byte: ", end='', flush=True)
        else:
            ctx.print('\b' * 7, end='')
        ctx.print(f"{progress.brute_force_initial_padding_steps:3d}/256", end='', flush=True)
        return
    elif progress.stage == Stage3SolutionStage.DETECT_PADDING_LENGTH:
        if progress.detect_padding_length_steps == 0:
            ctx.print("Detecting padding length: ", end='', flush=True)
        else:
            ctx.print('\b' * 7, end='')
        ctx.print(f"{progress.detect_padding_length_steps:3d}/ 16", end='', flush=True)
        return
    elif progress.stage == Stage3SolutionStage.EXPANDING_PADDING:
        if progress.next_padding_byte_iterations == 0:
            ctx.print(f"Expanding padding from {progress.current_known_padding_bytes:2d} to {(progress.current_known_padding_bytes + 1):2d} bytes: ", end='', flush=True)
        else:
            ctx.print('\b' * 7, end='')
        ctx.print(f"{progress.next_padding_byte_iterations:3d}/256", end='', flush=True)
        return
    elif progress.stage == Stage3SolutionStage.DECRYPTING_FINAL_BLOCK:
        ctx.print("\nDecrypting final block...", end='', flush=True)
    elif progress.stage == Stage3SolutionStage.NOT_STARTED:
        pass
    else:
        ctx.print_warning(f"Unknown progress stage: {progress.stage}")



async def cmd_sos3_autosolve(args: str, ctx: CommandContext) -> None:
    """Helper to write the stage 3 solution to the device."""
    with ctx.shell.suppress_serial_output():
        # this is the data that needs to be written to the device to solve stage 3 of the CTF
        await sos.erase_flash_4k(0x30000, ctx)
        await sos.write_flash(0x30000, STAGE3_SOLVED_FLASH_DATA, ctx)
        ctx.print_info("Stage 3 solution written to flash at address 0x30000:")
        await sos.util_hex_dump(ctx, STAGE3_SOLVED_FLASH_DATA, 0x30000)

async def cmd_sos3_brute_force_initial_padding(args: str, ctx: CommandContext) -> None:
    """Brute-force correction of the intentional corruption of the
    last byte of the penultimate AES-CBC block"""
    if args.strip() != "":
        raise ValueError(f"Unexpected argument: `{args.strip()}` (no arguments supported / expected)")

    with ctx.shell.suppress_serial_output():
        with sos.util_timer(ctx, f"Brute-force initial padding byte | "):
            result = await stage3_brute_force_initial_padding_destructive(ctx, STAGE3_ORIGINAL_CIPHERTEXT, Stage3GeneralCallback)
            ctx.print("Brute-force complete. Resulting ciphertext with valid padding:")
            await sos.util_hex_dump(ctx, result, 0x30004)

async def cmd_sos3_get_to_full_padding(args: str, ctx: CommandContext) -> None:
    """Helper to get the stage 3 ciphertext to a state with valid 16-byte padding."""
    quick_mode = False
    if args.strip() != "":
        if args.strip() == "-q":
            quick_mode = True
        else:
            raise ValueError(f"Unexpected argument: `{args.strip()}` (expected `-q` or empty)")

    with ctx.shell.suppress_serial_output():
        with sos.util_timer(ctx, f"getting to full padding"):
            if quick_mode:
                ctx.print("Quick mode enabled: only performing expansion from corrected ciphertext to 16-byte padding.")
                some_valid_padding = STAGE3_SOME_VALID_PADDING[1]
            else:
                some_valid_padding = await stage3_brute_force_initial_padding_destructive(ctx, STAGE3_ORIGINAL_CIPHERTEXT, Stage3GeneralCallback)
            ensured_16_bytes_padding = await stage3_ensure_16_byte_padding_destructive(ctx, some_valid_padding, Stage3GeneralCallback)
        await sos.util_hex_dump(ctx, ensured_16_bytes_padding, 0x30004)

async def cmd_sos3_decrypt_final_block(args: str, ctx: CommandContext) -> None:
    """Helper to decrypt the final block of the stage 3 ciphertext."""
    quick_mode = False
    if args.strip() != "":
        if args.strip() == "-q":
            quick_mode = True
        else:
            raise ValueError(f"Unexpected argument: `{args.strip()}` (expected `-q` or empty)")

    with ctx.shell.suppress_serial_output():
        with sos.util_timer(ctx, f"decrypting final block"):
            if quick_mode:
                ctx.print("Quick mode enabled: only performing decryption step.")
                some_valid_padding = STAGE3_SOME_VALID_PADDING[1]
                ensured_16_bytes_padding = STAGE3_SOME_VALID_PADDING[16]
            else:
                some_valid_padding = await stage3_brute_force_initial_padding_destructive(ctx, STAGE3_ORIGINAL_CIPHERTEXT, Stage3GeneralCallback)
                ensured_16_bytes_padding = await stage3_ensure_16_byte_padding_destructive(ctx, some_valid_padding, Stage3GeneralCallback)
            decrypted = await stage3_decrypt_final_aes_block(ctx, STAGE3_ORIGINAL_CIPHERTEXT, ensured_16_bytes_padding, Stage3GeneralCallback)
            if len(decrypted) != 0x10:
                raise ValueError(f"Unexpected decrypted block length: 0x{len(decrypted):02x} (expected 0x10)")
        ctx.print("Decryption complete! Final block plaintext:")
        await sos.util_hex_dump(ctx, decrypted, 0x30004 + len(STAGE3_ORIGINAL_CIPHERTEXT) - 0x10)

async def cmd_sos3_full_solution(args: str, ctx: CommandContext) -> None:
    """Helper to decrypt the final block of the stage 3 ciphertext."""
    quick_mode = False
    if args.strip() != "":
        if args.strip() == "-q":
            quick_mode = True
        else:
            raise ValueError(f"Unexpected argument: `{args.strip()}` (expected `-q` or empty)")

    with ctx.shell.suppress_serial_output():
        with sos.util_timer(ctx, f"full stage3 solution"):
            callback : Stage3Callback = Stage3GeneralCallback
            # callback = Stage3ValidateImplementationCallback

            if quick_mode:
                ctx.print("Quick mode enabled: starting with decrypted plaintext of final block.")
                some_valid_padding = STAGE3_SOME_VALID_PADDING[1]
                ensured_16_bytes_padding = STAGE3_SOME_VALID_PADDING[16]
                decrypted = STAGE3_FINAL_BLOCK_PLAINTEXT
            else:
                some_valid_padding = await stage3_brute_force_initial_padding_destructive(ctx, STAGE3_ORIGINAL_CIPHERTEXT, callback)
                ensured_16_bytes_padding = await stage3_ensure_16_byte_padding_destructive(ctx, some_valid_padding, callback)
                decrypted = await stage3_decrypt_final_aes_block(ctx, some_valid_padding, ensured_16_bytes_padding, callback)
            if len(decrypted) != 0x10:
                raise ValueError(f"Unexpected decrypted block length: 0x{len(decrypted):02x} (expected 0x10)")
            # validate decrypted has valid PKCS#7 padding
            padding_length = await get_pkcs7_padding_length(ctx, decrypted)
            # drop the padding
            cleartext = decrypted[:-padding_length]
            # drop the space and the trailing '}'
            secret_value = cleartext[1:-1]

            # now write the ciphertext length + original ciphertext + secret cleartext
            sector_data : bytes = bytes(
                int.to_bytes(len(STAGE3_ORIGINAL_CIPHERTEXT), length=4, byteorder='little') +
                some_valid_padding +
                secret_value
            )
            ctx.print("Writing final solution:")
            await sos.util_hex_dump(ctx, sector_data, 0x30000)
            await sos.erase_flash_4k(0x30000, ctx)
            await sos.write_flash(0x30000, sector_data, ctx)
            ctx.print("That should move to the next stage!")

# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------
