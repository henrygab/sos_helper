"""
Walkthrough to solve the Sword of Secrets hardware CTF.

This is SPOILER RICH content.  Do NOT read if you wish
to enjoy the challenge of the CTF on your own!
"""

from __future__ import annotations
from typing import Awaitable, Callable, List, TypeAlias

from ..command_registry import CommandContext, CommandRegistry
from . import sword_of_secrets            as sos
from . import sword_of_secrets_spoilers_1 as sos1
from . import sword_of_secrets_spoilers_2 as sos2
from . import sword_of_secrets_spoilers_3 as sos3

# ---------------------------------------------------------------------------
# Enums and types
# ---------------------------------------------------------------------------

Stage4CipherTextWriterType: TypeAlias = Callable[[CommandContext], Awaitable[None]]
Stage4OneTimeBFScriptWriterType: TypeAlias = Callable[[CommandContext], Awaitable[None]]

# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_sword_of_secrets_spoilers_4(registry: CommandRegistry) -> None:
    """Populate *registry* with the three example commands."""
    registry.register(
        "sos4_1_replace_code_ciphertext", cmd_sos4_1_replace_code_ciphertext,
        "brute forces the last bytes of the penultimate AES-CBC block until the oracle indicates valid padding.  This is the first step (of four)in solving stage 4.",
        usage="sos4_1_brute_initial_padding",
        category="Sword of Secrets - Stage 4 Spoilers",
    )
    registry.register(
        "sos4_autosolve", cmd_sos4_autosolve,
        "Writes the solution for stage 4 to the flash on the device.",
        usage="sos4_autosolve",
        category="Sword of Secrets - Stage 4 Spoilers",
    )
    registry.register(
        "sos4_bf_prep", cmd_sos4_prepare_for_BF_data_dump,
        "Prepares the device for running sos4_bf_dump",
        usage="sos4_bf_prep",
        category="Sword of Secrets - Stage 4 Spoilers",
    )
    registry.register(
        "sos4_bf_dump", cmd_sos4_bf_dump,
        "Runs a BF script to dump bytes from RAM (either before or after the `tape` variable)",
        usage="sos4_bf_dump <before|after|both>",
        category="Sword of Secrets - Stage 4 Spoilers",
    )
    registry.register(
        "full_solution", cmd_full_solution,
        "Times solving the entire Sword of Secrets from start to finish.",
        usage="full_solution",
        category="Sword of Secrets",
    )

# ---------------------------------------------------------------------------
# Global (const) data
# ---------------------------------------------------------------------------

STAGE4_ORIGINAL_CIPHERTEXT = bytes(
    # Setup encrypts 50 (0x32) bytes
    # Thus, know there's 0x0E PKCS7 padding bytes
    b'\x8e\x3c\x5a\xf5\x56\x82\xd4\x0c' +
    b'\x5a\x26\xdb\x1d\x71\xf3\xcf\x11' +

    b'\x5c\x71\x14\xfa\xc8\x30\xdb\xcd' +
    b'\xc9\x88\x58\x42\xce\x68\x9c\xc6' +

    b'\xb5\x78\x94\x3d\x59\x1f\xa9\xd4' +
    b'\xe2\xbc\x7b\x33\x45\xc5\x99\x8e' +

    b'\xc8\x4e\xb4\x4e\x38\xa2\xaa\x12' +
    b'\xa8\x78\xfb\x43\x8d\x7f\x8a\xcd'
)

STAGE4_START_OF_ORIGINAL_CLEARTEXT = bytes(
    # ------------------------------------------------------
    # This is just the first two blocks of the original
    # cleartext, which covers the entirety of the
    # theSwordOfSecrets() function.   The code actually
    # copies 0x50 bytes, which is much more than necessary,
    # so I'm only including the first 0x20 bytes here.
    # ------------------------------------------------------
    # ------------------------------------------------------------------------------------------------------------
    # Bytes 0x00..0x0F     # Address   Bytes       Assembly               Notes
    # ------------------------------------------------------------------------------------------------------------
    b'\xaa\x87' +          # 0x16b2    87aa        mv a5, a0              fn* arg0 -> a5
    b'\x2e\x85' +          # 0x16b4    852e        mv a0, a1              arg1 -> arg0
    b'\x06\xc0' +          # 0x16b6    c006        sw ra, 0(sp)           PROLOG: store $ra to stack
    b'\x71\x11' +          # 0x16b8    1171        addi sp, sp, -4        PROLOG: use 4 bytes of stack
    b'\x37\x07\x00\x08' +  # 0x16ba    08000737    lui a4, 0x8000         Load 0x8000’0000 to a4
    b'\x18\x43' +          # 0x16be    4318        lw a4, 0(a4)           load *(0x8000’0000) to a4
    b'\x11\xe7' +          # 0x16c0    e711        bnez a4, ip+0x0C       if non-zero, jump to fail (offset 0x1A)
    # ------------------------------------------------------------------------------------------------------------
    # Bytes 0x10..0x1F     # Address   Bytes       Assembly               Notes
    # ------------------------------------------------------------------------------------------------------------
    b'\x82\x97' +          # 0x16c2    9782        jalr a5                else call fn* arg0
    b'\x01\x45' +          # 0x16c4    4501        li a0, 0               set success result
    b'\x82\x40' +          # 0x16c6    4082        lw ra, 0(sp)           EPILOG: corrupts the stack!!
    b'\x11\x01' +          # 0x16c8    0111        addi sp, sp, 4         EPILOG: release 4 bytes of stack
    b'\x82\x80' +          # 0x16ca    8082        ret                    EPILOG: return
    b'\x7d\x55' +          # 0x16cc    557d        li a0, -1              FAIL: set failure result
    b'\xe5\xbf' +          # 0x16ce    bfe5        j ip-0x08              jump to epilog (offset 0x14)
    b'\xaa\x87'            # 0x16d0    87aa        mv a5, a0              (start of next function…)
    # ------------------------------------------------------------------------------------------------------------
    # ... bytes 0x20..0x31 are excluded for brevity
    # ------------------------------------------------------------------------------------------------------------
)

STAGE4_THIRD_AES_BLOCK_DESIRED_PLAINTEXT = bytes(
    b'\x82\x97' + # 0x9782 == c.jalr a5         # call fn* arg0
    b'\x01\x45' + # 0x4501 == c.li a0, 0        # set success result
    b'\x11\x01' + # 0x0111 == c.addi sp, sp, 4  # EPILOG: corrected sequence
    b'\x82\x40' + # 0x4082 == c.lw ra, 0(sp)    # EPILOG: corrected sequence
    b'\x82\x80' + # 0x8082 == c.ret             # EPILOG: return
    b'\x06' * 6                                 # PKCS7 padding to make a full block
)

STAGE4_THREE_AES_BLOCKS_WITH_FULL_BLOCK_PADDING = bytes(
    # First AES block of ciphertext remains unchanged
    b'\x8e\x3c\x5a\xf5\x56\x82\xd4\x0c' +
    b'\x5a\x26\xdb\x1d\x71\xf3\xcf\x11' +

    # Second AES block of ciphertext will decrypt unpredictably
    b'\xe9\x43\x52\x99\x70\x7f\x94\x57'
    b'\x44\xd3\x54\x5d\xcd\x75\x33\xa3'

    # Third AES block is vanity data
    b'\x68\x65\x6e\x72\x79\x67\x61\x62'
    b'\x68\x65\x6e\x72\x79\x67\x61\x62'
)

STAGE4_REPLACEMENT_CIPHERTEXT = bytes(
    b'\x8e\x3c\x5a\xf5\x56\x82\xd4\x0c' + # * Padding oracle cannot be used to predictably modify the
    b'\x5a\x26\xdb\x1d\x71\xf3\xcf\x11' + #   the first AES block, so keep original values.
    b'\x7b\xc4\x43\xcc\x71\x6e\x06\x07' + # * Second AES block will decrypt to unpredictable values,     
    b'\xd6\x43\x42\x4b\xdb\x63\x25\xb5' + #   OK because BF script will change the jump to skip over these...
    b'\x68\x65\x6e\x72\x79\x67\x61\x62' + # * Final AES block is vanity data
    b'\x68\x65\x6e\x72\x79\x67\x61\x62'
)

STAGE4_BF_SCRIPT = bytes(
    b'>' * 0x110 + # 0x3e: skip from data[0] to code[0]
    b'>' *   0xE + # 0x3e: goto first byte of the target instruction
    b'-' *   0x8 + # 0x2d: 0x11 --> 0x09 (-8)
    b'>' *   0x1 + # 0x3e: goto the second byte of the instruction
    b'+' *   0x4   # 0x2b: 0xE7 --> 0xeb (+4)
) #     299 bytes ... well shy of 512 byte maximum script size

STAGE4_BF_MAX_BYTES_PER_LINE = 0x10

# ---------------------------------------------------------------------------
# Auto-solve stages 1-4
# ---------------------------------------------------------------------------

async def write_stage4_solution(ctx: CommandContext) -> None:
    """Helper to write the stage 4 solution to the device."""
    old_wpt_state = await sos.get_write_protect_state(ctx)
    block_0x40000_was_locked = False
    block_0x50000_was_locked = False
    new_wpt_state = old_wpt_state

    #region unlock the blocks if write protection is currently enabled for them
    if old_wpt_state == sos.WriteProtectionType.INDIVIDUAL_BLOCK_PROTECT:
        block_0x40000_was_locked = await sos.wps_is_block_locked(ctx, 0x40000)
        block_0x50000_was_locked = await sos.wps_is_block_locked(ctx, 0x50000)
        if block_0x40000_was_locked:
            await sos.wps_unlock_block(ctx, 0x40000)
        if block_0x50000_was_locked:
            await sos.wps_unlock_block(ctx, 0x50000)
    elif old_wpt_state.LowestProtectedAddress is None or old_wpt_state.HighestProtectedAddress is None:
        pass
    elif old_wpt_state.LowestProtectedAddress >= 0x60000 or old_wpt_state.HighestProtectedAddress < 0x40000:
        pass
    else:
        await sos.set_write_protect_state(sos.WriteProtectionType.NONE, ctx)
        new_wpt_state = sos.WriteProtectionType.NONE
    #endregion unlock the blocks if write protection is currently enabled for them

    #region erase/write 0x40000 and 0x50000
    await sos.erase_flash_4k(0x40000, ctx)
    await sos.erase_flash_4k(0x50000, ctx)

    await sos.write_flash_with_length_prefix(0x40000, STAGE4_REPLACEMENT_CIPHERTEXT, ctx)
    await sos.write_flash(0x50000, STAGE4_BF_SCRIPT, ctx)
    #endregion erase/write 0x40000 and 0x50000

    #region restore write protection state if it was modified
    if new_wpt_state != old_wpt_state:
        await sos.set_write_protect_state(old_wpt_state, ctx)
    if block_0x40000_was_locked:
        await sos.wps_unlock_block(ctx, 0x40000)
    if block_0x50000_was_locked:
        await sos.wps_unlock_block(ctx, 0x50000)
    #endregion restore write protection state if it was modified
    ctx.print_info("Stage 4 solution written to flash at addresses 0x40000 and 0x50000.")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------




async def write_stage4_function_ciphertext(ctx: CommandContext, ciphertext: bytes, erase: bool = True) -> None:
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
        await sos.erase_flash_4k(0x40000, ctx)
    await sos.write_flash(0x40000, sector_data, ctx)

async def modify_final_aes_block_plaintext_via_penultimate_block(ctx: CommandContext, ciphertext: bytes, desired_final_block_plaintext: bytes, original_final_block_plaintext: bytes, progress_callback: sos3.Stage3Callback) -> bytearray:
    # This function will modify the bytes of the penultimate AES block (resulting
    # in unpredictable decryption of that penultimate AES block) in order to cause
    # the final AES block to decrypt to the desired final block plaintext.
    # This requires knowing the current plaintext of the final block.
    if len(ciphertext) < 0x20:
        raise ValueError(f"Unexpected ciphertext length: 0x{len(ciphertext):02x} (expected at least 0x20)")
    if len(ciphertext) % 0x10 != 0:
        raise ValueError(f"Unexpected ciphertext length: 0x{len(ciphertext):02x} (expected multiple of 0x10)")
    if len(desired_final_block_plaintext) != 0x10:
        raise ValueError(f"Unexpected desired_final_block_plaintext length: 0x{len(desired_final_block_plaintext):02x} (expected exactly 0x10)")
    if len(original_final_block_plaintext) != 0x10:
        raise ValueError(f"Unexpected original_final_block_plaintext length: 0x{len(original_final_block_plaintext):02x} (expected exactly 0x10)")
    result = bytearray(ciphertext)
    for i in range(0x10):
        # To modify the final block plaintext, we need to XOR the ciphertext of the penultimate block
        # with:
        #   original final block plaintext (padding bytes == 0x10) XOR desired final block plaintext
        result[-0x20 + i] ^= (desired_final_block_plaintext[i] ^ original_final_block_plaintext[i])
    return result

async def convert_16_byte_padding_to_desired_plaintext(ctx: CommandContext, ciphertext: bytes, desired_final_block_plaintext: bytes, progress_callback: sos3.Stage3Callback) -> bytearray:
    # This function assumes that the input ciphertext's final block decrypts to
    # a full-block PKCS7 padding (all sixteen bytes are 0x10).
    original_final_block_plaintext = bytes(b'\x10' * 0x10)
    return await modify_final_aes_block_plaintext_via_penultimate_block(
        ctx = ctx,
        ciphertext = ciphertext,
        desired_final_block_plaintext = desired_final_block_plaintext,
        original_final_block_plaintext = original_final_block_plaintext,
        progress_callback = progress_callback
    )

async def create_desired_ciphertext_for_code(ctx: CommandContext, progress_callback: sos3.Stage3Callback, *, quick: bool = False) -> bytearray:
    """
    Helper to convert original theSwordOfSecrets() ciphertext
    into a modified ciphertext with the first AES block unchanged,
    the second AES block decrypting to unpredictable values,
    and the third AES block decrypting to the desired instructions.
    
    Note that a BF script will still need to modify the final
    branch instruction in the first AES block to skip over the
    second AES block into the first byte of the third AES block.
    
    This is likely the intended solution for this stage.
    """

    # Take the original stage 4 ciphertext as the starting point
    tmp = bytearray(
        STAGE4_ORIGINAL_CIPHERTEXT[0x00:0x10] + # keep the first block the same
        b'\x00' * 0x10                        + # the AES block that will decrypt unpredictably
        b'henrygabhenrygab'                     # could be any value ... so I'll have fun
    )

    with ctx.shell.suppress_serial_output():
        with sos.util_timer(ctx, f"generate stage4 ciphertext"):
            if quick:
                ensured_16_bytes_padding = STAGE4_THREE_AES_BLOCKS_WITH_FULL_BLOCK_PADDING
            else:
                some_valid_padding = await sos3.stage3_brute_force_initial_padding_destructive(ctx, tmp, progress_callback)
                ensured_16_bytes_padding = await sos3.stage3_ensure_16_byte_padding_destructive(ctx, some_valid_padding, progress_callback)

            ctx.print("data with full block of PKCS7 padding as third AES block")
            await sos.util_hex_dump(ctx, ensured_16_bytes_padding, base_address=0x40004)

            final_ciphertext = await convert_16_byte_padding_to_desired_plaintext(ctx, ensured_16_bytes_padding, STAGE4_THIRD_AES_BLOCK_DESIRED_PLAINTEXT, progress_callback)
            ctx.print("final modified ciphertext for `code`:")
            await sos.util_hex_dump(ctx, final_ciphertext, base_address=0x40004)
            return final_ciphertext

async def default_stage4_bf_script_writer(ctx: CommandContext) -> None:
    await sos.erase_flash_4k(0x50000, ctx)
    await sos.write_flash(0x50000, STAGE4_BF_SCRIPT, ctx)

async def ensure_bf_dump_prerequisites(
    ctx: CommandContext,
    *,
    stage4_ciphertext_writer: Stage4CipherTextWriterType = write_stage4_solution,
    stage4_bf_script_writer : Stage4OneTimeBFScriptWriterType | None = default_stage4_bf_script_writer
    ) -> None:
    # This function will ensure all the prerequisites are in place to be able to
    # run a BF script that can dump bytes from RAM, without needing to reboot
    # between each execution of the BF script.
    with ctx.shell.suppress_serial_output():
        ctx.print("Ensuring prerequisites for running BF script to dump RAM bytes...")
        ctx.print("Writing solutions for stages 1-3")
        await sos1.write_stage1_solution(ctx)
        await sos2.write_stage2_solution(ctx)
        await sos3.cmd_sos3_autosolve(args="", ctx=ctx)
        ctx.print("Writing replacements 'code' ciphertext for stage 4")
        await stage4_ciphertext_writer(ctx)
        ctx.print("Ensuring WPS=1 (write protection per 64k-block)")
        old_wp_state = await sos.get_write_protect_state(ctx)
        if old_wp_state != sos.WriteProtectionType.INDIVIDUAL_BLOCK_PROTECT:
            await sos.set_write_protect_state(sos.WriteProtectionType.INDIVIDUAL_BLOCK_PROTECT, ctx)
        ctx.print("Ensuring no blocks are locked while WPS=1")
        await sos.wps_global_unlock(ctx)
        ctx.print("Locking block 0x40000 while WPS=1")
        await sos.wps_lock_block(ctx, 0x40000)
        ctx.print("Rebooting with locked `code` ciphertext")
        await sos.util_send_command("REBOOT", ctx)
        if stage4_bf_script_writer == default_stage4_bf_script_writer:
            ctx.print("Writing BF script to alter branch instruction in `code` (avoid lockup/crash)")
        if stage4_bf_script_writer is not None:
            await stage4_bf_script_writer(ctx)
        ctx.print("Executing SOLVE once");
        await sos.util_send_command("SOLVE", ctx)
        if stage4_bf_script_writer is not None:
            ctx.print("Erasing BF script from flash (cleanup)")
            await sos.erase_flash_4k(0x50000, ctx)
        ctx.print("Done!")

async def parse_bf_dump_output_and_extract_bytes(ctx: CommandContext, lines: List[str]) -> bytearray:

    # success output lines always look like:
    # lines[0]: MAGICLIB{No one can break this! 0x20000}
    # lines[1]: MAGICLIB{53Cr37 5745H: 0x30000}
    # lines[2]: MAGICLIB{Passwd: 53R37 0x50000}
    # lines[3]: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 FLAG{The secrets of the swords are revealed!}
    # lines[4]: THE SECRET IS REVEALED!
    #
    # except that lines[3] may contain between 1..16 bytes of hex data before "FLAG",
    # and the hex data is anything that legally outputs from '%02x ' format string for a single byte.
    #

    try:
        if len(lines) != 5:
            raise ValueError(f"Unexpected number of lines in BF dump output: {len(lines)} (expected 5)")
        if lines[0] != "MAGICLIB{No one can break this! 0x20000}":
            raise ValueError(f"Unexpected line 0 in BF dump output: {lines[0]!r} (expected 'MAGICLIB{{No one can break this! 0x20000}}')")
        if lines[1] != "MAGICLIB{53Cr37 5745H: 0x30000}\x01":
            raise ValueError(f"Unexpected line 1 in BF dump output: {lines[1]!r} (expected 'MAGICLIB{{53Cr37 5745H: 0x30000}}')")
        if lines[2] != "MAGICLIB{Passwd: 53R37 0x50000}":
            raise ValueError(f"Unexpected line 2 in BF dump output: {lines[2]!r} (expected 'MAGICLIB{{Passwd: 53R37 0x50000}}')")
        if lines[4] != "THE SECRET IS REVEALED!":
            raise ValueError(f"Unexpected line 4 in BF dump output: {lines[4]!r} (expected 'THE SECRET IS REVEALED!')")

        # Trim the non-hex postfix from line 3.
        line3_postfix = "FLAG{The secrets of the swords are revealed!}"
        if not lines[3].endswith(line3_postfix):
            raise ValueError(f"Unexpected line 3 in BF dump output: {lines[3]!r} (expected to end with {line3_postfix!r})")
        line3_hex_parts = lines[3][0:-len(line3_postfix)].strip().split(' ')
        if len(line3_hex_parts) > STAGE4_BF_MAX_BYTES_PER_LINE:
            raise ValueError(f"Unexpected line 3 in BF dump output: {lines[3]!r} (expected at most {STAGE4_BF_MAX_BYTES_PER_LINE} bytes of hex data, but got {len(line3_hex_parts)})")

        result = bytearray()
        # convert from hex formatted as '%x ' to raw bytes
        # could be any of: "0 ", "1 ", "2 ", ..., "fe ", "ff ", "00 ", "01 ", "02 ", ..., "0e ", "0f "
        for part in line3_hex_parts:
            result.append(int(part, base=16))

        # ctx.print(f"Input OK, extracted {len(result)} bytes from {lines!r}")
        return result
    except Exception as e:
        ctx.print_error(f"Input resulted in exception {e}\n")
        ctx.print_error(f"Lines: {lines!r}\n")
        raise

async def read_all_accessible_bytes_prior_to_tape_via_bf_script(ctx: CommandContext) -> bytearray:
    # Returns 0xFE bytes that preceed the `tape` variable in RAM.
    #
    # Although `tape` starts at 0x2000'00F4, and having 0x200 bytes of BF script space would
    # technically allow reading back as far as 0x1FFF'FEF5 (0x2000'00F4 - 0x1FF), this code
    # will return data starting from 0x2000'0000 because it's the start of the RAM area.
    #
    # await check_bf_dump_prerequisites(ctx)

    tape_start : int = 0x200000F4
    dump_start : int = 0x20000000
    results = bytearray()
    

    with ctx.shell.suppress_serial_output():

        # this can be done in a single BF script ... but might exceed firmware's output line limit
        target_address = dump_start
        bytes_to_dump : int = 0

        while target_address < tape_start:
            bytes_to_dump = min(STAGE4_BF_MAX_BYTES_PER_LINE, tape_start - target_address)
            instructions_to_reach_target = (tape_start - target_address)
            # each byte to be dumped takes two BF instructions, but can skip the final instruction
            # (which simply increments to the next memory location)
            bytes_to_dump = min(bytes_to_dump, (512 + 1 - instructions_to_reach_target) // 2)

            bf_script : bytes = bytes(
                b'<' * instructions_to_reach_target + # skip from data[0] to target address
                b'.>' * (bytes_to_dump - 1)         + # dump the byte and skip to the next byte
                b'.'                                  # dumps the final byte
            )

            await sos.erase_flash_4k(0x50000, ctx)
            await sos.write_flash(0x50000, bf_script, ctx)
            lines = await sos.util_send_command("SOLVE", ctx)

            parsed = await parse_bf_dump_output_and_extract_bytes(ctx, lines)
            results.extend(parsed)
            target_address += bytes_to_dump
    return results

async def read_all_accessible_bytes_following_tape_via_bf_script(ctx: CommandContext) -> bytearray:

    tape_start : int = 0x200000F4
    dump_start : int = 0x200000F4 # just start at tape....
    results = bytearray()

    with ctx.shell.suppress_serial_output():

        target_address = dump_start
        bytes_to_dump : int = 1

        while bytes_to_dump > 0:
            instructions_to_reach_target = target_address - tape_start
            remaining_instructions = 512 - instructions_to_reach_target
            bytes_to_dump = min(STAGE4_BF_MAX_BYTES_PER_LINE, (remaining_instructions+1) // 2)

            bf_script : bytes = bytes(
                b'>' * instructions_to_reach_target + # skip from data[0] to target address
                b'.>' * (bytes_to_dump - 1)         + # dump the byte and skip to the next byte
                b'.'                                  # dumps the final byte
            )

            await sos.erase_flash_4k(0x50000, ctx)
            await sos.write_flash(0x50000, bf_script, ctx)
            lines = await sos.util_send_command("SOLVE", ctx)

            parsed = await parse_bf_dump_output_and_extract_bytes(ctx, lines)
            results.extend(parsed)
            target_address += bytes_to_dump

    return results



# ---------------------------------------------------------------------------
# Commands registered with serial console
# ---------------------------------------------------------------------------

async def cmd_sos4_autosolve(args: str, ctx: CommandContext) -> None:
    if args.strip() != "":
        raise ValueError(f"Unexpected argument: `{args.strip()}` (expected empty)")
    with ctx.shell.suppress_serial_output():
        await write_stage4_solution(ctx)
        await sos.set_write_protect_state(sos.WriteProtectionType.INDIVIDUAL_BLOCK_PROTECT, ctx)
        await sos.wps_global_unlock(ctx)
        await sos.wps_lock_block(ctx, 0x40000)
    ctx.print("Stage 4 solution ... `code` block locked, BF script can execute once per boot for SOLVE")

async def cmd_sos4_1_replace_code_ciphertext(args: str, ctx: CommandContext) -> None:
    quick_mode = False
    if args.strip() != "":
        if args.strip() == "-q":
            quick_mode = True
        else:
            raise ValueError(f"Unexpected argument: `{args.strip()}` (expected `-q` or empty)")

    with ctx.shell.suppress_serial_output():
        new_ciphertext = await create_desired_ciphertext_for_code(ctx, sos3.Stage3GeneralCallback, quick=quick_mode)
        await sos.write_flash_with_length_prefix(0x40000, new_ciphertext, ctx)
        ctx.print("Stage 4 code ciphertext replaced with modified version.")
        await sos3.cmd_sos3_autosolve(args="", ctx=ctx)
        ctx.print("Stage 3 solution restored")
        ctx.print("This is only a small part of the solution....")

async def cmd_sos4_prepare_for_BF_data_dump(args: str, ctx: CommandContext) -> None:
    if args.strip() != "":
        raise ValueError(f"Unexpected argument: `{args.strip()}` (expected empty)")
    with ctx.shell.suppress_serial_output():
        await ensure_bf_dump_prerequisites(ctx)

async def cmd_sos4_bf_dump(args: str, ctx: CommandContext) -> None:
    args = args.strip()
    dumpBeforeTape : bool = False
    dumpAfterTape  : bool = False
    if args == "before":
        dumpBeforeTape = True
    elif args == "after":
        dumpAfterTape = True
    elif args == "both":
        dumpBeforeTape = True
        dumpAfterTape  = True
    else:
        raise ValueError(f"Unexpected argument: `{args.strip()}` (expected `before`, `after`, or `both`)")

    try:
        with ctx.shell.suppress_serial_output():
            data_after_tape : bytes = b''
            data_before_tape : bytes = b''
            start_address : int = 0
            header : str = "undefined"
            if dumpBeforeTape:
                data_before_tape = await read_all_accessible_bytes_prior_to_tape_via_bf_script(ctx)
                start_address = 0x20000000
                header = "Data before `tape`:"
            if dumpAfterTape:
                data_after_tape = await read_all_accessible_bytes_following_tape_via_bf_script(ctx)
                start_address = 0x200000f4
                header = "Data after `tape`:"
            if dumpBeforeTape and dumpAfterTape:
                header = "All data around `tape`:"
                start_address = 0x20000000

            data = bytearray(data_before_tape + data_after_tape)
            ctx.print(header)
            await sos.util_hex_dump(ctx, data, base_address=start_address)
    except Exception as e:
        ctx.print_error(f"Error during BF dump: {e}")
        raise

async def cmd_full_solution(args: str, ctx: CommandContext) -> None:
    if args.strip() != "":
        raise ValueError(f"Unexpected argument: `{args.strip()}` (expected empty)")
    with ctx.shell.suppress_serial_output():
        with sos.util_timer(ctx, "Erase/Reset device to prepare for full solution"):
            await sos.set_write_protect_state(sos.WriteProtectionType.NONE, ctx)
            await sos.erase_flash_4k(0x10000, ctx)
            await sos.erase_flash_4k(0x20000, ctx)
            await sos.erase_flash_4k(0x30000, ctx)
            await sos.erase_flash_4k(0x40000, ctx)
            await sos.erase_flash_4k(0x50000, ctx)
            await sos.util_send_command("RESET", ctx)
        ctx.print("")
        ctx.print("writing solutions for stages 1-4")
        with sos.util_timer(ctx, "Solving Sword of Secrets from start to finish"):
            await sos1.write_stage1_solution(ctx)
            await sos2.write_stage2_solution(ctx)
            await sos3.cmd_sos3_full_solution(args="", ctx=ctx)
            await cmd_sos4_1_replace_code_ciphertext(args="", ctx=ctx)

            ctx.print("Ensuring WPS=1 (write protection per 64k-block)")
            old_wp_state = await sos.get_write_protect_state(ctx)
            if old_wp_state != sos.WriteProtectionType.INDIVIDUAL_BLOCK_PROTECT:
                await sos.set_write_protect_state(sos.WriteProtectionType.INDIVIDUAL_BLOCK_PROTECT, ctx)
            ctx.print("Ensuring no blocks are locked while WPS=1")
            await sos.wps_global_unlock(ctx)
            ctx.print("Locking block 0x40000 while WPS=1")
            await sos.wps_lock_block(ctx, 0x40000)
            ctx.print("Rebooting with locked `code` ciphertext")
            await sos.util_send_command("REBOOT", ctx)
            ctx.print("Writing BF script to alter branch instruction in `code` (avoid lockup/crash)")
            await sos.erase_flash_4k(0x50000, ctx)
            await sos.write_flash(0x50000, STAGE4_BF_SCRIPT, ctx)
            ctx.print("Executing BF script once via SOLVE command");
            l = await sos.util_send_command("SOLVE", ctx)
            for line in l:
                ctx.print(line)
            ctx.print("Done!")

# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------
