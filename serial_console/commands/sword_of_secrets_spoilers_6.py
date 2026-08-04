"""
Walkthrough to solve the Sword of Secrets hardware CTF.

This is SPOILER RICH content.  Do NOT read if you wish
to enjoy the challenge of the CTF on your own!
"""

from __future__ import annotations

import asyncio
from binascii import Error

from ..command_registry import CommandContext, CommandRegistry
from enum import Enum
from typing import Literal, Sequence, Tuple, overload, TypeAlias
from . import sword_of_secrets as sos

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

# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_sword_of_secrets_spoilers_x(registry: CommandRegistry) -> None:
    """Populate *registry* with the three example commands."""
    registry.register(
        "autosolve", cmd_solve_original_challenge,
        "Automatically solve the original Sword of Secrets challenge.",
        usage="autosolve",
        category="Sword of Secrets Walkthrough",
    )

# ---------------------------------------------------------------------------
# Global (const) data
# ---------------------------------------------------------------------------


STAGE1_SOLVED_DATA = bytes(
        b'\x00\x00\x1F\x00\x0E\x05\x13\x07' +
        b'\x36\x0F\x37\x69\x22\x27\x3F\x65' +
        b'\x2E\x20\x36\x69\x2F\x3B\x3F\x24' +
        b'\x26\x61\x2C\x21\x24\x3A\x7B\x65' +
        b'\x7D\x39\x6A\x79\x7D\x79\x6A\x38' +
        b'\x4D\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
    )
STAGE2_SOLVED_DATA = bytes(
        b'\xDE\x90\xE7\xD0\xAE\x83\x38\xB0\x7A\xAC\x38\x94\x75\x74\x69\x00' +
        b'\x41\x5D\x39\x41\xDE\xD0\xE4\xE3\xAD\xC5\x45\x98\x42\xDC\xA5\x8D' +
        b'\xDE\x90\xE7\xD0\xAE\x83\x38\xB0\x7A\xAC\x38\x94\x75\x74\x69\x00' +
        b'\x41\x5D\x39\x41\xDE\xD0\xE4\xE3\xAD\xC5\x45\x98\x42\xDC\xA5\x8D'
    )
STAGE3_SOLVED_DATA = bytes(
        b'\x20\x00\x00\x00' +
        b'\xf7\x60\x4a\x1f\x5e\x96\x39\x7e\x96\xf5\x9e\x31\x72\x0b\xd9\x32' +
        b'\xd7\x6b\xed\xc8\xd1\xd1\x47\x34\x81\x46\x9a\x24\xbf\xaa\x90\x22' +
        b'\x35\x33\x52\x33\x37\x20\x30\x78\x35\x30\x30\x30\x30\x00\x00\x00'
)
STAGE4_REPLACEMENT_FUNCTION_ENC = bytes(
    b'\x20\x00\x00\x00' +
    b'\xb8\xfc\x6d\x55\xae\xc8\x7c\x5f\xec\xc5\x1c\xc5\xb9\xc4\xa7\x32' +
    b'\xe8\xc2\xaa\x11\x03\xbf\x00\x72\x08\x79\x21\xc3\xb4\xaf\x59\x1d'
    )
STAGE4_BF_SCRIPT = bytes(
    b'>' * 0x110 + # skip from data[0] to code[0]
    b'>' *   0xE + # skip to the first byte of the target instruction (0x11)
    b'-' *   0x8 + # change that first byte from 0x11 -> 0x09 (-8)
    b'>' *   0x1 + # goto the second byte of the instruction (0xe7)
    b'+' *   0x4   # change that second byte from 0xe7 -> 0xeb (+4)
) #     299 bytes ... well shy of 512 byte maximum script size
AES_KEY = bytes( b'\x0d\x70\xb8\x05\xed\xeb\x72\x3a\x5c\xcd\x12\x23\xb9\x34\x62\x1c' )

# ---------------------------------------------------------------------------
# Auto-solve stages 1-4
# ---------------------------------------------------------------------------

async def write_stage1_solution(ctx: CommandContext) -> None:
    """Helper to write the stage 1 solution to the device."""
    # this is the data that needs to be written to the device to solve stage 1 of the CTF

    await sos.erase_flash_4k(0x10000, ctx)
    await sos.write_flash(0x10000, STAGE1_SOLVED_DATA, ctx)
    ctx.print_info("Stage 1 solution written to flash at address 0x10000.")

async def write_stage2_solution(ctx: CommandContext) -> None:
    """Helper to write the stage 2 solution to the device."""
    # this is the data that needs to be written to the device to solve stage 2 of the CTF

    await sos.erase_flash_4k(0x20000, ctx)
    await sos.write_flash(0x20000, STAGE2_SOLVED_DATA, ctx)
    ctx.print_info("Stage 2 solution written to flash at address 0x20000.")

async def write_stage3_solution(ctx: CommandContext) -> None:
    """Helper to write the stage 3 solution to the device."""
    # this is the data that needs to be written to the device to solve stage 3 of the CTF
    await sos.erase_flash_4k(0x30000, ctx)
    await sos.write_flash(0x30000, STAGE3_SOLVED_DATA, ctx)
    ctx.print_info("Stage 3 solution written to flash at address 0x30000.")

async def write_stage4_solution(ctx: CommandContext) -> None:
    """Helper to write the stage 4 solution to the device."""
    await sos.erase_flash_4k(0x40000, ctx)
    await sos.write_flash(0x40000, STAGE4_REPLACEMENT_FUNCTION_ENC, ctx)
    await sos.erase_flash_4k(0x50000, ctx)
    await sos.write_flash(0x50000, STAGE4_BF_SCRIPT, ctx)
    ctx.print_info("Stage 4 solution written to flash at addresses 0x40000 and 0x50000.")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

async def check_stage3_oracle(ctx: CommandContext) -> OracleResponse:
    """Helper to check the stage 3 padding oracle response."""
    multilines = await sos.util_send_command("SOLVE", ctx)

    if len(multilines) != 3:
        raise ValueError(f"Unexpected response length: {len(multilines)} lines (expected 3)")
    if not multilines[0].startswith("MAGICLIB{"):
        raise ValueError(f"Unexpected response format: `{multilines[0]}` (expected to start with `MAGICLIB{{`)")
    if not multilines[0].endswith("}"):
        raise ValueError(f"Unexpected response format: `{multilines[0]}` (expected to end with `}}`)")
    if not multilines[1].startswith("MAGICLIB{"):
        raise ValueError(f"Unexpected response format: `{multilines[1]}` (expected to start with `MAGICLIB{{`)")
    if not not multilines[1].endswith("}"):
        raise ValueError(f"Unexpected response format: `{multilines[1]}` (expected to end with `}}`)")
    if multilines[2].strip() == "Invalid padding":
        return OracleResponse.BAD_PADDING
    if multilines[2].strip() == "Error in response.":
        return OracleResponse.GOOD_PADDING
    ctx.print_warning(f"Unexpected oracle response: `{multilines[2]}` (expected `Invalid padding` or `Error in response.`)")
    return OracleResponse.MANUAL_REVIEW_REQUIRED

async def stage4_bf_script_attempt(ctx: CommandContext) -> None:
    # Here, we write a BF script to 0x50000 which will dump ***binary*** data
    # Note that it is fully expected that the device will lockup afterwards,
    # due to the intentional stack corruption in `sword_of_secrets()` function.
    bf_script_read_at_256_for_128_bytes = b'>' * 256 + b'.>' * 128
    bf_script_read_at_384_for__64_bytes = b'>' * 384 + b'.>' *  64
    bf_script_read_at_448_for__32_bytes = b'>' * 448 + b'.>' *  32
    bf_script_read_at_480_for__16_bytes = b'>' * 480 + b'.>' *  16
    bf_script_read_at_496_for___8_bytes = b'>' * 496 + b'.>' *   8
    bf_script_read_at_504_for___4_bytes = b'>' * 504 + b'.>' *   4
    bf_script_read_at_508_for___2_bytes = b'>' * 508 + b'.>' *   2
    bf_script_read_at_510_for___1_bytes = b'>' * 510 + b'.>' *   1
    bf_script_read_sword_of_secrets_function = b'>' * 256 + b'>' * 16 + b'.>' * 120

    # maximum negative read:
    # Tape variable is @ 0x200000f4
    # Start of memory  @ 0x20000000
    # so go backwards 0xF4 bytes and then start reading forward....
    # that leaves 0x10C bytes of script space...
    # 
    bf_script_read_0x000__0x086 = b'<' * 0xF4 + b'.>' * ((0x200 - 0xF4) // 2) # reads 0x86 bytes
    bf_script_read_0x080__0x146 = b'<' * 0x74 + b'.>' * ((0x200 - 0x74) // 2) # reads 0xC6 bytes
    bf_script = bf_script_read_sword_of_secrets_function

    await sos.erase_flash_4k(0x50000, ctx)
    await sos.write_flash(0x50000, bf_script[:256], ctx)
    await sos.write_flash(0x50000 + 256, bf_script[256:512], ctx)
    # then, send the command "SOLVE" to trigger execution of the BF script
    # ... fully expecting the device to crash / lockup as we're not modifying
    # the instructions (yet)

async def find_aes_key(ctx: CommandContext) -> None:
    # This is a helper function to brute-force search for the AES key
    # that may be dumped by the BF scripts in stage 4.
    # loop through every 16-byte possibility, treat it as an AES key,
    # and attempt to encrypt a known plaintext from stage 2.
    potential_keys = bytes(
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x0d\x70\xb8\x05\xed\xeb\x72\x3a\x5c\xcd\x12\x23\xb9\x34\x62\x1c' +
        b'\x24\x00\x00\x00\x00\x00\x00\x00\x4d\x41\x58\x49\x4d\x49\x5a\x45' +
        b'\x00\x00\x00\x00\xff\xff\xff\x00\x11\x9c\x42\x16\x85\x71\x35\x10' +
        b'\x00\x00\x00\x00\xaa\x87\x2e\x85\x06\xc0\x71\x11\x37\x07\x00\x08' +
        b'\x18\x43\x11\xe7\x82\x97\x01\x45\x82\x40\x11\x01\x82\x80\x7d\x55' +
        b'\xe5\xbf\xaa\x87\x03\xc7\x07\x00\x01\xe7\x33\x85\xa7\x40\x82\x80' +
        b'\x85\x07\xcd\xbf\x13\x01\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e' +
        b'\x0e\x0e\x0e\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\xdd\x1d\x44\x28\xf5\x5b\xae\x8f\x7a\x0b\x34\xe7' +
        b'\x7b\xcd\x38\x88\xa8\x8e\xaa\x8e\xb1\xad\x7b\x53\x3d\x61\xf2\x7c' +
        b'\x9b\xbc\xf7\xd0\x9a\x27\x46\x2a\xe4\xba\xe4\xd5\x50\xaa\x53\xb6' +
        b'\x09\x1e\x61\x57\x40\x6c\x33\xe0\xcd\x27\x5e\x30\x45\xa7\xeb\xeb' +
        b'\x0a\xd9\xfa\x7a\x57\x4d\x57\xdc\xb5\xcc\x8c\xf5\x78\x1b\x2e\x5d' +
        b'\x5b\x1a\x4f\x1c\x30\xf4\xb8\x8a\xde\x4f\x11\xd1\x30\xaa\x13\xf8' +
        b'\x6a\x89\x6b\xfe\xa4\x18\x16\x80\xbd\xc0\x21\xb9\x25\x05\xd5\x6d' +
        b'\x1d\x7c\x03\xcf\x11\x28\xfd\x23\x24\x40\xc8\x21\x0b\x02\x15\xa9' +
        b'\x69\xbd\xaf\x55\xe3\x52\x15\x5e\xd9\x24\xa6\x0f\x71\x79\x78\x07' +
        b'\x2e\xf6\x82\x7d\xf2\x8f\x37\x04\xe0\x3f\x5a\x71\xad\x38\xe8\xe8' +
        b'\xc7\xac\x7e\x46\x4b\x76\xed\xc5\x48\xda\xc1\xf7\x82\x79\x99\xab' +
        b'\xbd\x92\xe1\xd5\x92\xc4\xd0\x81\xfa\xfd\x88\x3c\x93\xbc\xed\xc5' +
        b'\x2d\xe2\xe1\x02\xb5\x1e\xa5\x8f\xac\x26\x8e\xae\xba\x3e\xec\xb7' +
        b'\xd5\xf1\x57\x98\xf9\x5f\xdb\xaa\x87\x62\xea\xe7\x26\x22\x81\xc1' +
        b'\x87\x3d\x0d\x9f\x88\x40\xc8\x03\xcf\x28\x5f\xfe\x01\x95\xd0\x93' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 
        )

    for i in range(0, len(potential_keys)-0x10, 1):
        key = potential_keys[i:i+16]
        ciphertext = STAGE2_SOLVED_DATA[:16]
        # decrypt using AES ECB mode with the candidate key
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        # check if all the bytes are ASCII printable characters (between 0x20 and 0x7E)
        if all(b >= 0x20 and b <= 0x7E for b in decrypted):
            ctx.print_info(f"Potential key found at offset 0x{i:02x}: {key.hex()} -> {decrypted.decode('ascii')}")
        else:
            # ctx.print(f"Key at offset 0x{i:02x} did not produce printable output.")
            None
    ctx.print("done")

async def stage4_decrypt_sos_function(ctx: CommandContext) -> None:
    ciphertext = bytes(
        b'\x8e\x3c\x5a\xf5\x56\x82\xd4\x0c' +
        b'\x5a\x26\xdb\x1d\x71\xf3\xcf\x11' +
        b'\x5c\x71\x14\xfa\xc8\x30\xdb\xcd' +
        b'\xc9\x88\x58\x42\xce\x68\x9c\xc6' +
        b'\xb5\x78\x94\x3d\x59\x1f\xa9\xd4' +
        b'\xe2\xbc\x7b\x33\x45\xc5\x99\x8e' +
        b'\xc8\x4e\xb4\x4e\x38\xa2\xaa\x12' +
        b'\xa8\x78\xfb\x43\x8d\x7f\x8a\xcd'
    )
    key = AES_KEY
    iv = bytes(b'\x00' * 16)
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)
    ctx.print_info(f"Decrypted SOS function:")
    for i in range(0, len(decrypted), 16):
        hexdump = ' '.join(f"{b:02x}" for b in decrypted[i:i+16])
        padding = ' ' * (3 * (16 - len(decrypted[i:i+16])))
        ascii_dump = ''.join(chr(b) if b >= 0x20 and b <= 0x7E else '.' for b in decrypted[i:i+16])
        ctx.print(f"{i:04x} {hexdump}{padding} {ascii_dump}")
    # Yes, this is correct, and gives the following 
    # b'\xaa\x87\x2e\x85\x06\xc0\x71\x11\x37\x07\x00\x08\x18\x43\x11\xe7' +
    # b'\x82\x97\x01\x45\x82\x40\x11\x01\x82\x80\x7d\x55\xe5\xbf\xaa\x87' +
    # b'\x03\xc7\x07\x00\x01\xe7\x33\x85\xa7\x40\x82\x80\x85\x07\xcd\xbf' +
    # b'\x13\x01\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
    #
    # Now, adjust that assembly code, and CBC encrypt it to produce a
    # ciphertext that, if not overwritten, will skip the check and just run
    # the proper solution.   Oh, and don't forget to fix the stack corruption!

async def stage4_encrypt_modified_sos_function(ctx: CommandContext) -> None:
    plaintext = bytes(
        b'\xaa\x87' + # c.mv a5, a0         // first parameter moves to a5 ... it's the function pointer
        b'\x2e\x85' + # c.mv a0, a1         // second parameter becomes the first
        b'\x06\xc0' + # c.swsp ra, 0(sp)    // store return address at sp+0
        b'\x71\x11' + # c.addi sp, -4       // adjust stack pointer to make room for the return address
        b'\x82\x97' + # c.jalr a5           // call the function pointer (was first parameter)
        b'\x01\x45' + # c.li a0, 1          // indicate this function return value is SUCCESS
        b'\x11\x01' + # c.addi sp, 4        // restore stack pointer
        b'\x82\x40' + # c.lwsp ra, 0(sp)    // restore return address
        b'\x82\x80' + # c.jr ra             // return to caller
        b'\x14' * 14  # PKCS7 padding
        )
    key = AES_KEY
    iv = bytes(b'\x00' * 16)
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(plaintext)
    ctx.print_info(f"Encrypted replacement SOS function:")
    for i in range(0, len(ciphertext), 16):
        hexdump = ' '.join(f"{b:02x}" for b in ciphertext[i:i+16])
        padding = ' ' * (3 * (16 - len(ciphertext[i:i+16])))
        ascii_dump = ''.join(chr(b) if b >= 0x20 and b <= 0x7E else '.' for b in ciphertext[i:i+16])
        ctx.print(f"{i:04x} {hexdump}{padding} {ascii_dump}")

    # TODO: write that to 0x40000, and enable write-protection, then reboot

async def stage4_verify_write_protect_functionality(ctx: CommandContext) -> None:
    # Actually, just test writing to 0xA0000
    # and then setting write protect
    # and then writing to 0xA0000 again to verify it fails
    # then reboot and write to 0xA0000 again
    # to verify it still fails after REBOOT command
    test_data = bytes(b'\xCA\xFE\xBA\xBE' * 4)
    await sos.erase_flash_4k(0xA0000, ctx)
    await sos.write_flash(0xA0000, test_data, ctx)
    ctx.print_info("Test data written to 0xA0000 successfully.")
    await asyncio.sleep(2)
    await sos.set_write_protect_state(sos.WriteProtectionType.PROTECT_ALL, ctx)
    is_ok = True
    try:
        bad_data = bytes(b'\xBA\xAD\xF0\x0D' * 4)
        await sos.write_flash(0xA0000, bad_data, ctx)
        is_ok = False
        ctx.print_error("ERROR: writing to protected flash succeeded when it should have failed!")
    except Exception as e:
        ctx.print_info(f"SUCCESS: writing to protected flash fails as expected: {e}")
    if not is_ok:
        raise ValueError("Write protection test failed: was able to write to protected flash.")
    await asyncio.sleep(2)

    l = await sos.util_send_command("REBOOT", ctx)
    is_ok = True
    try:
        bad_data = bytes(b'\xBA\xAD\xF0\x0D' * 4)
        await sos.write_flash(0xA0000, bad_data, ctx)
        is_ok = False
        ctx.print_error("ERROR: writing to protected flash (after reboot) succeeded when it should have failed!")
    except Exception as e:
        ctx.print_info(f"SUCCESS: writing to protected flash (after reboot) fails as expected: {e}")
    if not is_ok:
        raise ValueError("Write protection test failed: was able to write to protected flash (after reboot).")
    await asyncio.sleep(2)

    await sos.set_write_protect_state(sos.WriteProtectionType.NONE, ctx)
    try:
        more_goodness = bytes(b'\xDE\xAD\xBE\xEF' * 4)
        await sos.write_flash(0xA0000, more_goodness, ctx)
        ctx.print_info("Successfully wrote to 0xA0000 again after removing write protection.")
    except Exception as e:
        ctx.print_error(f"ERROR: writing to flash failed after removing write protection: {e}")
        raise

    ctx.print_success("Write protection functionality verified successfully.")

async def stage3_detect_current_padding_destructive(ctx: CommandContext) -> int:
    """Helper to detect how many padding bytes are currently correct in stage 3."""
    resp = await check_stage3_oracle(ctx)
    if resp == OracleResponse.BAD_PADDING:
        raise ValueError("Current padding is incorrect. Unable to proceed.")
    if resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
        raise ValueError("Unexpected oracle response. Please review manually.")

    # OK, padding appears to have some correct bytes.
    # Read the existing sector data.
    tmp = await sos.read_flash(0x30000, 0x4, ctx)
    datalen = int.from_bytes(tmp, byteorder='little')
    if datalen % 0x10 != 0:
        raise ValueError(f"Unexpected data length format: 0x{datalen:02x} (expected multiple of 0x10)")
    if datalen < 0x20:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at least 0x20)")
    if datalen > 0x80:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at most 0x80)")
    penultimate_block_offset = datalen - 0x20 + 0x04
    golden_stage3_data = await sos.read_flash(0x30000, datalen + 0x04, ctx)

    try:
        # Detect how many padding bytes are currently correct.
        # starting at offset 0 of penultimate block, change the byte, check oracle response
        padding_byte_count = 0
        for offset in range(0, 0x10):
            ctx.print(f"Checking if byte 0x{offset:02x} is padding...")
            tmp = bytearray(golden_stage3_data)
            byte_offset = penultimate_block_offset + offset
            tmp[byte_offset] ^= 0xFF # flip all bits to ensure padding is incorrect
            await sos.erase_flash_4k(0x30000, ctx)
            await sos.write_flash(0x30000, tmp, ctx)
            resp = await check_stage3_oracle(ctx)
            if resp == OracleResponse.BAD_PADDING:
                # this is the first byte that, if changed, causes the padding to be incorrect.
                padding_byte_count = 16 - offset
                break
            if resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
                raise ValueError("Unexpected oracle response during padding byte detection. Please review manually.")
            # else still good padding, try the next byte
        if padding_byte_count == 0:
            raise ValueError("Could not discover padding byte count. Please review manually.")
        ctx.print(f"Detected padding byte count: 0x{padding_byte_count:02x}")
        return padding_byte_count
    finally:
        # restore the original data to avoid leaving the device in a broken state
        await sos.erase_flash_4k(0x30000, ctx)
        await sos.write_flash(0x30000, golden_stage3_data, ctx)

async def stage3_expand_second_block_padding(ctx: CommandContext) -> None:
    """Helper to expand the padded size of the second sector in stage 3."""
    resp = await check_stage3_oracle(ctx)
    if resp == OracleResponse.BAD_PADDING:
        ctx.print_info("Current padding is incorrect. Unable to proceed.")
        return
    if resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
        ctx.print_info("Unexpected oracle response. Please review manually.")
        return

    tmp = await sos.read_flash(0x30000, 0x4, ctx)
    datalen = int.from_bytes(tmp, byteorder='little')
    if datalen % 0x10 != 0:
        raise ValueError(f"Unexpected data length format: 0x{datalen:02x} (expected multiple of 0x10)")
    if datalen < 0x20:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at least 0x20)")
    if datalen > 0x80:
        raise ValueError(f"Unexpected data length: 0x{datalen:02x} (expected at most 0x80)")
    golden_stage3_data = await sos.read_flash(0x30000, datalen + 0x04, ctx)
    penultimate_block_offset = 0x04 + datalen - 0x20

    ctx.print("Detecting current padding byte count...")
    # Detect how many padding bytes are currently correct.
    padding_byte_count = await stage3_detect_current_padding_destructive(ctx)

    ctx.print(f"Current padding byte count: {padding_byte_count}")


    while (padding_byte_count < 16):

        padding_byte_count += 1
        ctx.print(f"Searching for padding byte count: {padding_byte_count}")

        # How to change padding from N to N+1:
        XOR_PADDING = padding_byte_count ^ (padding_byte_count - 1)
        TEST_BYTE_OFFSET = penultimate_block_offset + 0x10 - padding_byte_count

        tmp = bytearray(golden_stage3_data)
        for i in range(penultimate_block_offset, penultimate_block_offset+0x10):
            if i == TEST_BYTE_OFFSET:
                # this is the next byte to be find a valid padding encoding for
                # set it to 0xFF as starting value for efficient traversal
                tmp[i] = 0xFF
            elif i > TEST_BYTE_OFFSET:
                # have to adjust the padding bytes
                tmp[i] ^= XOR_PADDING

        # write the new data to the device, so can start searching for value that makes it valid padding
        ctx.print(f"STARTING - Pad Count 0x{padding_byte_count:02x}:")
        ctx.print(f"DATA {' '.join(f'{b:02x}' for b in tmp[penultimate_block_offset:penultimate_block_offset+0x10])}")

        found_valid_padding = False
        for next_test in sos.FLASH_WALK:
            ctx.print(f"Testing: Pad Count 0x{padding_byte_count:02x}   Value 0x{next_test:02x} @ offset 0x{TEST_BYTE_OFFSET:02x}")

            need_erase = (tmp[TEST_BYTE_OFFSET] & next_test != next_test)
            tmp[TEST_BYTE_OFFSET] = next_test
            if need_erase:
                await sos.erase_flash_4k(0x30000, ctx)
            await sos.write_flash(0x30000, bytes(tmp), ctx)
            # check the oracle response ... end when padding is OK
            resp = await check_stage3_oracle(ctx)
            if resp == OracleResponse.GOOD_PADDING:
                # Found the value that results in valid padding of length padding_byte_count + 1!
                ctx.print(f"FOUND VALID PADDING 0x{next_test:02x} at offset 0x{TEST_BYTE_OFFSET:02x} for padding byte count {padding_byte_count}")
                ctx.print(f"GOLD({padding_byte_count:02x})    {' '.join(f'{b:02x}' for b in tmp[penultimate_block_offset:penultimate_block_offset+0x10])}")
                golden_stage3_data = tmp # update the golden data to reflect the newly discovered padding byte
                found_valid_padding = True
                break
            elif resp == OracleResponse.MANUAL_REVIEW_REQUIRED:
                raise ValueError("Unexpected oracle response during padding expansion. Please review manually.")
            # else test next flash_walk value

        if not found_valid_padding:
            raise ValueError(f"Could not find valid padding byte value for padding byte count {padding_byte_count}. Please review manually.")

    ctx.print_success(f"Successfully expanded padding to 16 bytes! Final padding byte count: {padding_byte_count}")

# ---------------------------------------------------------------------------
# Commands registered with serial console
# ---------------------------------------------------------------------------

async def cmd_solve_original_challenge(args: str, ctx: CommandContext) -> None:
    """Helper to write the stage 1 solution to the device."""
    await write_stage1_solution(ctx)
    await write_stage2_solution(ctx)
    await write_stage3_solution(ctx)
    await write_stage4_solution(ctx)
    await sos.set_write_protect_state(sos.WriteProtectionType.PROTECT_ALL, ctx)
    await sos.util_send_command("REBOOT", ctx)
    await sos.set_write_protect_state(sos.WriteProtectionType.NONE, ctx)
    await sos.util_send_command("SOLVE", ctx)

async def cmd_stage3(args: str, ctx: CommandContext) -> None:
    """Helper to expand the padded size of the second sector in stage 3."""
    with ctx.shell.suppress_serial_output():
        await stage3_expand_second_block_padding(ctx)

async def cmd_stage4(args: str, ctx: CommandContext) -> None:
    """Helper to solve stage 4."""
    #await stage4_bf_script_attempt(ctx)
    #await find_aes_key(ctx)
    #await stage4_decrypt_sos_function(ctx)
    #await stage4_verify_write_protect_functionality(ctx)
    await write_stage4_solution(ctx)
    return None

async def cmd_tmp2(_:str, ctx: CommandContext) -> None:
    """Temporary command for testing and experimentation."""
    ctx.shell.print_local("This is a temporary command for testing and experimentation.")
    ORIGINAL_STAGE4_SOS_ENCRYPTED_FUNCTION = bytes(
        b'\x8e\x3c\x5a\xf5\x56\x82\xd4\x0c\x5a\x26\xdb\x1d\x71\xf3\xcf\x11' +
        b'\x5c\x71\x14\xfa\xc8\x30\xdb\xcd\xc9\x88\x58\x42\xce\x68\x9c\xc6' +
        b'\xb5\x78\x94\x3d\x59\x1f\xa9\xd4\xe2\xbc\x7b\x33\x45\xc5\x99\x8e' +
        b'\xc8\x4e\xb4\x4e\x38\xa2\xaa\x12\xa8\x78\xfb\x43\x8d\x7f\x8a\xcd'
    )
    SOLVED_STAGE4_ENCRYPTED = bytes(
        b'\x8e\x3c\x5a\xf5\x56\x82\xd4\x0c\x5a\x26\xdb\x1d\x71\xf3\xcf\x11' +
        b'\x58\xc1\x0f\x14\x2a\xaa\x0b\x6b\x5e\x30\x12\xa9\xb0\x37\x72\xb7' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )

    from Crypto.Cipher import AES
    cipher2 = AES.new(AES_KEY, AES.MODE_CBC, iv=bytes(b'\x00' * 16))
    decrypted2 = cipher2.decrypt(SOLVED_STAGE4_ENCRYPTED)
    for i in range(0, len(decrypted2), 16):
        hexdump = ' '.join(f"{b:02x}" for b in decrypted2[i:i+16])
        padding = ' ' * (3 * (16 - len(decrypted2[i:i+16])))
        ascii_dump = ''.join(chr(b) if b >= 0x20 and b <= 0x7E else '.' for b in decrypted2[i:i+16])
        ctx.print(f"{i:04x} {hexdump}{padding} {ascii_dump}")



    current_data = bytearray(
        ORIGINAL_STAGE4_SOS_ENCRYPTED_FUNCTION[0:16] +
        b'\x00' * 32
        )

    pad_len = 1
    while pad_len <= 16:
        # ctx.print(f"Testing padding of 0x{pad_len:02x} bytes...")
        # adjust any prior-existing padding bytes to old value + 1
        if pad_len > 1:
            xor_value = pad_len ^ (pad_len - 1)
            for i in range(1, pad_len):
                current_data[-16-i] ^= xor_value
        # brute-force the next padding byte
        target_idx = 32 - pad_len

        found_valid_padding = False

        for test_byte in range(0x00, 0x100):
            current_data[target_idx] = test_byte
            from Crypto.Cipher import AES
            cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=bytes(b'\x00' * 16))
            decrypted = cipher.decrypt(current_data)
            if decrypted[target_idx+16] == pad_len:
                ctx.print(f"Found valid padding byte: 0x{test_byte:02x} for pad length 0x{pad_len:02x}")
                ctx.print(f"DECRYPTED0: {' '.join(f'{b:02x}' for b in decrypted[ 0:16])}")
                ctx.print(f"DECRYPTED1: {' '.join(f'{b:02x}' for b in decrypted[16:32])}")
                ctx.print(f"DECRYPTED2: {' '.join(f'{b:02x}' for b in decrypted[32:48])}")
                found_valid_padding = True
                break

        if not found_valid_padding:
            raise ValueError(f"Could not find valid padding byte for pad length 0x{pad_len:02x}.")
        ctx.print(f"GOLD(0x{pad_len:02x})    {' '.join(f'{b:02x}' for b in current_data[16:32])}")


        pad_len += 1
    
    ctx.print(f"Final encrypted data blob with 0x10 bytes PKCS7 padding:")
    ctx.print(f"ENCRYPTED0: {' '.join(f'{b:02x}' for b in current_data[ 0:16])}")
    ctx.print(f"ENCRYPTED1: {' '.join(f'{b:02x}' for b in current_data[16:32])}")
    ctx.print(f"ENCRYPTED2: {' '.join(f'{b:02x}' for b in current_data[32:48])}")

# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------
