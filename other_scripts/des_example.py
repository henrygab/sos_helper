from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes


def generate_des_key() -> bytes:
    # DES key is 8 bytes, of which the least significant bit of each byte is a parity bit (56 bits + 8 parity bits)
    key_without_parity = get_random_bytes(8)  # Generate a random 8-byte key
    
    # Clear the least significant bit of each byte
    key_with_parity = bytearray((b & 0xFE) for b in key_without_parity)
    
    # Set the parity bit of each byte to ensure odd parity
    for i in range(len(key_without_parity)):
        parity_bit = 1 if (bin(key_with_parity[i]).count('1') % 2 == 0) else 0
        key_with_parity[i] |= parity_bit

    return bytes(key_with_parity)

# Perform the DES encryption and decryption
key = generate_des_key()
cipher = DES.new(key, DES.MODE_ECB)

plaintext = b"henrygab"  # 8 bytes
# DES block size is 8 bytes, so plaintext must be a multiple of 8 bytes
ciphertext = cipher.encrypt(plaintext)

cleartext = cipher.decrypt(ciphertext)


print("Original   (hex):", plaintext.hex())
print("Key        (hex):", key.hex())
print("Ciphertext (hex):", ciphertext.hex())
print("Cleartext  (hex):", cleartext.hex())

if plaintext == cleartext:
    print("Success: Cleartext matches original plaintext.")
else:
    print("*****Error******: Cleartext does not match original plaintext.")

