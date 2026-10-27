from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad


key = b"A1B2C3D4"

ciphertext_hex = input("Enter ciphertext in hex: ")

ciphertext = bytes.fromhex(ciphertext_hex)

cipher = DES.new(key, DES.MODE_ECB)

plaintext = unpad(
    cipher.decrypt(ciphertext),
    DES.block_size
)

print("Decrypted:", plaintext.decode())