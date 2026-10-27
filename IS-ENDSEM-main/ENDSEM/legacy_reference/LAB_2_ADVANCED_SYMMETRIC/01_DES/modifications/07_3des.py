from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex(
    "1234567890ABCDEF234567890ABCDEF134567890ABCDEF12"
)

plaintext = input("Enter plaintext: ")

cipher = DES3.new(key, DES3.MODE_ECB)

padded_text = pad(plaintext.encode(), DES3.block_size)

ciphertext = cipher.encrypt(padded_text)

print("Encrypted:", ciphertext.hex())


cipher = DES3.new(key, DES3.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(ciphertext),
    DES3.block_size
)

print("Decrypted:", decrypted.decode())