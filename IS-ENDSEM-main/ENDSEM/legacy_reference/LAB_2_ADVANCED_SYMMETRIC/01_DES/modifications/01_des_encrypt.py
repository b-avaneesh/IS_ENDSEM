from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


key = b"A1B2C3D4"

plaintext = input("Enter plaintext: ")

cipher = DES.new(key, DES.MODE_ECB)

padded_text = pad(plaintext.encode(), DES.block_size)

ciphertext = cipher.encrypt(padded_text)

print("Encrypted:", ciphertext.hex())


cipher = DES.new(key, DES.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(ciphertext),
    DES.block_size
)

print("Decrypted:", decrypted.decode())