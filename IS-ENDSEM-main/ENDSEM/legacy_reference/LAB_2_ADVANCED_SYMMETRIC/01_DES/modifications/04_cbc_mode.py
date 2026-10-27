from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


key = b"A1B2C3D4"
iv = b"12345678"

plaintext = input("Enter plaintext: ")

cipher = DES.new(
    key,
    DES.MODE_CBC,
    iv=iv
)

ciphertext = cipher.encrypt(
    pad(plaintext.encode(), DES.block_size)
)

print("Encrypted:", ciphertext.hex())


cipher = DES.new(
    key,
    DES.MODE_CBC,
    iv=iv
)

decrypted = unpad(
    cipher.decrypt(ciphertext),
    DES.block_size
)

print("Decrypted:", decrypted.decode())