from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b"A1B2C3D4"

# ---------------- ENCRYPTION ----------------

with open("input.txt", "rb") as f:
    plaintext = f.read()

cipher = DES.new(key, DES.MODE_ECB)

padded_text = pad(plaintext, DES.block_size)

ciphertext = cipher.encrypt(padded_text)

with open("encrypted.bin", "wb") as f:
    f.write(ciphertext)

print("File encrypted successfully.")
print("Encrypted data:", ciphertext.hex())


# ---------------- DECRYPTION ----------------

cipher = DES.new(key, DES.MODE_ECB)

decrypted = cipher.decrypt(ciphertext)

decrypted = unpad(decrypted, DES.block_size)

with open("decrypted.txt", "wb") as f:
    f.write(decrypted)

print("File decrypted successfully.")