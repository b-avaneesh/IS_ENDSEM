from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES-128 key
key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

# ---------------- ENCRYPTION ----------------

# Read file as bytes
with open("input.txt", "rb") as file:
    plaintext = file.read()

# Create AES cipher
cipher = AES.new(key, AES.MODE_ECB)

# Pad data
padded_text = pad(plaintext, AES.block_size)

# Encrypt
ciphertext = cipher.encrypt(padded_text)

# Save encrypted data
with open("encrypted.bin", "wb") as file:
    file.write(ciphertext)

print("File encrypted successfully.")


# ---------------- DECRYPTION ----------------

# Read encrypted file
with open("encrypted.bin", "rb") as file:
    ciphertext = file.read()

# Create AES cipher again
cipher = AES.new(key, AES.MODE_ECB)

# Decrypt
decrypted = cipher.decrypt(ciphertext)

# Remove padding
decrypted = unpad(decrypted, AES.block_size)

# Save decrypted data
with open("decrypted.txt", "wb") as file:
    file.write(decrypted)

print("File decrypted successfully.")