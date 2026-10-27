from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES-128 key written as HEX
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")

# Take plaintext in HEX
hex_plaintext = input("Enter plaintext in HEX: ")

# Convert HEX to bytes
plaintext = bytes.fromhex(hex_plaintext)

# Create AES cipher
cipher = AES.new(key, AES.MODE_ECB)

# Pad plaintext
padded_text = pad(plaintext, AES.block_size)

# Encrypt
ciphertext = cipher.encrypt(padded_text)

# Display ciphertext in HEX
print("Encrypted (HEX):", ciphertext.hex())

# Decryption
cipher = AES.new(key, AES.MODE_ECB)

decrypted = cipher.decrypt(ciphertext)

# Remove padding
decrypted = unpad(decrypted, AES.block_size)

# Display decrypted data
print("Decrypted (HEX):", decrypted.hex())