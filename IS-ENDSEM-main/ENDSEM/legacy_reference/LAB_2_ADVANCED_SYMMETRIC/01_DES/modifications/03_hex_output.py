from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# DES key in hexadecimal
key = bytes.fromhex("A1B2C3D4E5F60708")

# Enter plaintext as hexadecimal
hex_data = input("Enter plaintext in HEX: ")

# Convert HEX string to bytes
plaintext = bytes.fromhex(hex_data)

# Create DES cipher
cipher = DES.new(key, DES.MODE_ECB)

# Pad plaintext
padded_text = pad(plaintext, DES.block_size)

# Encrypt
ciphertext = cipher.encrypt(padded_text)

# Display ciphertext in HEX
print("Encrypted (HEX):", ciphertext.hex())


# Decryption
cipher = DES.new(key, DES.MODE_ECB)

decrypted = cipher.decrypt(ciphertext)

# Remove padding
decrypted = unpad(decrypted, DES.block_size)

# Display decrypted data in HEX
print("Decrypted (HEX):", decrypted.hex())

# Display decrypted data as text
print("Decrypted (Text):", decrypted.decode())