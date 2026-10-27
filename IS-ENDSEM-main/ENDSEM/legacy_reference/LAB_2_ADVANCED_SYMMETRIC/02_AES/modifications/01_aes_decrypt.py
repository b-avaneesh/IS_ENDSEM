from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# AES-128 key
key = b"0123456789ABCDEF"

# Take ciphertext input in HEX
ciphertext_hex = input("Enter ciphertext (HEX): ")

# Convert HEX string to bytes
ciphertext = bytes.fromhex(ciphertext_hex)

# Create AES cipher
cipher = AES.new(key, AES.MODE_ECB)

# Decrypt
padded_text = cipher.decrypt(ciphertext)

# Remove padding
plaintext = unpad(padded_text, AES.block_size)

# Convert bytes to string
plaintext = plaintext.decode()

# Display plaintext
print("Decrypted:", plaintext)