from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES-128 key
key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

# AES CBC IV
iv = bytes.fromhex(
    "00000000000000000000000000000000"
)

# Take plaintext input
plaintext = input("Enter plaintext: ")

# Convert string to bytes
plaintext = plaintext.encode()

# Create AES-CBC cipher
cipher = AES.new(key, AES.MODE_CBC, iv)

# Pad plaintext
padded_text = pad(plaintext, AES.block_size)

# Encrypt
ciphertext = cipher.encrypt(padded_text)

print("Encrypted (HEX):", ciphertext.hex())

# Create cipher again for decryption
cipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt
decrypted = cipher.decrypt(ciphertext)

# Remove padding
decrypted = unpad(decrypted, AES.block_size)

# Convert bytes to string
print("Decrypted:", decrypted.decode())