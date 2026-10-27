from Crypto.Cipher import AES

# AES-128 key
key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

# 8-byte nonce
nonce = bytes.fromhex(
    "0000000000000000"
)

# Take plaintext input
plaintext = input("Enter plaintext: ")

# Convert string to bytes
plaintext = plaintext.encode()

# Create AES-CTR cipher
cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce
)

# Encrypt
ciphertext = cipher.encrypt(plaintext)

print("Encrypted (HEX):", ciphertext.hex())

# Create cipher again for decryption
cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce
)

# Decrypt
decrypted = cipher.decrypt(ciphertext)

print("Decrypted:", decrypted.decode())