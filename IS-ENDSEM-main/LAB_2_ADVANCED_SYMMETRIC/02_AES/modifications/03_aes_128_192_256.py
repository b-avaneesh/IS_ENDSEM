from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Choose AES key size
choice = input("Enter AES key size (128/192/256): ")

if choice == "128":
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
    )

elif choice == "192":
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    )

elif choice == "256":
    key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF"
    )

else:
    print("Invalid AES key size")
    exit()

plaintext = input("Enter plaintext: ")

# Convert string to bytes
plaintext = plaintext.encode()

# Create AES cipher
cipher = AES.new(key, AES.MODE_ECB)

# Pad plaintext
padded_text = pad(plaintext, AES.block_size)

# Encrypt
ciphertext = cipher.encrypt(padded_text)

print("Encrypted (HEX):", ciphertext.hex())

# Decrypt
cipher = AES.new(key, AES.MODE_ECB)

decrypted = cipher.decrypt(ciphertext)

# Remove padding
decrypted = unpad(decrypted, AES.block_size)

print("Decrypted:", decrypted.decode())