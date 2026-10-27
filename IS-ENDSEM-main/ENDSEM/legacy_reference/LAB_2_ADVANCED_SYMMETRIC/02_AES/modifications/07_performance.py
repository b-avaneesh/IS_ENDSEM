from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

# AES-128 key
key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

plaintext = input("Enter plaintext: ")
plaintext = plaintext.encode()

# Pad plaintext
padded_text = pad(plaintext, AES.block_size)


# ---------------- ENCRYPTION ----------------

cipher = AES.new(key, AES.MODE_ECB)

start = time.perf_counter()

ciphertext = cipher.encrypt(padded_text)

end = time.perf_counter()

encryption_time = end - start


# ---------------- DECRYPTION ----------------

cipher = AES.new(key, AES.MODE_ECB)

start = time.perf_counter()

decrypted = cipher.decrypt(ciphertext)

end = time.perf_counter()

decryption_time = end - start

# Remove padding
decrypted = unpad(decrypted, AES.block_size)


# ---------------- OUTPUT ----------------

print("\nEncrypted (HEX):", ciphertext.hex())
print("Decrypted:", decrypted.decode())

print("\nEncryption time:", encryption_time, "seconds")
print("Decryption time:", decryption_time, "seconds")