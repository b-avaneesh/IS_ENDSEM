from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time

# AES-128 key
key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

# CBC IV
iv = bytes.fromhex(
    "00000000000000000000000000000000"
)

plaintext = input("Enter plaintext: ")
plaintext = plaintext.encode()

# Pad plaintext
padded_text = pad(plaintext, AES.block_size)


# ---------------- ECB ----------------

cipher = AES.new(key, AES.MODE_ECB)

start = time.perf_counter()

ecb_ciphertext = cipher.encrypt(padded_text)

end = time.perf_counter()

ecb_time = end - start


# ---------------- CBC ----------------

cipher = AES.new(key, AES.MODE_CBC, iv)

start = time.perf_counter()

cbc_ciphertext = cipher.encrypt(padded_text)

end = time.perf_counter()

cbc_time = end - start


# ---------------- OUTPUT ----------------

print("\nECB Ciphertext (HEX):", ecb_ciphertext.hex())
print("ECB Encryption Time:", ecb_time, "seconds")

print("\nCBC Ciphertext (HEX):", cbc_ciphertext.hex())
print("CBC Encryption Time:", cbc_time, "seconds")