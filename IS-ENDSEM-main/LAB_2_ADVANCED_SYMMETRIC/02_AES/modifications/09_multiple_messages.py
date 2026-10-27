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

messages = [
    "Message One",
    "Message Two",
    "Message Three",
    "Message Four",
    "Message Five"
]


# ---------------- ECB ----------------

print("===== ECB =====")

for message in messages:

    plaintext = message.encode()
    padded_text = pad(plaintext, AES.block_size)

    cipher = AES.new(key, AES.MODE_ECB)

    start = time.perf_counter()

    ciphertext = cipher.encrypt(padded_text)

    end = time.perf_counter()

    print("\nMessage:", message)
    print("Encrypted (HEX):", ciphertext.hex())
    print("Time:", end - start, "seconds")


# ---------------- CBC ----------------

print("\n===== CBC =====")

for message in messages:

    plaintext = message.encode()
    padded_text = pad(plaintext, AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    start = time.perf_counter()

    ciphertext = cipher.encrypt(padded_text)

    end = time.perf_counter()

    print("\nMessage:", message)
    print("Encrypted (HEX):", ciphertext.hex())
    print("Time:", end - start, "seconds")