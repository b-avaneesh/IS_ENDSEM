from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time


# ---------------- INPUT ----------------

plaintext = input("Enter plaintext: ")
plaintext = plaintext.encode()


# ---------------- DES ----------------

des_key = b"A1B2C3D4"

des_padded = pad(plaintext, DES.block_size)

# Encryption
des_cipher = DES.new(des_key, DES.MODE_ECB)

start = time.perf_counter()
des_ciphertext = des_cipher.encrypt(des_padded)
end = time.perf_counter()

des_encrypt_time = end - start

# Decryption
des_cipher = DES.new(des_key, DES.MODE_ECB)

start = time.perf_counter()
des_decrypted = des_cipher.decrypt(des_ciphertext)
end = time.perf_counter()

des_decrypt_time = end - start

des_decrypted = unpad(des_decrypted, DES.block_size)


# ---------------- AES-128 ----------------

aes_key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

aes_padded = pad(plaintext, AES.block_size)

# Encryption
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

start = time.perf_counter()
aes_ciphertext = aes_cipher.encrypt(aes_padded)
end = time.perf_counter()

aes_encrypt_time = end - start

# Decryption
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

start = time.perf_counter()
aes_decrypted = aes_cipher.decrypt(aes_ciphertext)
end = time.perf_counter()

aes_decrypt_time = end - start

aes_decrypted = unpad(aes_decrypted, AES.block_size)


# ---------------- OUTPUT ----------------

print("\n========== DES ==========")
print("Encrypted (HEX):", des_ciphertext.hex())
print("Decrypted:", des_decrypted.decode())
print("Encryption Time:", des_encrypt_time, "seconds")
print("Decryption Time:", des_decrypt_time, "seconds")

print("\n========== AES-128 ==========")
print("Encrypted (HEX):", aes_ciphertext.hex())
print("Decrypted:", aes_decrypted.decode())
print("Encryption Time:", aes_encrypt_time, "seconds")
print("Decryption Time:", aes_decrypt_time, "seconds")