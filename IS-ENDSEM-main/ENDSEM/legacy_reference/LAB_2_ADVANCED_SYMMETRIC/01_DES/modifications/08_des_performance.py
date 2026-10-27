from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import time

key = b"A1B2C3D4"

plaintext = input("Enter plaintext: ")

padded_text = pad(plaintext.encode(), DES.block_size)

# Encryption timing
cipher = DES.new(key, DES.MODE_ECB)

start = time.perf_counter()

ciphertext = cipher.encrypt(padded_text)

end = time.perf_counter()

encryption_time = end - start

print("Ciphertext:", ciphertext.hex())
print("Encryption time:", encryption_time, "seconds")


# Decryption timing
cipher = DES.new(key, DES.MODE_ECB)

start = time.perf_counter()

decrypted = cipher.decrypt(ciphertext)

end = time.perf_counter()

decryption_time = end - start

print("Decryption time:", decryption_time, "seconds")