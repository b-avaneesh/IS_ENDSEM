"""DES/AES encryption, decryption and timing - copy this complete file."""

import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad


def make_key(key_text, algorithm):
    size = 8 if algorithm.upper() == "DES" else int(algorithm.split("-")[1]) // 8
    return key_text.encode()[:size].ljust(size, b"0")


def encrypt_data(data, key, algorithm="AES-128"):
    module = DES if algorithm.upper() == "DES" else AES
    cipher = module.new(make_key(key, algorithm), module.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), module.block_size))


def decrypt_data(encrypted_data, key, algorithm="AES-128"):
    module = DES if algorithm.upper() == "DES" else AES
    cipher = module.new(make_key(key, algorithm), module.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), module.block_size).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter key: ")
    for algorithm in ["DES", "AES-128", "AES-192", "AES-256"]:
        start = time.perf_counter()
        encrypted = encrypt_data(data, key, algorithm)
        decrypted = decrypt_data(encrypted, key, algorithm)
        print(algorithm, "hex:", encrypted.hex())
        print(algorithm, "decrypted:", decrypted)
        print(algorithm, "time:", time.perf_counter() - start)
