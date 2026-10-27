"""DES CBC - copy this complete file. Requires PyCryptodome."""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def make_bytes(text, size):
    return text.encode()[:size].ljust(size, b"0")


def encrypt_data(data, key, iv):
    cipher = DES.new(make_bytes(key, 8), DES.MODE_CBC, make_bytes(iv, 8))
    return cipher.encrypt(pad(data.encode(), 8))


def decrypt_data(encrypted_data, key, iv):
    cipher = DES.new(make_bytes(key, 8), DES.MODE_CBC, make_bytes(iv, 8))
    return unpad(cipher.decrypt(encrypted_data), 8).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter DES key: ")
    iv = input("Enter 8-character IV: ")
    encrypted = encrypt_data(data, key, iv)
    print("Encrypted hex:", encrypted.hex())
    print("Decrypted:", decrypt_data(encrypted, key, iv))

