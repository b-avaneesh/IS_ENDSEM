"""DES ECB - copy this complete file. Requires PyCryptodome."""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def make_key(key_text):
    return key_text.encode()[:8].ljust(8, b"0")


def encrypt_data(data, key):
    cipher = DES.new(make_key(key), DES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), 8))


def decrypt_data(encrypted_data, key):
    cipher = DES.new(make_key(key), DES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), 8).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter DES key: ")
    encrypted = encrypt_data(data, key)
    print("Encrypted hex:", encrypted.hex())
    print("Decrypted:", decrypt_data(encrypted, key))

