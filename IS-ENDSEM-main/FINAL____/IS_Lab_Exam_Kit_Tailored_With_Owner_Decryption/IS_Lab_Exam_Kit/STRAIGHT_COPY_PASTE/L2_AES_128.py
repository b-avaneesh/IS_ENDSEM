"""AES-128 ECB - copy this complete file. Requires PyCryptodome."""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def make_key(key_text):
    # A 32-character hexadecimal value is exactly 16 bytes.
    key = bytes.fromhex(key_text) if len(key_text) == 32 else key_text.encode()
    return key[:16].ljust(16, b"0")


def encrypt_data(data, key):
    cipher = AES.new(make_key(key), AES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), 16))


def decrypt_data(encrypted_data, key):
    cipher = AES.new(make_key(key), AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), 16).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter AES-128 key: ")
    encrypted = encrypt_data(data, key)
    print("Encrypted hex:", encrypted.hex())
    print("Decrypted:", decrypt_data(encrypted, key))
