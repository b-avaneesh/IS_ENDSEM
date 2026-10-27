"""Triple DES - copy this complete file. Requires PyCryptodome."""

import hashlib
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def make_key(key_text):
    key = bytes.fromhex(key_text) if len(key_text) == 48 else key_text.encode()
    key = key[:24].ljust(24, b"0")
    try:
        key = DES3.adjust_key_parity(key)
        DES3.new(key, DES3.MODE_ECB)  # Reject a key that becomes ordinary DES.
        return key
    except ValueError:
        return DES3.adjust_key_parity(hashlib.sha256(key_text.encode()).digest()[:24])


def encrypt_data(data, key):
    cipher = DES3.new(make_key(key), DES3.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), 8))


def decrypt_data(encrypted_data, key):
    cipher = DES3.new(make_key(key), DES3.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), 8).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter Triple DES key: ")
    encrypted = encrypt_data(data, key)
    print("Encrypted hex:", encrypted.hex())
    print("Decrypted:", decrypt_data(encrypted, key))
