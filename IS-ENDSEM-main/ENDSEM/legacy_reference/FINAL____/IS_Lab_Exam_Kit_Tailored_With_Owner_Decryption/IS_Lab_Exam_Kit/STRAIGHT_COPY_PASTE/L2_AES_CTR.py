"""AES CTR - copy this complete file. Requires PyCryptodome."""

from Crypto.Cipher import AES


def make_key(key_text):
    key = bytes.fromhex(key_text) if len(key_text) == 32 else key_text.encode()
    return key[:16].ljust(16, b"0")


def make_nonce(nonce_text):
    nonce = bytes.fromhex(nonce_text) if len(nonce_text) == 16 else nonce_text.encode()
    return nonce[:8].ljust(8, b"0")


def encrypt_data(data, key, nonce):
    cipher = AES.new(make_key(key), AES.MODE_CTR, nonce=make_nonce(nonce))
    return cipher.encrypt(data.encode())


def decrypt_data(encrypted_data, key, nonce):
    cipher = AES.new(make_key(key), AES.MODE_CTR, nonce=make_nonce(nonce))
    return cipher.decrypt(encrypted_data).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    key = input("Enter AES key: ")
    nonce = input("Enter nonce: ")
    encrypted = encrypt_data(data, key, nonce)
    print("Encrypted hex:", encrypted.hex())
    print("Decrypted:", decrypt_data(encrypted, key, nonce))
