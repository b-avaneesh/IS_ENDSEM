"""ECC (P-256) + AES encryption - copy this file. Requires PyCryptodome."""

import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC


def generate_keys():
    private_key = ECC.generate(curve="P-256")
    return private_key.public_key(), private_key


def make_aes_key(point):
    x = int(point.x).to_bytes(32, "big")
    return hashlib.sha256(x).digest()


def encrypt_data(data, public_key):
    temporary_private = ECC.generate(curve="P-256")
    shared_point = public_key.pointQ * temporary_private.d
    cipher = AES.new(make_aes_key(shared_point), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return temporary_private.public_key(), cipher.nonce, tag, ciphertext


def decrypt_data(encrypted_data, private_key):
    temporary_public, nonce, tag, ciphertext = encrypted_data
    shared_point = temporary_public.pointQ * private_key.d
    cipher = AES.new(make_aes_key(shared_point), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    public_key, private_key = generate_keys()
    encrypted = encrypt_data(data, public_key)
    print("Encrypted hex:", encrypted[3].hex())
    print("Decrypted:", decrypt_data(encrypted, private_key))

