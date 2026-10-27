"""Diffie-Hellman shared key + AES - copy this file. Requires PyCryptodome."""

import hashlib
import random
from Crypto.Cipher import AES

P = 7919
G = 2


def generate_keys():
    private_key = random.randint(2, P - 2)
    public_key = pow(G, private_key, P)
    return public_key, private_key


def get_shared_key(other_public_key, private_key):
    secret = pow(other_public_key, private_key, P)
    return hashlib.sha256(str(secret).encode()).digest()


def encrypt_data(data, shared_key):
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce, tag, ciphertext


def decrypt_data(encrypted_data, shared_key):
    nonce, tag, ciphertext = encrypted_data
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    alice_public, alice_private = generate_keys()
    bob_public, bob_private = generate_keys()
    alice_key = get_shared_key(bob_public, alice_private)
    bob_key = get_shared_key(alice_public, bob_private)
    encrypted = encrypt_data(data, alice_key)
    print("Shared keys match:", alice_key == bob_key)
    print("Encrypted hex:", encrypted[2].hex())
    print("Decrypted:", decrypt_data(encrypted, bob_key))

