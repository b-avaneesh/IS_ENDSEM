"""RSA-protected DH exchange + AES message. Requires PyCryptodome."""

import hashlib
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

P, G = 7919, 2


def generate_keys():
    rsa_private = RSA.generate(2048)
    dh_private = random.randint(2, P - 2)
    dh_public = pow(G, dh_private, P)
    return rsa_private.publickey(), rsa_private, dh_public, dh_private


def protect_public_value(value, rsa_public_key):
    return PKCS1_OAEP.new(rsa_public_key).encrypt(str(value).encode())


def recover_public_value(value, rsa_private_key):
    return int(PKCS1_OAEP.new(rsa_private_key).decrypt(value).decode())


def make_shared_key(other_public, private_key):
    secret = pow(other_public, private_key, P)
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
    data = input("Enter message: ")
    a_rsa_pub, a_rsa_priv, a_dh_pub, a_dh_priv = generate_keys()
    b_rsa_pub, b_rsa_priv, b_dh_pub, b_dh_priv = generate_keys()
    received_a = recover_public_value(protect_public_value(a_dh_pub, b_rsa_pub), b_rsa_priv)
    received_b = recover_public_value(protect_public_value(b_dh_pub, a_rsa_pub), a_rsa_priv)
    a_key = make_shared_key(received_b, a_dh_priv)
    b_key = make_shared_key(received_a, b_dh_priv)
    encrypted = encrypt_data(data, a_key)
    print("Encrypted hex:", encrypted[2].hex())
    print("Decrypted:", decrypt_data(encrypted, b_key))

