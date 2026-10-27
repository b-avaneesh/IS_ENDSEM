"""CIA triad: RSA+AES encryption, SHA-256 and RSA signature."""

import hashlib
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def encrypt_data(data, public_key):
    aes_key = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    encrypted_key = PKCS1_OAEP.new(public_key).encrypt(aes_key)
    return encrypted_key, cipher.nonce, tag, ciphertext


def decrypt_data(encrypted_data, private_key):
    encrypted_key, nonce, tag, ciphertext = encrypted_data
    aes_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def hash_data(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def sign_data(data, private_key):
    if isinstance(data, str):
        data = data.encode()
    return pkcs1_15.new(private_key).sign(SHA256.new(data))


def verify_signature(data, signature, public_key):
    if isinstance(data, str):
        data = data.encode()
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    data = input("Enter data: ")
    receiver_public, receiver_private = generate_keys()
    sender_public, sender_private = generate_keys()
    encrypted = encrypt_data(data, receiver_public)
    signature = sign_data(encrypted[3], sender_private)
    print("Encrypted hex:", encrypted[3].hex())
    print("Hash:", hash_data(encrypted[3]))
    print("Signature valid:", verify_signature(encrypted[3], signature, sender_public))
    print("Decrypted:", decrypt_data(encrypted, receiver_private))
