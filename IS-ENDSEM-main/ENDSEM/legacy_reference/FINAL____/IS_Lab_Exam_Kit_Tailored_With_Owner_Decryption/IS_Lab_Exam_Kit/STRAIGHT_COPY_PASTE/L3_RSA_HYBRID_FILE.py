"""RSA-2048 + AES file encryption - copy this file. Requires PyCryptodome."""

import os
import pickle
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def encrypt_data(data, public_key):
    aes_key = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_key = PKCS1_OAEP.new(public_key).encrypt(aes_key)
    return encrypted_key, cipher.nonce, tag, ciphertext


def decrypt_data(encrypted_data, private_key):
    encrypted_key, nonce, tag, ciphertext = encrypted_data
    aes_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


if __name__ == "__main__":
    input_file = input("Enter input file path: ")
    output_file = input("Enter recovered output path: ")
    public_key, private_key = generate_keys()

    with open(input_file, "rb") as file:
        original = file.read()
    encrypted = encrypt_data(original, public_key)
    with open("encrypted_file.bin", "wb") as file:
        pickle.dump(encrypted, file)

    with open("encrypted_file.bin", "rb") as file:
        encrypted = pickle.load(file)
    recovered = decrypt_data(encrypted, private_key)
    with open(output_file, "wb") as file:
        file.write(recovered)

    print("File recovered correctly:", original == recovered)
