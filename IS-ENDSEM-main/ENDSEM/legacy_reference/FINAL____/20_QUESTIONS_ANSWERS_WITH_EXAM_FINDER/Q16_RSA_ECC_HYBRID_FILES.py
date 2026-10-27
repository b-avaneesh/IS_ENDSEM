# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - No EduSecure menus or roles are needed unless explicitly requested.
# - Encrypt two binary files using both RSA-AES and ECC-AES hybrid schemes.
# - Decrypt each package and compare original/recovered SHA-256 hashes.
# - Measure key-generation, encryption and decryption times.
# =====================================================================
"""RSA and ECC hybrid file encryption comparison."""

import hashlib

import json

import os

import random

import time

from base64 import b64decode, b64encode

from math import gcd

from Crypto.Cipher import AES, PKCS1_OAEP

from Crypto.PublicKey import ECC, RSA

def rsa_2048_generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key

def rsa_hybrid_encrypt_bytes(data, rsa_public_key):
    aes_key = os.urandom(16)
    aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes.encrypt_and_digest(data)
    encrypted_key = PKCS1_OAEP.new(rsa_public_key).encrypt(aes_key)
    return {
        "encrypted_key": encrypted_key,
        "nonce": aes.nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }

def rsa_hybrid_decrypt_bytes(package, rsa_private_key):
    aes_key = PKCS1_OAEP.new(rsa_private_key).decrypt(package["encrypted_key"])
    aes = AES.new(aes_key, AES.MODE_EAX, nonce=package["nonce"])
    return aes.decrypt_and_verify(package["ciphertext"], package["tag"])

def ecc_generate_keys():
    private_key = ECC.generate(curve="P-256")  # secp256r1
    return private_key.public_key(), private_key

def point_to_aes_key(point):
    x_coordinate = int(point.x).to_bytes(32, "big")
    return hashlib.sha256(x_coordinate).digest()

def ecc_encrypt_bytes(data, recipient_public_key):
    temporary_private = ECC.generate(curve="P-256")
    shared_point = recipient_public_key.pointQ * temporary_private.d
    aes_key = point_to_aes_key(shared_point)
    aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes.encrypt_and_digest(data)
    return {
        "temporary_public_key": temporary_private.public_key().export_key(format="PEM").encode(),
        "nonce": aes.nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }

def ecc_decrypt_bytes(package, recipient_private_key):
    temporary_public = ECC.import_key(package["temporary_public_key"])
    shared_point = temporary_public.pointQ * recipient_private_key.d
    aes_key = point_to_aes_key(shared_point)
    aes = AES.new(aes_key, AES.MODE_EAX, nonce=package["nonce"])
    return aes.decrypt_and_verify(package["ciphertext"], package["tag"])


def test_file(filename):
    from pathlib import Path
    from time import perf_counter
    original = Path(filename).read_bytes()
    for name in ("RSA", "ECC"):
        start = perf_counter()
        public, private = rsa_2048_generate_keys() if name == "RSA" else ecc_generate_keys()
        key_time = perf_counter() - start
        start = perf_counter()
        package = rsa_hybrid_encrypt_bytes(original, public) if name == "RSA" else ecc_encrypt_bytes(original, public)
        enc_time = perf_counter() - start
        start = perf_counter()
        recovered = rsa_hybrid_decrypt_bytes(package, private) if name == "RSA" else ecc_decrypt_bytes(package, private)
        dec_time = perf_counter() - start
        print(name, "SHA-256 match:", hashlib.sha256(original).digest() == hashlib.sha256(recovered).digest())
        print("key:", key_time, "encrypt:", enc_time, "decrypt:", dec_time)


if __name__ == "__main__":
    test_file(input("First file: ")); test_file(input("Second file: "))
