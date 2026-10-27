# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - Replace the role system with a direct RSA-versus-ElGamal experiment.
# - Implement key generation, encryption and decryption for both algorithms.
# - Use the same plaintext and verify that both recover it correctly.
# - Compare key-generation, encryption, decryption time and ciphertext size.
# =====================================================================
"""RSA versus ElGamal performance."""

import hashlib

import json

import os

import random

import time

from base64 import b64decode, b64encode

from math import gcd

from Crypto.Cipher import AES, PKCS1_OAEP

from Crypto.PublicKey import ECC, RSA

def rsa_generate_keys(p=61, q=53, e=17):
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi(n)")
    d = pow(e, -1, phi)
    return (n, e), (n, d)

def rsa_encrypt(plaintext, public_key):
    n, e = public_key
    data = plaintext.encode()
    if any(byte >= n for byte in data):
        raise ValueError("n must be larger than every plaintext byte")
    return [pow(byte, e, n) for byte in data]

def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    data = bytes(pow(number, d, n) for number in ciphertext)
    return data.decode()

def elgamal_generate_keys(p=7919, g=2, private_key=None):
    x = private_key if private_key is not None else random.randint(2, p - 2)
    h = pow(g, x, p)
    return (p, g, h), x

def elgamal_encrypt(plaintext, public_key):
    p, g, h = public_key
    ciphertext = []
    for byte in plaintext.encode():
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        c2 = (byte * pow(h, k, p)) % p
        ciphertext.append((c1, c2))
    return ciphertext

def elgamal_decrypt(ciphertext, private_key, p=7919):
    recovered = []
    for c1, c2 in ciphertext:
        shared_secret = pow(c1, private_key, p)
        byte = (c2 * pow(shared_secret, -1, p)) % p
        recovered.append(byte)
    return bytes(recovered).decode()


def measure(name, key_function, encrypt_function, decrypt_function, message):
    from time import perf_counter
    start = perf_counter(); public, private = key_function(); key_time = perf_counter() - start
    start = perf_counter(); encrypted = encrypt_function(message, public); enc_time = perf_counter() - start
    start = perf_counter(); recovered = decrypt_function(encrypted, private); dec_time = perf_counter() - start
    print(name, "key:", key_time, "encrypt:", enc_time, "decrypt:", dec_time,
          "cipher items:", len(encrypted), "recovered:", recovered)


if __name__ == "__main__":
    text = input("Message: ")
    measure("RSA", rsa_generate_keys, rsa_encrypt, rsa_decrypt, text)
    measure("ElGamal", elgamal_generate_keys, elgamal_encrypt, elgamal_decrypt, text)
