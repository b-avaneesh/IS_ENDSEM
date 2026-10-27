# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - Use a short algorithm menu rather than the complete EduSecure system.
# - Generate and verify both ElGamal and Schnorr digital signatures.
# - Sign the original message, modify one character and verify again.
# - The original must pass and the tampered message must fail.
# =====================================================================
"""ElGamal and Schnorr signatures with tampering."""

import hashlib

import json

import os

import random

import socket

import sys

from base64 import b64decode, b64encode

from math import gcd

from Crypto.Cipher import AES, PKCS1_OAEP

from Crypto.Hash import SHA256

from Crypto.PublicKey import RSA

from Crypto.Signature import pkcs1_15

def hash_number(message, modulus):
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, "big") % modulus

def elgamal_generate_keys(p=7919, g=2):
    private_key = random.randint(2, p - 2)
    public_key = (p, g, pow(g, private_key, p))
    return public_key, private_key

def elgamal_sign(message, private_key, p=7919, g=2):
    message_hash = hash_number(message, p - 1)
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((message_hash - private_key * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s

def elgamal_verify(message, signature, public_key):
    p, g, y = public_key
    r, s = signature
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    message_hash = hash_number(message, p - 1)
    left = pow(g, message_hash, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

def elgamal_encrypt(plaintext, public_key):
    """Encryption/decryption included for reference even though Q1 asks signatures."""
    p, g, y = public_key
    encrypted = []
    for byte in plaintext.encode():
        k = random.randint(2, p - 2)
        encrypted.append((pow(g, k, p), byte * pow(y, k, p) % p))
    return encrypted

def elgamal_decrypt(ciphertext, private_key, p=7919):
    recovered = []
    for c1, c2 in ciphertext:
        shared = pow(c1, private_key, p)
        recovered.append(c2 * pow(shared, -1, p) % p)
    return bytes(recovered).decode()

def schnorr_generate_keys(p=23, q=11, g=2):
    private_key = random.randint(1, q - 1)
    public_key = pow(g, private_key, p)
    return (p, q, g, public_key), private_key

def schnorr_sign(message, private_key, p=23, q=11, g=2):
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    challenge = hash_number(message + str(r), q)
    response = (k - private_key * challenge) % q
    return challenge, response

def schnorr_verify(message, signature, public_key):
    p, q, g, y = public_key
    challenge, response = signature
    reconstructed_r = (pow(g, response, p) * pow(y, challenge, p)) % p
    expected_challenge = hash_number(message + str(reconstructed_r), q)
    return expected_challenge == challenge


def main():
    message = input("Message: "); choice = input("1 ElGamal  2 Schnorr: ")
    if choice == "1":
        public, private = elgamal_generate_keys(); signature = elgamal_sign(message, private)
        verify = elgamal_verify
    else:
        public, private = schnorr_generate_keys(); signature = schnorr_sign(message, private)
        verify = schnorr_verify
    print("Signature:", signature); print("Original valid:", verify(message, signature, public))
    print("Tampered valid:", verify(message + "X", signature, public))


if __name__ == "__main__": main()
