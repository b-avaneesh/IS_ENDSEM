# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - Do not use the full EduSecure record-storage workflow.
# - Authenticate Diffie-Hellman public values using RSA signatures.
# - Derive the same AES key from the DH shared secret using SHA-256.
# - Measure DH key-generation and shared-secret computation time.
# =====================================================================
"""Authenticated Diffie-Hellman messaging with RSA and AES."""

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

def dh_generate_keypair(p=7919, g=2):
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def dh_shared_secret(other_public, my_private, p=7919):
    return pow(other_public, my_private, p)

def dh_encrypt(plaintext, shared_secret):
    key = hashlib.sha256(str(shared_secret).encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {"nonce": cipher.nonce, "tag": tag, "ciphertext": ciphertext}

def dh_decrypt(package, shared_secret):
    key = hashlib.sha256(str(shared_secret).encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX, nonce=package["nonce"])
    return cipher.decrypt_and_verify(package["ciphertext"], package["tag"]).decode()

def rsa_generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key

def rsa_sign(message_bytes, private_key):
    digest = SHA256.new(message_bytes)
    return pkcs1_15.new(private_key).sign(digest)

def rsa_verify(message_bytes, signature, public_key):
    digest = SHA256.new(message_bytes)
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


def main():
    from time import perf_counter
    message = input("Enter message: ")
    start = perf_counter()
    sender_public, sender_private = dh_generate_keypair()
    receiver_public, receiver_private = dh_generate_keypair()
    dh_time = perf_counter() - start

    sender_rsa_public, sender_rsa_private = rsa_generate_keys()
    signature = rsa_sign(str(sender_public).encode(), sender_rsa_private)
    signature_ok = rsa_verify(str(sender_public).encode(), signature, sender_rsa_public)

    start = perf_counter()
    sender_secret = dh_shared_secret(receiver_public, sender_private)
    receiver_secret = dh_shared_secret(sender_public, receiver_private)
    shared_time = perf_counter() - start
    package = dh_encrypt(message, sender_secret)

    print("Sender DH public:", sender_public)
    print("Receiver DH public:", receiver_public)
    print("DH public signature valid:", signature_ok)
    print("Shared secrets match:", sender_secret == receiver_secret)
    print("Ciphertext:", package["ciphertext"].hex())
    print("Decrypted:", dh_decrypt(package, receiver_secret))
    print("Key generation time:", dh_time)
    print("Shared-key computation time:", shared_time)


if __name__ == "__main__":
    main()
