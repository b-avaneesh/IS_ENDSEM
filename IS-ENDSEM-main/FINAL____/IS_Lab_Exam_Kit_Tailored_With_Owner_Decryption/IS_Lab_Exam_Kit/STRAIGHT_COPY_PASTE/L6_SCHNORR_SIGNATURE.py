"""Schnorr digital signature with small learning values."""

import hashlib
import random

P, Q, G = 23, 11, 2


def generate_keys():
    private_key = random.randint(1, Q - 1)
    return (P, Q, G, pow(G, private_key, P)), private_key


def hash_data(data):
    return int.from_bytes(hashlib.sha256(data.encode()).digest(), "big") % Q


def sign_data(data, private_key):
    k = random.randint(1, Q - 1)
    r = pow(G, k, P)
    challenge = hash_data(data + str(r))
    response = (k - private_key * challenge) % Q
    return challenge, response


def verify_signature(data, signature, public_key):
    p, q, g, y = public_key
    challenge, response = signature
    r = pow(g, response, p) * pow(y, challenge, p) % p
    return hash_data(data + str(r)) == challenge


if __name__ == "__main__":
    data = input("Enter data: ")
    public_key, private_key = generate_keys()
    signature = sign_data(data, private_key)
    print("Signature:", signature)
    print("Verified:", verify_signature(data, signature, public_key))

