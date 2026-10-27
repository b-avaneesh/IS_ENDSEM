"""ElGamal digital signature - copy this complete file."""

import hashlib
import random
from math import gcd

P, G = 7919, 2


def generate_keys():
    private_key = random.randint(2, P - 2)
    return (P, G, pow(G, private_key, P)), private_key


def hash_data(data):
    return int.from_bytes(hashlib.sha256(data.encode()).digest(), "big") % (P - 1)


def sign_data(data, private_key):
    while True:
        k = random.randint(2, P - 2)
        if gcd(k, P - 1) == 1:
            break
    r = pow(G, k, P)
    s = (hash_data(data) - private_key * r) * pow(k, -1, P - 1) % (P - 1)
    return r, s


def verify_signature(data, signature, public_key):
    p, g, y = public_key
    r, s = signature
    left = pow(g, hash_data(data), p)
    right = pow(y, r, p) * pow(r, s, p) % p
    return left == right


if __name__ == "__main__":
    data = input("Enter data: ")
    public_key, private_key = generate_keys()
    signature = sign_data(data, private_key)
    print("Signature:", signature)
    print("Verified:", verify_signature(data, signature, public_key))

