"""Affine cipher - copy this complete file."""

from math import gcd


def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def encrypt_data(data, key):
    a, b = key
    if gcd(a, 26) != 1:
        raise ValueError("First key must be coprime with 26")
    return "".join(chr((a * (ord(ch) - 65) + b) % 26 + 65) for ch in clean(data))


def decrypt_data(encrypted_data, key):
    a, b = key
    inverse_a = pow(a, -1, 26)
    return "".join(chr((inverse_a * ((ord(ch) - 65) - b)) % 26 + 65) for ch in clean(encrypted_data))


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    a = int(input("Enter first key a: "))
    b = int(input("Enter second key b: "))
    key = (a, b)
    encrypted = encrypt_data(data, key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, key))

