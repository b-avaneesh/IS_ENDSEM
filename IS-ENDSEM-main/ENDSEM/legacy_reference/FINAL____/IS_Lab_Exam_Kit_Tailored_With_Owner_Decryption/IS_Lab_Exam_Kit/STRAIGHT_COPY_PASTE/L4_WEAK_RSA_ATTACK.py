"""Weak RSA encryption, decryption and factor attack - copy this complete file."""

from math import isqrt


def generate_keys(p=17, q=19, e=5):
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    return (n, e), (n, d)


def encrypt_data(data, public_key):
    n, e = public_key
    return [pow(ord(character), e, n) for character in data]


def decrypt_data(encrypted_data, private_key):
    n, d = private_key
    return "".join(chr(pow(number, d, n)) for number in encrypted_data)


def attack(encrypted_data, public_key):
    n, e = public_key
    for p in range(2, isqrt(n) + 1):
        if n % p == 0:
            q = n // p
            d = pow(e, -1, (p - 1) * (q - 1))
            return decrypt_data(encrypted_data, (n, d)), p, q
    return None


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    public_key, private_key = generate_keys()
    encrypted = encrypt_data(data, public_key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, private_key))
    cracked, p, q = attack(encrypted, public_key)
    print("Factors:", p, q)
    print("Cracked text:", cracked)
