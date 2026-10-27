"""Basic ElGamal encryption - copy this complete file."""

import random


def generate_keys(p=7919, g=2):
    private_key = random.randint(2, p - 2)
    public_key = (p, g, pow(g, private_key, p))
    return public_key, private_key


def encrypt_data(data, public_key):
    p, g, y = public_key
    encrypted = []
    for byte in data.encode():
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        c2 = byte * pow(y, k, p) % p
        encrypted.append((c1, c2))
    return encrypted


def decrypt_data(encrypted_data, private_key, p=7919):
    answer = []
    for c1, c2 in encrypted_data:
        shared = pow(c1, private_key, p)
        answer.append(c2 * pow(shared, -1, p) % p)
    return bytes(answer).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    public_key, private_key = generate_keys()
    encrypted = encrypt_data(data, public_key)
    print("Public key:", public_key)
    print("Private key:", private_key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, private_key))

