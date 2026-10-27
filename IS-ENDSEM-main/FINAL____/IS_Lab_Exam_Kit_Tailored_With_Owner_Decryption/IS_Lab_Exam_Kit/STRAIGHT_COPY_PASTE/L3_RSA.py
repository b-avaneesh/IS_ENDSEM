"""Basic RSA for short text - copy this complete file."""

from math import gcd


def generate_keys(p=61, q=53, e=17):
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi")
    d = pow(e, -1, phi)
    return (n, e), (n, d)


def encrypt_data(data, public_key):
    n, e = public_key
    return [pow(byte, e, n) for byte in data.encode()]


def decrypt_data(encrypted_data, private_key):
    n, d = private_key
    return bytes(pow(number, d, n) for number in encrypted_data).decode()


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    public_key, private_key = generate_keys()
    encrypted = encrypt_data(data, public_key)
    print("Public key:", public_key)
    print("Private key:", private_key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, private_key))

