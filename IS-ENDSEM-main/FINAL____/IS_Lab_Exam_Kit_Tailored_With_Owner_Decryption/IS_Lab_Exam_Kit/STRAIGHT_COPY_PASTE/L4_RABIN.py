"""Rabin encryption/decryption - copy this file. Requires PyCryptodome."""

from Crypto.Util.number import getPrime, inverse


def generate_keys(bits=512):
    while True:
        p = getPrime(bits // 2)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits // 2)
        if q % 4 == 3 and q != p:
            break
    return p * q, (p, q)


def encrypt_data(data, public_key):
    number = int.from_bytes(b"RB" + data.encode(), "big")
    if number >= public_key:
        raise ValueError("Message too large")
    return pow(number, 2, public_key)


def decrypt_data(encrypted_data, private_key):
    p, q = private_key
    n = p * q
    mp = pow(encrypted_data, (p + 1) // 4, p)
    mq = pow(encrypted_data, (q + 1) // 4, q)
    yp, yq = inverse(p, q), inverse(q, p)
    roots = [(yp*p*mq + yq*q*mp) % n,
             (-yp*p*mq - yq*q*mp) % n,
             (yp*p*mq - yq*q*mp) % n,
             (-yp*p*mq + yq*q*mp) % n]
    for root in roots:
        size = max(1, (root.bit_length() + 7) // 8)
        value = root.to_bytes(size, "big")
        if value.startswith(b"RB"):
            return value[2:].decode()
    raise ValueError("Correct plaintext root not found")


if __name__ == "__main__":
    data = input("Enter plaintext: ")
    public_key, private_key = generate_keys()
    encrypted = encrypt_data(data, public_key)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypt_data(encrypted, private_key))

