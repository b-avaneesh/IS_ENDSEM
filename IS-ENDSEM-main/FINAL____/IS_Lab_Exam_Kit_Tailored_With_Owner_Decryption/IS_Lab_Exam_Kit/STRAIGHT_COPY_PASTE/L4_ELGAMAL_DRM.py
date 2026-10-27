"""Simple ElGamal content encryption with access control."""

import random
from datetime import datetime, timedelta

P, G = 7919, 2
CONTENT = {}
ACCESS = {}


def generate_keys():
    private_key = random.randint(2, P - 2)
    return (P, G, pow(G, private_key, P)), private_key


def encrypt_data(data, public_key):
    p, g, y = public_key
    answer = []
    for byte in data.encode():
        k = random.randint(2, p - 2)
        answer.append((pow(g, k, p), byte * pow(y, k, p) % p))
    return answer


def decrypt_data(encrypted_data, private_key):
    answer = []
    for c1, c2 in encrypted_data:
        shared = pow(c1, private_key, P)
        answer.append(c2 * pow(shared, -1, P) % P)
    return bytes(answer).decode()


def grant_access(username, content_id, minutes):
    ACCESS[(username, content_id)] = datetime.now() + timedelta(minutes=minutes)


def view_content(username, content_id, private_key):
    expiry = ACCESS.get((username, content_id))
    if expiry is None or datetime.now() > expiry:
        raise PermissionError("Access missing or expired")
    return decrypt_data(CONTENT[content_id], private_key)


if __name__ == "__main__":
    public_key, private_key = generate_keys()
    content_id = input("Enter content ID: ")
    data = input("Enter content: ")
    CONTENT[content_id] = encrypt_data(data, public_key)
    username = input("Grant access to user: ")
    grant_access(username, content_id, 60)
    print("Decrypted content:", view_content(username, content_id, private_key))

