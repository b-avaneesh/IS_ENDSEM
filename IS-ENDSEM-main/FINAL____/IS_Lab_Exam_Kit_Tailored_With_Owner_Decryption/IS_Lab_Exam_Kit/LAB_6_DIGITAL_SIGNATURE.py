"""LAB 6 - DIGITAL SIGNATURES

Covers ElGamal signatures, Schnorr signatures, Diffie-Hellman, a client/server
signature demo, and the CIA triad using RSA + AES + SHA-256.
Requires: pip install pycryptodome
"""

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


# ---------------------------------------------------------------------------
# Q1: ELGAMAL DIGITAL SIGNATURE
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Q1: SCHNORR DIGITAL SIGNATURE (small learning parameters)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Q2: DIFFIE-HELLMAN + AES ENCRYPTION
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# RSA SIGNATURE + ENCRYPTION (used by Q3 and the CIA additional exercise)
# ---------------------------------------------------------------------------
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


def rsa_hybrid_encrypt(plaintext, public_key):
    aes_key = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    encrypted_key = PKCS1_OAEP.new(public_key).encrypt(aes_key)
    return {
        "encrypted_key": encrypted_key,
        "nonce": cipher.nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }


def rsa_hybrid_decrypt(package, private_key):
    aes_key = PKCS1_OAEP.new(private_key).decrypt(package["encrypted_key"])
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=package["nonce"])
    return cipher.decrypt_and_verify(package["ciphertext"], package["tag"]).decode()


def create_cia_record(plaintext, receiver_public_key, sender_private_key):
    """Confidentiality=RSA/AES, Integrity=SHA-256, Authenticity=RSA signature."""
    encrypted = rsa_hybrid_encrypt(plaintext, receiver_public_key)
    signature = rsa_sign(encrypted["ciphertext"], sender_private_key)
    return {"encrypted": encrypted, "signature": signature}


def open_cia_record(record, receiver_private_key, sender_public_key, role):
    """Availability/access control: only the allowed role can open the record."""
    if role not in ["admin", "authorized_user"]:
        raise PermissionError("Access denied")
    encrypted = record["encrypted"]
    if not rsa_verify(encrypted["ciphertext"], record["signature"], sender_public_key):
        raise ValueError("Signature invalid: data may be changed")
    return rsa_hybrid_decrypt(encrypted, receiver_private_key)


# ===========================================================================
# STANDARD EXAM INTERFACE - SAME NAMES USED IN EVERY LAB FILE/TEMPLATE
# ===========================================================================
def generate_keys(algorithm="rsa", **options):
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "rsa":
        return rsa_generate_keys()
    if algorithm == "elgamal":
        return elgamal_generate_keys(options.get("p", 7919), options.get("g", 2))
    if algorithm == "schnorr":
        return schnorr_generate_keys(
            options.get("p", 23), options.get("q", 11), options.get("g", 2)
        )
    if algorithm in ("dh", "diffie-hellman"):
        return dh_generate_keypair(options.get("p", 7919), options.get("g", 2))
    raise ValueError("Unsupported algorithm: " + algorithm)


def encrypt_data(data, key, algorithm="rsa-hybrid", **options):
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "elgamal":
        return elgamal_encrypt(data, key)
    if algorithm in ("dh", "dh-aes"):
        return dh_encrypt(data, key)
    if algorithm in ("rsa", "rsa-hybrid"):
        return rsa_hybrid_encrypt(data, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def decrypt_data(encrypted_data, key, algorithm="rsa-hybrid", **options):
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "elgamal":
        return elgamal_decrypt(encrypted_data, key, options.get("p", 7919))
    if algorithm in ("dh", "dh-aes"):
        return dh_decrypt(encrypted_data, key)
    if algorithm in ("rsa", "rsa-hybrid"):
        return rsa_hybrid_decrypt(encrypted_data, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def hash_data(data, algorithm="sha256"):
    raw = data.encode() if isinstance(data, str) else data
    return hashlib.new(algorithm.lower().replace("-", ""), raw).hexdigest()


def sign_data(data, private_key, algorithm="rsa", **options):
    """Same signing name for RSA, ElGamal and Schnorr."""
    algorithm = algorithm.lower()
    if algorithm == "rsa":
        raw = data.encode() if isinstance(data, str) else data
        return rsa_sign(raw, private_key)
    text = data.decode() if isinstance(data, bytes) else data
    if algorithm == "elgamal":
        return elgamal_sign(
            text, private_key, options.get("p", 7919), options.get("g", 2)
        )
    if algorithm == "schnorr":
        return schnorr_sign(
            text,
            private_key,
            options.get("p", 23),
            options.get("q", 11),
            options.get("g", 2),
        )
    raise ValueError("Unsupported algorithm: " + algorithm)


def verify_signature(data, signature, public_key, algorithm="rsa", **options):
    """Same verification name for RSA, ElGamal and Schnorr."""
    algorithm = algorithm.lower()
    if algorithm == "rsa":
        raw = data.encode() if isinstance(data, str) else data
        return rsa_verify(raw, signature, public_key)
    text = data.decode() if isinstance(data, bytes) else data
    if algorithm == "elgamal":
        return elgamal_verify(text, signature, public_key)
    if algorithm == "schnorr":
        return schnorr_verify(text, signature, public_key)
    raise ValueError("Unsupported algorithm: " + algorithm)


# ---------------------------------------------------------------------------
# Q3: CLIENT/SERVER SIGNATURE VERIFICATION
# Run in two terminals: python LAB_6_DIGITAL_SIGNATURE.py server / client
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 5001


def receive_json_line(connection):
    data = b""
    while not data.endswith(b"\n"):
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())


def run_signature_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        print("Signature server listening on", host, port)
        while True:
            connection, address = server.accept()
            with connection:
                request = receive_json_line(connection)
                message = b64decode(request["message"])
                signature = b64decode(request["signature"])
                public_key = RSA.import_key(b64decode(request["public_key"]))
                valid = rsa_verify(message, signature, public_key)
                connection.sendall((json.dumps({"valid": valid}) + "\n").encode())
                print(address, "signature valid:", valid)


def run_signature_client(message, host=HOST, port=PORT):
    public_key, private_key = rsa_generate_keys()
    message_bytes = message.encode()
    request = {
        "message": b64encode(message_bytes).decode(),
        "signature": b64encode(rsa_sign(message_bytes, private_key)).decode(),
        "public_key": b64encode(public_key.export_key()).decode(),
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((host, port))
        client.sendall((json.dumps(request) + "\n").encode())
        response = receive_json_line(client)
    print("Server verification result:", response["valid"])
    return response["valid"]


def demo():
    message = "Information Security"

    print("\nELGAMAL SIGNATURE")
    public_key, private_key = elgamal_generate_keys()
    signature = elgamal_sign(message, private_key)
    print("Signature:", signature)
    print("Valid:", elgamal_verify(message, signature, public_key))

    print("\nSCHNORR SIGNATURE")
    public_key, private_key = schnorr_generate_keys()
    signature = schnorr_sign(message, private_key)
    print("Signature:", signature)
    print("Valid:", schnorr_verify(message, signature, public_key))

    print("\nDIFFIE-HELLMAN")
    alice_private, alice_public = dh_generate_keypair()
    bob_private, bob_public = dh_generate_keypair()
    alice_secret = dh_shared_secret(bob_public, alice_private)
    bob_secret = dh_shared_secret(alice_public, bob_private)
    package = dh_encrypt(message, alice_secret)
    print("Same shared key:", alice_secret == bob_secret)
    print("Recovered:", dh_decrypt(package, bob_secret))

    print("\nCIA TRIAD")
    sender_public, sender_private = rsa_generate_keys()
    receiver_public, receiver_private = rsa_generate_keys()
    record = create_cia_record("Very secret record", receiver_public, sender_private)
    print(open_cia_record(record, receiver_private, sender_public, "authorized_user"))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "server":
        run_signature_server()
    elif len(sys.argv) > 1 and sys.argv[1].lower() == "client":
        run_signature_client(input("Enter message: "))
    else:
        demo()
