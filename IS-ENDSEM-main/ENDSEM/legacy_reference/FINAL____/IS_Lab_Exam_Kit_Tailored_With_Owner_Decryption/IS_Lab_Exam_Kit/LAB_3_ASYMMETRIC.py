"""LAB 3 - RSA, ELGAMAL, ECC AND DIFFIE-HELLMAN

Small mathematical versions are provided for easy exam writing.
Hybrid RSA/ECC functions are included for the file-transfer questions.
Requires: pip install pycryptodome
"""

import hashlib
import json
import os
import random
import time
from base64 import b64decode, b64encode
from math import gcd

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import ECC, RSA


# ---------------------------------------------------------------------------
# RSA - small and easy mathematical version
# ---------------------------------------------------------------------------
def rsa_generate_keys(p=61, q=53, e=17):
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi(n)")
    d = pow(e, -1, phi)
    return (n, e), (n, d)


def rsa_encrypt(plaintext, public_key):
    n, e = public_key
    data = plaintext.encode()
    if any(byte >= n for byte in data):
        raise ValueError("n must be larger than every plaintext byte")
    return [pow(byte, e, n) for byte in data]


def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    data = bytes(pow(number, d, n) for number in ciphertext)
    return data.decode()


def factor_rsa_modulus(n):
    """Additional attack question: factor a deliberately weak RSA modulus."""
    factor = 2
    while factor * factor <= n:
        if n % factor == 0:
            return factor, n // factor
        factor += 1
    raise ValueError("No factors found")


def attack_weak_rsa(ciphertext, n, e):
    p, q = factor_rsa_modulus(n)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    plaintext = rsa_decrypt(ciphertext, (n, d))
    return {"p": p, "q": q, "d": d, "plaintext": plaintext}


# ---------------------------------------------------------------------------
# ELGAMAL - integer version, encrypts UTF-8 bytes
# ---------------------------------------------------------------------------
def elgamal_generate_keys(p=7919, g=2, private_key=None):
    x = private_key if private_key is not None else random.randint(2, p - 2)
    h = pow(g, x, p)
    return (p, g, h), x


def elgamal_encrypt(plaintext, public_key):
    p, g, h = public_key
    ciphertext = []
    for byte in plaintext.encode():
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        c2 = (byte * pow(h, k, p)) % p
        ciphertext.append((c1, c2))
    return ciphertext


def elgamal_decrypt(ciphertext, private_key, p=7919):
    recovered = []
    for c1, c2 in ciphertext:
        shared_secret = pow(c1, private_key, p)
        byte = (c2 * pow(shared_secret, -1, p)) % p
        recovered.append(byte)
    return bytes(recovered).decode()


# ---------------------------------------------------------------------------
# DIFFIE-HELLMAN KEY EXCHANGE
# ---------------------------------------------------------------------------
def dh_generate_keypair(p=7919, g=2):
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def dh_shared_secret(other_public_key, my_private_key, p=7919):
    return pow(other_public_key, my_private_key, p)


def diffie_hellman_demo():
    p, g = 7919, 2
    alice_private, alice_public = dh_generate_keypair(p, g)
    bob_private, bob_public = dh_generate_keypair(p, g)
    alice_secret = dh_shared_secret(bob_public, alice_private, p)
    bob_secret = dh_shared_secret(alice_public, bob_private, p)
    print("Alice shared key:", alice_secret)
    print("Bob shared key:  ", bob_secret)
    print("Keys match:", alice_secret == bob_secret)
    return alice_secret


def measure_diffie_hellman():
    """Lab Q5: measure key generation and exchange time."""
    start = time.perf_counter()
    alice_private, alice_public = dh_generate_keypair()
    bob_private, bob_public = dh_generate_keypair()
    key_generation_time = time.perf_counter() - start

    start = time.perf_counter()
    alice_secret = dh_shared_secret(bob_public, alice_private)
    bob_secret = dh_shared_secret(alice_public, bob_private)
    exchange_time = time.perf_counter() - start
    assert alice_secret == bob_secret
    print("Key generation time:", key_generation_time)
    print("Key exchange time:", exchange_time)
    return key_generation_time, exchange_time


# ---------------------------------------------------------------------------
# HYBRID RSA + AES - use this for large messages/files.
# RSA encrypts only the random AES key; AES encrypts the actual file.
# ---------------------------------------------------------------------------
def rsa_2048_generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def rsa_hybrid_encrypt_bytes(data, rsa_public_key):
    aes_key = os.urandom(16)
    aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes.encrypt_and_digest(data)
    encrypted_key = PKCS1_OAEP.new(rsa_public_key).encrypt(aes_key)
    return {
        "encrypted_key": encrypted_key,
        "nonce": aes.nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }


def rsa_hybrid_decrypt_bytes(package, rsa_private_key):
    aes_key = PKCS1_OAEP.new(rsa_private_key).decrypt(package["encrypted_key"])
    aes = AES.new(aes_key, AES.MODE_EAX, nonce=package["nonce"])
    return aes.decrypt_and_verify(package["ciphertext"], package["tag"])


def rsa_encrypt_file(input_file, encrypted_file, rsa_public_key):
    with open(input_file, "rb") as file:
        package = rsa_hybrid_encrypt_bytes(file.read(), rsa_public_key)
    save_package(package, encrypted_file)


def rsa_decrypt_file(encrypted_file, output_file, rsa_private_key):
    package = load_package(encrypted_file)
    data = rsa_hybrid_decrypt_bytes(package, rsa_private_key)
    with open(output_file, "wb") as file:
        file.write(data)


# ---------------------------------------------------------------------------
# ECC / ECIES-STYLE ENCRYPTION
# PyCryptodome does not provide direct ECC encryption, so ECDH creates an AES key.
# ---------------------------------------------------------------------------
def ecc_generate_keys():
    private_key = ECC.generate(curve="P-256")  # secp256r1
    return private_key.public_key(), private_key


def point_to_aes_key(point):
    x_coordinate = int(point.x).to_bytes(32, "big")
    return hashlib.sha256(x_coordinate).digest()


def ecc_encrypt_bytes(data, recipient_public_key):
    temporary_private = ECC.generate(curve="P-256")
    shared_point = recipient_public_key.pointQ * temporary_private.d
    aes_key = point_to_aes_key(shared_point)
    aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes.encrypt_and_digest(data)
    return {
        "temporary_public_key": temporary_private.public_key().export_key(format="PEM").encode(),
        "nonce": aes.nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }


def ecc_decrypt_bytes(package, recipient_private_key):
    temporary_public = ECC.import_key(package["temporary_public_key"])
    shared_point = temporary_public.pointQ * recipient_private_key.d
    aes_key = point_to_aes_key(shared_point)
    aes = AES.new(aes_key, AES.MODE_EAX, nonce=package["nonce"])
    return aes.decrypt_and_verify(package["ciphertext"], package["tag"])


def ecc_encrypt(plaintext, public_key):
    return ecc_encrypt_bytes(plaintext.encode(), public_key)


def ecc_decrypt(package, private_key):
    return ecc_decrypt_bytes(package, private_key).decode()


def ecc_encrypt_file(input_file, encrypted_file, public_key):
    with open(input_file, "rb") as file:
        package = ecc_encrypt_bytes(file.read(), public_key)
    save_package(package, encrypted_file)


def ecc_decrypt_file(encrypted_file, output_file, private_key):
    package = load_package(encrypted_file)
    data = ecc_decrypt_bytes(package, private_key)
    with open(output_file, "wb") as file:
        file.write(data)


def save_package(package, filename):
    """Save a dictionary of bytes as readable JSON."""
    converted = {key: b64encode(value).decode() for key, value in package.items()}
    with open(filename, "w") as file:
        json.dump(converted, file)


def load_package(filename):
    with open(filename, "r") as file:
        converted = json.load(file)
    return {key: b64decode(value) for key, value in converted.items()}


# ===========================================================================
# STANDARD EXAM INTERFACE - SAME NAMES USED IN EVERY LAB FILE
# ===========================================================================
def generate_keys(algorithm="rsa", **options):
    """Generate a public/private key pair for the selected algorithm."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "rsa":
        return rsa_generate_keys(
            options.get("p", 61), options.get("q", 53), options.get("e", 17)
        )
    if algorithm in ("rsa-2048", "rsa-hybrid"):
        return rsa_2048_generate_keys()
    if algorithm == "elgamal":
        return elgamal_generate_keys(
            options.get("p", 7919), options.get("g", 2), options.get("private_key")
        )
    if algorithm in ("ecc", "ecc-hybrid"):
        return ecc_generate_keys()
    if algorithm in ("dh", "diffie-hellman"):
        return dh_generate_keypair(options.get("p", 7919), options.get("g", 2))
    raise ValueError("Unsupported algorithm: " + algorithm)


def encrypt_data(data, key, algorithm="rsa", **options):
    """Common encryption name for RSA, ElGamal and ECC."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "rsa":
        return rsa_encrypt(data, key)
    if algorithm == "elgamal":
        return elgamal_encrypt(data, key)
    if algorithm == "ecc":
        return ecc_encrypt(data, key)
    if algorithm in ("rsa-2048", "rsa-hybrid"):
        raw = data.encode() if isinstance(data, str) else data
        return rsa_hybrid_encrypt_bytes(raw, key)
    if algorithm in ("ecc-hybrid", "ecies"):
        raw = data.encode() if isinstance(data, str) else data
        return ecc_encrypt_bytes(raw, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def decrypt_data(encrypted_data, key, algorithm="rsa", **options):
    """Common decryption name for RSA, ElGamal and ECC."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "rsa":
        return rsa_decrypt(encrypted_data, key)
    if algorithm == "elgamal":
        return elgamal_decrypt(encrypted_data, key, options.get("p", 7919))
    if algorithm == "ecc":
        return ecc_decrypt(encrypted_data, key)
    if algorithm in ("rsa-2048", "rsa-hybrid"):
        return rsa_hybrid_decrypt_bytes(encrypted_data, key)
    if algorithm in ("ecc-hybrid", "ecies"):
        return ecc_decrypt_bytes(encrypted_data, key)
    raise ValueError("Unsupported algorithm: " + algorithm)


def hash_data(data, algorithm="sha256"):
    """Common hashing name; useful for original/recovered file comparison."""
    raw = data.encode() if isinstance(data, str) else data
    return hashlib.new(algorithm.lower().replace("-", ""), raw).hexdigest()


def compare_rsa_ecc(data):
    """Measure key generation, encryption and decryption times."""
    start = time.perf_counter()
    rsa_public, rsa_private = rsa_2048_generate_keys()
    rsa_key_time = time.perf_counter() - start
    start = time.perf_counter()
    rsa_package = rsa_hybrid_encrypt_bytes(data, rsa_public)
    rsa_encrypt_time = time.perf_counter() - start
    start = time.perf_counter()
    assert rsa_hybrid_decrypt_bytes(rsa_package, rsa_private) == data
    rsa_decrypt_time = time.perf_counter() - start

    start = time.perf_counter()
    ecc_public, ecc_private = ecc_generate_keys()
    ecc_key_time = time.perf_counter() - start
    start = time.perf_counter()
    ecc_package = ecc_encrypt_bytes(data, ecc_public)
    ecc_encrypt_time = time.perf_counter() - start
    start = time.perf_counter()
    assert ecc_decrypt_bytes(ecc_package, ecc_private) == data
    ecc_decrypt_time = time.perf_counter() - start

    answer = {
        "RSA": (rsa_key_time, rsa_encrypt_time, rsa_decrypt_time),
        "ECC": (ecc_key_time, ecc_encrypt_time, ecc_decrypt_time),
    }
    print("Algorithm -> key generation, encryption, decryption (seconds)")
    for name, values in answer.items():
        print(name, "->", values)
    return answer


def compare_rsa_elgamal_ecc(message):
    """Additional Q5: simple timing comparison of all three algorithms."""
    data = message.encode()
    results = {}

    start = time.perf_counter()
    rsa_public, rsa_private = rsa_2048_generate_keys()
    key_time = time.perf_counter() - start
    start = time.perf_counter()
    package = rsa_hybrid_encrypt_bytes(data, rsa_public)
    encrypt_time = time.perf_counter() - start
    start = time.perf_counter()
    recovered = rsa_hybrid_decrypt_bytes(package, rsa_private)
    decrypt_time = time.perf_counter() - start
    assert recovered == data
    results["RSA-2048 hybrid"] = (key_time, encrypt_time, decrypt_time)

    start = time.perf_counter()
    elgamal_public, elgamal_private = elgamal_generate_keys()
    key_time = time.perf_counter() - start
    start = time.perf_counter()
    package = elgamal_encrypt(message, elgamal_public)
    encrypt_time = time.perf_counter() - start
    start = time.perf_counter()
    recovered_text = elgamal_decrypt(package, elgamal_private)
    decrypt_time = time.perf_counter() - start
    assert recovered_text == message
    results["ElGamal"] = (key_time, encrypt_time, decrypt_time)

    start = time.perf_counter()
    ecc_public, ecc_private = ecc_generate_keys()
    key_time = time.perf_counter() - start
    start = time.perf_counter()
    package = ecc_encrypt_bytes(data, ecc_public)
    encrypt_time = time.perf_counter() - start
    start = time.perf_counter()
    recovered = ecc_decrypt_bytes(package, ecc_private)
    decrypt_time = time.perf_counter() - start
    assert recovered == data
    results["ECC P-256 hybrid"] = (key_time, encrypt_time, decrypt_time)

    print("Algorithm -> key generation, encryption, decryption (seconds)")
    for name, values in results.items():
        print(name, "->", values)
    return results


def demo():
    print("\nRSA")
    public_key, private_key = rsa_generate_keys()
    encrypted = rsa_encrypt("Asymmetric Encryption", public_key)
    print("Public key:", public_key)
    print("Private key:", private_key)
    print("Ciphertext:", encrypted)
    print("Plaintext:", rsa_decrypt(encrypted, private_key))

    print("\nElGamal - values from the additional exercise")
    public_key, private_key = elgamal_generate_keys(7919, 2, 2999)
    print("Generated h:", public_key[2], "(manual incorrectly gives 6465)")
    # A public key must use h = g^x mod p, so use the consistent generated h.
    encrypted = elgamal_encrypt("Asymmetric Algorithms", public_key)
    print("Ciphertext:", encrypted)
    print("Plaintext:", elgamal_decrypt(encrypted, private_key, 7919))

    print("\nECC")
    public_key, private_key = ecc_generate_keys()
    encrypted = ecc_encrypt("Secure Transactions", public_key)
    print("Ciphertext:", encrypted["ciphertext"].hex())
    print("Plaintext:", ecc_decrypt(encrypted, private_key))

    print("\nDiffie-Hellman")
    diffie_hellman_demo()

    print("\nWeak RSA attack (n=323, e=5, d=173)")
    encrypted = rsa_encrypt("Cryptographic Protocols", (323, 5))
    print(attack_weak_rsa(encrypted, 323, 5))


if __name__ == "__main__":
    demo()
