"""LAB 2 - DES, 3DES AND AES

Install PyCryptodome BEFORE the offline exam:
    pip install pycryptodome matplotlib

All encrypt functions return bytes. Print ciphertext with ciphertext.hex().
"""

import hashlib
import os
import time

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter


def make_key(key_text, size):
    """Convert an ASCII/hex key to exactly size bytes.

    The manual's AES-192 key contains only 128 bits. For that question this helper
    pads it with zero bytes so the demonstration can still run.
    """
    try:
        key = bytes.fromhex(key_text)
    except ValueError:
        key = key_text.encode()
    if len(key) == size:
        return key
    # If interpreting as hex gave the wrong size, try the literal ASCII key.
    if len(key_text.encode()) == size:
        return key_text.encode()
    return key[:size].ljust(size, b"0")


def make_3des_key(key_text):
    """Return a valid non-degenerate 24-byte 3DES key.

    The manual repeats one 8-byte value three times, which degenerates to DES
    and PyCryptodome correctly rejects it. A SHA-256 derivation makes it valid.
    """
    key = make_key(key_text, 24)
    try:
        key = DES3.adjust_key_parity(key)
        DES3.new(key, DES3.MODE_ECB)  # validate that K1, K2, K3 are usable
        return key
    except ValueError:
        derived = hashlib.sha256(key_text.encode()).digest()[:24]
        return DES3.adjust_key_parity(derived)


# ---------------------------------------------------------------------------
# DES ECB - Lab exercise Q1 and additional exercise Q2
# ---------------------------------------------------------------------------
def des_encrypt(plaintext, key_text):
    key = make_key(key_text, 8)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), DES.block_size))


def des_decrypt(ciphertext, key_text):
    key = make_key(key_text, 8)
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()


def des_encrypt_hex(hex_data, key_text):
    """Additional Q2: encrypt bytes supplied as hexadecimal text."""
    key = make_key(key_text, 8)
    data = bytes.fromhex(hex_data)
    return DES.new(key, DES.MODE_ECB).encrypt(pad(data, DES.block_size))


def des_decrypt_hex(ciphertext, key_text):
    """Return the original hexadecimal data."""
    key = make_key(key_text, 8)
    data = unpad(DES.new(key, DES.MODE_ECB).decrypt(ciphertext), DES.block_size)
    return data.hex()


# ---------------------------------------------------------------------------
# AES ECB - works for AES-128, AES-192 and AES-256
# key_size must be 16, 24 or 32 bytes.
# ---------------------------------------------------------------------------
def aes_encrypt(plaintext, key_text, key_size=16):
    key = make_key(key_text, key_size)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))


def aes_decrypt(ciphertext, key_text, key_size=16):
    key = make_key(key_text, key_size)
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


# ---------------------------------------------------------------------------
# TRIPLE DES ECB - Lab exercise Q4
# ---------------------------------------------------------------------------
def triple_des_encrypt(plaintext, key_text):
    key = make_3des_key(key_text)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), DES3.block_size))


def triple_des_decrypt(ciphertext, key_text):
    key = make_3des_key(key_text)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode()


# ---------------------------------------------------------------------------
# DES CBC - Additional exercise Q4
# ---------------------------------------------------------------------------
def des_cbc_encrypt(plaintext, key_text, iv_text):
    key = make_key(key_text, 8)
    iv = make_key(iv_text, 8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode(), DES.block_size))


def des_cbc_decrypt(ciphertext, key_text, iv_text):
    key = make_key(key_text, 8)
    iv = make_key(iv_text, 8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()


# ---------------------------------------------------------------------------
# AES CTR - Additional exercise Q5. Encryption and decryption are identical.
# ---------------------------------------------------------------------------
def aes_ctr_encrypt(plaintext, key_text, nonce_text):
    key = make_key(key_text, 16)
    nonce = make_key(nonce_text, 8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(plaintext.encode())


def aes_ctr_decrypt(ciphertext, key_text, nonce_text):
    key = make_key(key_text, 16)
    nonce = make_key(nonce_text, 8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()


# ---------------------------------------------------------------------------
# Generic AES modes for the comparison question.
# Returned package is a dictionary, making decryption simple.
# ---------------------------------------------------------------------------
def aes_mode_encrypt(plaintext, key_text, mode_name, key_size=16):
    key = make_key(key_text, key_size)
    data = plaintext.encode()
    mode_name = mode_name.upper()

    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return {"ciphertext": cipher.encrypt(pad(data, 16))}
    if mode_name == "CBC":
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return {"ciphertext": cipher.encrypt(pad(data, 16)), "iv": iv}
    if mode_name == "CFB":
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return {"ciphertext": cipher.encrypt(data), "iv": iv}
    if mode_name == "OFB":
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        return {"ciphertext": cipher.encrypt(data), "iv": iv}
    if mode_name == "CTR":
        nonce = os.urandom(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return {"ciphertext": cipher.encrypt(data), "nonce": nonce}
    raise ValueError("Use ECB, CBC, CFB, OFB or CTR")


def aes_mode_decrypt(package, key_text, mode_name, key_size=16):
    key = make_key(key_text, key_size)
    mode_name = mode_name.upper()
    ciphertext = package["ciphertext"]

    if mode_name == "ECB":
        return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16).decode()
    if mode_name == "CBC":
        data = AES.new(key, AES.MODE_CBC, package["iv"]).decrypt(ciphertext)
        return unpad(data, 16).decode()
    if mode_name == "CFB":
        return AES.new(key, AES.MODE_CFB, package["iv"]).decrypt(ciphertext).decode()
    if mode_name == "OFB":
        return AES.new(key, AES.MODE_OFB, package["iv"]).decrypt(ciphertext).decode()
    if mode_name == "CTR":
        return AES.new(key, AES.MODE_CTR, nonce=package["nonce"]).decrypt(ciphertext).decode()
    raise ValueError("Use ECB, CBC, CFB, OFB or CTR")


# ===========================================================================
# STANDARD EXAM INTERFACE - SAME NAMES USED IN EVERY LAB FILE
# Extra values such as IV/nonce are supplied by keyword in **options.
# ===========================================================================
def encrypt_data(data, key, algorithm="aes-128", **options):
    """Common encryption name for DES, 3DES and AES."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "des":
        return des_encrypt(data, key)
    if algorithm == "des-cbc":
        return des_cbc_encrypt(data, key, options["iv"])
    if algorithm in ("3des", "triple-des", "tripledes"):
        return triple_des_encrypt(data, key)
    if algorithm in ("aes-128", "aes-192", "aes-256"):
        size = {"aes-128": 16, "aes-192": 24, "aes-256": 32}[algorithm]
        return aes_encrypt(data, key, size)
    if algorithm == "aes-ctr":
        return aes_ctr_encrypt(data, key, options["nonce"])
    if algorithm == "aes-mode":
        return aes_mode_encrypt(
            data, key, options.get("mode", "CBC"), options.get("key_size", 16)
        )
    raise ValueError("Unsupported algorithm: " + algorithm)


def decrypt_data(encrypted_data, key, algorithm="aes-128", **options):
    """Common decryption name for DES, 3DES and AES."""
    algorithm = algorithm.lower().replace("_", "-")
    if algorithm == "des":
        return des_decrypt(encrypted_data, key)
    if algorithm == "des-cbc":
        return des_cbc_decrypt(encrypted_data, key, options["iv"])
    if algorithm in ("3des", "triple-des", "tripledes"):
        return triple_des_decrypt(encrypted_data, key)
    if algorithm in ("aes-128", "aes-192", "aes-256"):
        size = {"aes-128": 16, "aes-192": 24, "aes-256": 32}[algorithm]
        return aes_decrypt(encrypted_data, key, size)
    if algorithm == "aes-ctr":
        return aes_ctr_decrypt(encrypted_data, key, options["nonce"])
    if algorithm == "aes-mode":
        return aes_mode_decrypt(
            encrypted_data,
            key,
            options.get("mode", "CBC"),
            options.get("key_size", 16),
        )
    raise ValueError("Unsupported algorithm: " + algorithm)


def compare_des_aes(message, repetitions=1000):
    """Lab Q3: compare total encryption and decryption time."""
    des_key = "A1B2C3D4"
    aes_key = "0123456789ABCDEF" * 4

    start = time.perf_counter()
    for _ in range(repetitions):
        encrypted = des_encrypt(message, des_key)
        des_decrypt(encrypted, des_key)
    des_time = time.perf_counter() - start

    start = time.perf_counter()
    for _ in range(repetitions):
        encrypted = aes_encrypt(message, aes_key, 32)
        aes_decrypt(encrypted, aes_key, 32)
    aes_time = time.perf_counter() - start

    print("DES time:", des_time, "seconds")
    print("AES-256 time:", aes_time, "seconds")
    return des_time, aes_time


def compare_aes_modes(messages, key_text="0123456789ABCDEF"):
    """Additional Q1: compare five AES modes and optionally plot a graph."""
    modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]
    times = []
    for mode in modes:
        start = time.perf_counter()
        for message in messages:
            package = aes_mode_encrypt(message, key_text, mode)
            aes_mode_decrypt(package, key_text, mode)
        times.append(time.perf_counter() - start)
        print(mode, "time:", times[-1])

    try:
        import matplotlib.pyplot as plt
        plt.bar(modes, times)
        plt.xlabel("AES mode")
        plt.ylabel("Seconds")
        plt.title("AES mode execution time")
        plt.show()
    except ImportError:
        print("matplotlib is not installed; numeric times are shown above.")
    return dict(zip(modes, times))


def compare_des_and_all_aes(messages):
    """Additional Q1: DES versus AES-128/192/256 using five messages."""
    algorithms = [
        ("DES", des_encrypt, des_decrypt, "A1B2C3D4", None),
        ("AES-128", aes_encrypt, aes_decrypt, "0123456789ABCDEF" * 2, 16),
        ("AES-192", aes_encrypt, aes_decrypt, "0123456789ABCDEF" * 3, 24),
        ("AES-256", aes_encrypt, aes_decrypt, "0123456789ABCDEF" * 4, 32),
    ]
    results = {}
    for name, encrypt_function, decrypt_function, key, size in algorithms:
        start = time.perf_counter()
        for message in messages:
            if size is None:
                encrypted = encrypt_function(message, key)
                recovered = decrypt_function(encrypted, key)
            else:
                encrypted = encrypt_function(message, key, size)
                recovered = decrypt_function(encrypted, key, size)
            assert recovered == message
        results[name] = time.perf_counter() - start
        print(name, "time:", results[name])

    try:
        import matplotlib.pyplot as plt
        plt.bar(results.keys(), results.values())
        plt.ylabel("Seconds")
        plt.title("DES and AES execution time")
        plt.show()
    except ImportError:
        print("matplotlib is not installed; numeric times are shown above.")
    return results


def show_aes_192_steps(plaintext, key_text):
    """Print the named AES stages required by Lab Q5 (library performs rounds)."""
    key = make_key(key_text, 24)
    print("1. Normalized 192-bit key:", key.hex())
    print("2. Key expansion: AES-192 creates 13 round keys")
    print("3. Initial round: AddRoundKey")
    print("4. Main rounds 1-11: SubBytes, ShiftRows, MixColumns, AddRoundKey")
    print("5. Final round 12: SubBytes, ShiftRows, AddRoundKey")
    ciphertext = aes_encrypt(plaintext, key_text, 24)
    print("6. Ciphertext:", ciphertext.hex())
    return ciphertext


def demo():
    print("\nQ1 DES")
    encrypted = des_encrypt("Confidential Data", "A1B2C3D4")
    print("Ciphertext:", encrypted.hex())
    print("Plaintext:", des_decrypt(encrypted, "A1B2C3D4"))

    print("\nQ2 AES-128")
    key128 = "0123456789ABCDEF0123456789ABCDEF"
    encrypted = aes_encrypt("Sensitive Information", key128, 16)
    print("Ciphertext:", encrypted.hex())
    print("Plaintext:", aes_decrypt(encrypted, key128, 16))

    print("\nQ4 Triple DES")
    key3 = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    encrypted = triple_des_encrypt("Classified Text", key3)
    print("Ciphertext:", encrypted.hex())
    print("Plaintext:", triple_des_decrypt(encrypted, key3))

    print("\nQ5 AES-192 (manual key is padded to 24 bytes)")
    key192 = "FEDCBA9876543210FEDCBA9876543210"
    encrypted = aes_encrypt("Top Secret Data", key192, 24)
    print("Ciphertext:", encrypted.hex())
    print("Plaintext:", aes_decrypt(encrypted, key192, 24))

    print("\nAdditional Q3 AES-256")
    key256 = "0123456789ABCDEF" * 4
    encrypted = aes_encrypt("Encryption Strength", key256, 32)
    print("Ciphertext:", encrypted.hex())
    print("Plaintext:", aes_decrypt(encrypted, key256, 32))

    print("\nAdditional Q4 DES CBC")
    encrypted = des_cbc_encrypt("Secure Communication", "A1B2C3D4", "12345678")
    print("Ciphertext:", encrypted.hex())
    print("Plaintext:", des_cbc_decrypt(encrypted, "A1B2C3D4", "12345678"))

    print("\nAdditional Q5 AES CTR")
    encrypted = aes_ctr_encrypt(
        "Cryptography Lab Exercise",
        "0123456789ABCDEF0123456789ABCDEF",
        "0000000000000000",
    )
    print("Ciphertext:", encrypted.hex())
    print("Plaintext:", aes_ctr_decrypt(
        encrypted,
        "0123456789ABCDEF0123456789ABCDEF",
        "0000000000000000",
    ))


if __name__ == "__main__":
    demo()
