# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - No EduSecure login, roles, hashing, signatures or storage are needed.
# - Offer DES, AES-128, AES-192, AES-256 and Triple DES in one menu.
# - Encrypt/decrypt user input and display the ciphertext in hexadecimal.
# - Compare encryption execution times for all requested algorithms.
# =====================================================================
"""DES/AES/3DES selection and timing."""

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

def des_encrypt(plaintext, key_text):
    key = make_key(key_text, 8)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), DES.block_size))

def des_decrypt(ciphertext, key_text):
    key = make_key(key_text, 8)
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()

def aes_encrypt(plaintext, key_text, key_size=16):
    key = make_key(key_text, key_size)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def aes_decrypt(ciphertext, key_text, key_size=16):
    key = make_key(key_text, key_size)
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def triple_des_encrypt(plaintext, key_text):
    key = make_3des_key(key_text)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), DES3.block_size))

def triple_des_decrypt(ciphertext, key_text):
    key = make_3des_key(key_text)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode()

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


def main():
    message = input("Message: "); key = input("Key text: ")
    print("1 DES  2 AES-128  3 AES-192  4 AES-256  5 Triple DES  6 Compare")
    choice = input("Choice: ")
    if choice == "1": encrypted = des_encrypt(message, key); recovered = des_decrypt(encrypted, key)
    elif choice in ("2", "3", "4"):
        size = {"2": 16, "3": 24, "4": 32}[choice]
        encrypted = aes_encrypt(message, key, size); recovered = aes_decrypt(encrypted, key, size)
    elif choice == "5": encrypted = triple_des_encrypt(message, key); recovered = triple_des_decrypt(encrypted, key)
    else: compare_des_and_all_aes([message]); return
    print("Encrypted:", encrypted.hex()); print("Decrypted:", recovered)


if __name__ == "__main__": main()
