# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - No role-based EduSecure workflow is required.
# - Support AES ECB, CBC, CFB, OFB and CTR modes.
# - Store/display IV for CBC/CFB/OFB and nonce for CTR.
# - Accept five inputs and plot the mode execution-time comparison.
# =====================================================================
"""AES modes, IV/nonce handling and graph."""

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


def main():
    mode = input("Mode (ECB/CBC/CFB/OFB/CTR): ").upper()
    message = input("Message: "); key = input("Key text: ")
    package = aes_mode_encrypt(message, key, mode)
    print("Ciphertext:", package["ciphertext"].hex())
    if "iv" in package: print("IV:", package["iv"].hex())
    if "nonce" in package: print("Nonce:", package["nonce"].hex())
    print("Decrypted:", aes_mode_decrypt(package, key, mode))
    if input("Plot five-input comparison? (y/n): ").lower() == "y":
        compare_aes_modes([input(f"Message {i + 1}: ") for i in range(5)], key)


if __name__ == "__main__": main()
