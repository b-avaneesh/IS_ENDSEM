# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - Replace EduSecure record handling with a centralized Rabin key service.
# - Register, authorize/distribute, revoke and renew Hospital/Clinic keys.
# - Keep private keys unavailable to ordinary displays and log lifecycle events.
# - Show Rabin's four roots and select plaintext using the fixed RB prefix.
# =====================================================================
"""Centralized Rabin key-management service."""

import hashlib

import random

import time

from datetime import datetime, timedelta

from math import gcd

from Crypto.Cipher import AES, PKCS1_OAEP

from Crypto.PublicKey import RSA

from Crypto.Util.number import getPrime, inverse

AUDIT_LOG = []

FACILITIES = {}

def log_event(message):
    entry = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - " + message
    AUDIT_LOG.append(entry)
    print(entry)

def show_audit_log():
    for entry in AUDIT_LOG:
        print(entry)

def rabin_generate_keys(bits=1024):
    """Generate p and q where p % 4 == q % 4 == 3."""
    while True:
        p = getPrime(bits // 2)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits // 2)
        if q % 4 == 3 and q != p:
            break
    return p * q, (p, q)

def rabin_encrypt(plaintext, public_key):
    """Prefix RB helps select the correct one of Rabin's four roots."""
    message = int.from_bytes(b"RB" + plaintext.encode(), "big")
    if message >= public_key:
        raise ValueError("Message is too large for this key")
    return pow(message, 2, public_key)

def rabin_decrypt(ciphertext, private_key):
    p, q = private_key
    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    yp = inverse(p, q)
    yq = inverse(q, p)
    roots = [
        (yp * p * mq + yq * q * mp) % n,
        (-yp * p * mq - yq * q * mp) % n,
        (yp * p * mq - yq * q * mp) % n,
        (-yp * p * mq + yq * q * mp) % n,
    ]
    for root in roots:
        size = max(1, (root.bit_length() + 7) // 8)
        data = root.to_bytes(size, "big")
        if data.startswith(b"RB"):
            return data[2:].decode()
    raise ValueError("Correct Rabin root not found")

def register_facility(name, bits=1024):
    public_key, private_key = rabin_generate_keys(bits)
    FACILITIES[name] = {
        "public_key": public_key,
        "private_key": private_key,
        "active": True,
        "created": datetime.now(),
    }
    log_event("Rabin keys generated for " + name)

def distribute_facility_keys(name, authorized):
    if not authorized:
        raise PermissionError("Only an authorized user can request keys")
    record = FACILITIES.get(name)
    if not record or not record["active"]:
        raise ValueError("Facility is missing or revoked")
    log_event("Keys distributed to " + name)
    return record["public_key"], record["private_key"]

def revoke_facility(name):
    if name in FACILITIES:
        FACILITIES[name]["active"] = False
        log_event("Rabin keys revoked for " + name)

def renew_facility(name, bits=1024):
    register_facility(name, bits)
    log_event("Rabin keys renewed for " + name)

def renew_keys_older_than(days=365, bits=1024):
    now = datetime.now()
    for name, record in list(FACILITIES.items()):
        if now - record["created"] >= timedelta(days=days):
            renew_facility(name, bits)

def rabin_rsa_tradeoff():
    """Short trade-off answer requested in Question 2."""
    points = [
        "Rabin encryption is fast: c = m^2 mod n.",
        "Rabin security is directly related to integer factorisation.",
        "Rabin decryption produces four roots, so redundancy is needed.",
        "RSA decryption gives one plaintext and is easier to use in practice.",
        "Both require large random primes, padding and protected private keys.",
    ]
    for point in points:
        print("-", point)
    return points


def main():
    while True:
        print("\n1 Register  2 Distribute  3 Encrypt/decrypt  4 Revoke")
        print("5 Renew  6 Renew old keys  7 Audit log  8 Rabin/RSA comparison  0 Exit")
        choice = input("Choice: ")
        if choice == "0": return
        name = input("Facility name: ") if choice in "12345" else None
        try:
            if choice == "1": register_facility(name)
            elif choice == "2":
                public, _ = distribute_facility_keys(name, True)
                print("Public key:", public)
                print("Private key withheld from ordinary display")
            elif choice == "3":
                public, private = distribute_facility_keys(name, True)
                message = input("Short patient record: ")
                encrypted = rabin_encrypt(message, public)
                print("Encrypted:", encrypted)
                print("Decrypted:", rabin_decrypt(encrypted, private))
            elif choice == "4": revoke_facility(name)
            elif choice == "5": renew_facility(name)
            elif choice == "6": renew_keys_older_than(int(input("Age in days: ")))
            elif choice == "7": show_audit_log()
            elif choice == "8": rabin_rsa_tradeoff()
        except (ValueError, PermissionError) as error:
            print("Error:", error)


if __name__ == "__main__":
    main()
