# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - Model Finance, HR and Supply Chain as dynamically addable subsystems.
# - Use RSA-protected DH exchange, derive an AES key and encrypt documents.
# - Allow only the addressed department to receive a document.
# - Support key addition/renewal/revocation and SHA-256 audit records.
# =====================================================================
"""RSA-protected DH plus AES enterprise communication."""

import hashlib

import random

import time

from datetime import datetime, timedelta

from math import gcd

from Crypto.Cipher import AES, PKCS1_OAEP

from Crypto.PublicKey import RSA

from Crypto.Util.number import getPrime, inverse

AUDIT_LOG = []

SUBSYSTEMS = {}

def log_event(message):
    entry = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - " + message
    AUDIT_LOG.append(entry)
    print(entry)

def show_audit_log():
    for entry in AUDIT_LOG:
        print(entry)

def add_subsystem(name):
    """Scalable: call this function whenever a new subsystem is added."""
    private_key = RSA.generate(2048)
    SUBSYSTEMS[name] = {
        "public_key": private_key.publickey(),
        "private_key": private_key,
        "active": True,
    }
    log_event("RSA keys generated for " + name)

def revoke_subsystem(name):
    if name in SUBSYSTEMS:
        SUBSYSTEMS[name]["active"] = False
        log_event("Keys revoked for " + name)

def renew_subsystem_keys(name):
    if name in SUBSYSTEMS:
        add_subsystem(name)
        log_event("Keys renewed for " + name)

def dh_keypair(p=7919, g=2):
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    return private, public

def rsa_encrypt_number(number, public_key):
    data = str(number).encode()
    return PKCS1_OAEP.new(public_key).encrypt(data)

def rsa_decrypt_number(ciphertext, private_key):
    data = PKCS1_OAEP.new(private_key).decrypt(ciphertext)
    return int(data.decode())

def aes_encrypt_with_secret(plaintext, shared_secret):
    key = hashlib.sha256(str(shared_secret).encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {"nonce": cipher.nonce, "tag": tag, "ciphertext": ciphertext}

def aes_decrypt_with_secret(package, shared_secret):
    key = hashlib.sha256(str(shared_secret).encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX, nonce=package["nonce"])
    return cipher.decrypt_and_verify(package["ciphertext"], package["tag"]).decode()

def secure_communication(sender, receiver, message):
    """RSA protects the DH public values; DH creates the shared AES key."""
    if sender not in SUBSYSTEMS or receiver not in SUBSYSTEMS:
        raise ValueError("Add both subsystems first")
    if not SUBSYSTEMS[sender]["active"] or not SUBSYSTEMS[receiver]["active"]:
        raise PermissionError("A subsystem has revoked keys")

    p, g = 7919, 2
    sender_private, sender_public = dh_keypair(p, g)
    receiver_private, receiver_public = dh_keypair(p, g)

    # Exchange DH public numbers after protecting them using receiver RSA keys.
    protected_sender_public = rsa_encrypt_number(
        sender_public, SUBSYSTEMS[receiver]["public_key"]
    )
    received_sender_public = rsa_decrypt_number(
        protected_sender_public, SUBSYSTEMS[receiver]["private_key"]
    )

    protected_receiver_public = rsa_encrypt_number(
        receiver_public, SUBSYSTEMS[sender]["public_key"]
    )
    received_receiver_public = rsa_decrypt_number(
        protected_receiver_public, SUBSYSTEMS[sender]["private_key"]
    )

    sender_secret = pow(received_receiver_public, sender_private, p)
    receiver_secret = pow(received_sender_public, receiver_private, p)
    package = aes_encrypt_with_secret(message, sender_secret)
    recovered = aes_decrypt_with_secret(package, receiver_secret)
    log_event(sender + " securely sent a message to " + receiver)
    return package, recovered

DOCUMENTS = []


def send_document(sender, receiver, message):
    package, recovered = secure_communication(sender, receiver, message)
    DOCUMENTS.append({"sender": sender, "receiver": receiver, "package": package,
                      "encrypted_hash": hashlib.sha256(package["ciphertext"]).hexdigest(),
                      "demonstration_recovery": recovered})
    print("Ciphertext:", package["ciphertext"].hex())
    print("SHA-256:", DOCUMENTS[-1]["encrypted_hash"])


def main():
    for name in ("Finance", "HR", "SupplyChain"):
        add_subsystem(name)
    while True:
        print("\n1 Add department  2 Send document  3 Receive documents")
        print("4 Renew keys  5 Revoke keys  6 Audit log  0 Exit")
        choice = input("Choice: ")
        if choice == "0": return
        try:
            if choice == "1": add_subsystem(input("Department: "))
            elif choice == "2": send_document(input("Sender: "), input("Receiver: "), input("Document: "))
            elif choice == "3":
                receiver = input("Receiving department: ")
                for document in DOCUMENTS:
                    if document["receiver"] == receiver:
                        print(document["sender"], "->", receiver, document["demonstration_recovery"])
            elif choice == "4": renew_subsystem_keys(input("Department: "))
            elif choice == "5": revoke_subsystem(input("Department: "))
            elif choice == "6": show_audit_log()
        except (ValueError, PermissionError) as error:
            print("Error:", error)


if __name__ == "__main__":
    main()
