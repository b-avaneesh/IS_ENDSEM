# EXACT ALGORITHMS AVAILABLE
# Encryption/decryption: AES-128 ECB (auxiliary confidentiality).
# Record hashing: SHA-256.
# Digital signature: RSA, ElGamal or Schnorr, selected in EDIT BOX 2.
# RSA, ElGamal and Schnorr signatures all hash their input using SHA-256.

"""ROLE TEMPLATE: RSA, ElGamal or Schnorr digital signatures."""

import hashlib
import pickle
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from math import gcd
import secrets


# ============================ EDIT BOX 1 ============================
# Edit only if usernames, passwords or displayed role names change.
# Keep internal roles as uploader, reviewer and auditor.
USERS = {
    "user1": ("123", "uploader"),
    "user2": ("123", "reviewer"),
    "user3": ("123", "auditor"),
}

ROLE_NAMES = {
    "uploader": "Student",
    "reviewer": "Faculty",
    "auditor": "HoD",
}


# ============================ EDIT BOX 2 ============================
# Change SIGNATURE_ALGORITHM only: "RSA", "ELGAMAL" or "SCHNORR".
SIGNATURE_ALGORITHM = "RSA"
CIPHER_KEY = b"0123456789ABCDEF"       # Auxiliary AES-128 encryption.

DATA_FILE = "signature_records.pkl"  # Change only if a filename is given.
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
def encrypt_data(data, key=CIPHER_KEY):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), 16))


def decrypt_data(encrypted_data, key=CIPHER_KEY):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), 16).decode()


def data_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return pickle.dumps(data)


def hash_data(data):
    return hashlib.sha256(data_bytes(data)).hexdigest()


def generate_keys():
    if SIGNATURE_ALGORITHM == "RSA":
        private_key = RSA.generate(2048)
        return private_key.publickey(), private_key
    if SIGNATURE_ALGORITHM == "ELGAMAL":
        p, g = 7919, 2
        private = secrets.randbelow(p - 3) + 2
        return (p, g, pow(g, private, p)), (p, g, private)
    p, q, g = 23, 11, 2
    private = secrets.randbelow(q - 1) + 1
    return (p, q, g, pow(g, private, p)), (p, q, g, private)


def get_user_keys(username):
    if username not in USER_KEYS:
        USER_KEYS[username] = generate_keys()
    return USER_KEYS[username]


def sign_data(data, private_key):
    data = data_bytes(data)
    if SIGNATURE_ALGORITHM == "RSA":
        return pkcs1_15.new(private_key).sign(SHA256.new(data))
    if SIGNATURE_ALGORITHM == "ELGAMAL":
        p, g, private = private_key
        k = secrets.randbelow(p - 2) + 1
        while gcd(k, p - 1) != 1:
            k = secrets.randbelow(p - 2) + 1
        h = int.from_bytes(SHA256.new(data).digest(), "big")
        r = pow(g, k, p)
        return r, ((h - private * r) * pow(k, -1, p - 1)) % (p - 1)
    p, q, g, private = private_key
    k = secrets.randbelow(q - 1) + 1
    r = pow(g, k, p)
    e = int.from_bytes(SHA256.new(data + str(r).encode()).digest(), "big") % q
    return e, (k + private * e) % q


def verify_signature(data, signature, public_key):
    data = data_bytes(data)
    if SIGNATURE_ALGORITHM == "RSA":
        try:
            pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
            return True
        except (ValueError, TypeError):
            return False
    if SIGNATURE_ALGORITHM == "ELGAMAL":
        p, g, public = public_key
        r, s = signature
        h = int.from_bytes(SHA256.new(data).digest(), "big")
        return pow(g, h, p) == (pow(public, r, p) * pow(r, s, p)) % p
    p, q, g, public = public_key
    e, s = signature
    r = (pow(g, s, p) * pow(pow(public, e, p), -1, p)) % p
    expected = int.from_bytes(SHA256.new(data + str(r).encode()).digest(), "big") % q
    return e == expected


def export_public_key(public_key):
    return public_key.export_key() if SIGNATURE_ALGORITHM == "RSA" else public_key


def import_public_key(saved_key):
    return RSA.import_key(saved_key) if SIGNATURE_ALGORITHM == "RSA" else saved_key


# ========================== STORAGE HELPERS =========================
def load_records():
    global RECORDS
    try:
        with open(DATA_FILE, "rb") as file:
            RECORDS = pickle.load(file)
    except (FileNotFoundError, EOFError):
        RECORDS = []


def save_records():
    with open(DATA_FILE, "wb") as file:
        pickle.dump(RECORDS, file)


def get_input_data():
    print("1. Enter data using keyboard")
    print("2. Read data from file")
    choice = input("Choice: ")
    if choice == "1":
        return input("Enter data: ")
    if choice == "2":
        filename = input("Enter file path: ").strip('"')
        with open(filename, "r") as file:
            return file.read()
    print("Invalid choice")
    return None


def select_record(records):
    if not records:
        print("No records found")
        return None
    for index, record in enumerate(records):
        print(index + 1, record["owner"], record["time"])
    try:
        index = int(input("Select record: ")) - 1
        if 0 <= index < len(records):
            return records[index]
    except ValueError:
        pass
    print("Invalid record")
    return None


# ============================ ROLE ACTIONS ===========================
def upload_record(username):
    data = get_input_data()
    if data is None:
        return

    encrypted = encrypt_data(data)
    public_key, private_key = get_user_keys(username)
    RECORDS.append({
        "owner": username,
        "encrypted": encrypted,
        "encrypted_hash": hash_data(encrypted),
        "plain_hash": hash_data(data),
        "signature": sign_data(encrypted, private_key),
        "public_key": export_public_key(public_key),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "verification": "Not verified",
    })
    save_records()
    print("Data encrypted, signed and uploaded")


def view_own_records(username):
    own_records = [record for record in RECORDS if record["owner"] == username]
    if not own_records:
        print("No records found")
    for record in own_records:
        print("\nTime:", record["time"])
        encrypted = record["encrypted"]
        print("Encrypted:", encrypted.hex() if isinstance(encrypted, bytes) else encrypted)
        print("Encrypted hash:", record["encrypted_hash"])
        print("Plain hash:", record["plain_hash"])


def review_record(username):
    record = select_record(RECORDS)
    if record is None:
        return

    public_key = import_public_key(record["public_key"])
    signature_ok = verify_signature(record["encrypted"], record["signature"], public_key)
    encrypted_hash_ok = hash_data(record["encrypted"]) == record["encrypted_hash"]
    data = decrypt_data(record["encrypted"])
    plain_hash_ok = hash_data(data) == record["plain_hash"]

    print("Decrypted data:", data)
    print("Signature valid:", signature_ok)
    print("Encrypted hash valid:", encrypted_hash_ok)
    print("Plain hash valid:", plain_hash_ok)

    valid = signature_ok and encrypted_hash_ok and plain_hash_ok
    record["verification"] = "Valid" if valid else "Invalid"
    record["verified_by"] = username
    record["verified_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_records()


def audit_records():
    if not RECORDS:
        print("No records found")
    for record in RECORDS:
        public_key = import_public_key(record["public_key"])
        signature_ok = verify_signature(record["encrypted"], record["signature"], public_key)
        print("\nOwner:", record["owner"])
        print("Time:", record["time"])
        print("Encrypted hash:", record["encrypted_hash"])
        print("Plain hash:", record["plain_hash"])
        print("Signature valid:", signature_ok)
        print("Verification:", record["verification"])


# ============================== MENUS ================================
# Only edit the PRINTED role/action names if the story changes.
def user_menu(username, role):
    while True:
        if role == "uploader":
            print("\n1. Upload record\n2. View my records\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                upload_record(username)
            elif choice == "2":
                view_own_records(username)
            elif choice == "0":
                return

        elif role == "reviewer":
            print("\n1. Decrypt and verify record\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                review_record(username)
            elif choice == "0":
                return

        else:
            print("\n1. View hashes and verify signatures\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                audit_records()
            elif choice == "0":
                return


def main():
    load_records()
    while True:
        print("\n=== Secure Record System ===")
        print("1. Login\n0. Exit")
        if input("Choice: ") == "0":
            break

        username = input("Username: ")
        password = input("Password: ")
        user = USERS.get(username)
        if user and user[0] == password:
            print("Logged in as", ROLE_NAMES[user[1]])
            user_menu(username, user[1])
        else:
            print("Invalid login")


if __name__ == "__main__":
    main()
