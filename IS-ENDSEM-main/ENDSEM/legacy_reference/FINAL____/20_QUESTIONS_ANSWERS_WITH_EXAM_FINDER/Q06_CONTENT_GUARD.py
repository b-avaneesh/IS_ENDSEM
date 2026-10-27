# =====================================================================
# MAIN QUESTION REQUIREMENTS DIFFERENT FROM ORIGINAL EDUSECURE
# - Use Content Creator, Customer and Administrator roles.
# - Use AES-128 for content but replace RSA signatures with ElGamal signatures.
# - Grant access to a named customer for a limited time and deny expired access.
# - Support customer-access revocation and compromised creator-key revocation.
# =====================================================================
# ================= EXACT ALGORITHMS USED =================
# Primary digital-signature algorithm: ElGamal signature with SHA-256.
# Auxiliary encryption: AES-128 ECB.
# Record hashing: SHA-256.
# =========================================================

"""ANSWER: ContentGuard.

AES-128 encryption, SHA-256 and ElGamal-signature role system.
"""

import hashlib
import os
import pickle
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from math import gcd
import secrets

# ============================ USER ACCOUNTS ============================
USERS = {
    "user1": ("123", "uploader"),
    "user2": ("123", "reviewer"),
    "user3": ("123", "auditor"),
}

ROLE_NAMES = {
    "uploader": "Content Creator",
    "reviewer": "Customer",
    "auditor": "Administrator",
}


# ========================== FIXED SETTINGS ==========================
CIPHER_KEY = b"0123456789ABCDEF"
DATA_FILE = "contentguard_records.pkl"
RECORDS = []
USER_KEYS = {}
REVOKED_CREATORS = set()


# ========================= CRYPTO FUNCTIONS =========================
def encrypt_data(data, key=CIPHER_KEY):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pad(data.encode(), AES.block_size))


def decrypt_data(encrypted_data, key=CIPHER_KEY):
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def data_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return pickle.dumps(data)


def hash_data(data):
    return hashlib.sha256(data_bytes(data)).hexdigest()


def generate_keys():
    p, g = 7919, 2
    private = secrets.randbelow(p - 3) + 2
    return (p, g, pow(g, private, p)), (p, g, private)


def sign_data(data, private_key):
    p, g, private = private_key
    k = secrets.randbelow(p - 2) + 1
    while gcd(k, p - 1) != 1:
        k = secrets.randbelow(p - 2) + 1
    h = int.from_bytes(SHA256.new(data_bytes(data)).digest(), "big")
    r = pow(g, k, p)
    return r, ((h - private * r) * pow(k, -1, p - 1)) % (p - 1)


def verify_signature(data, signature, public_key):
    p, g, public = public_key
    r, s = signature
    h = int.from_bytes(SHA256.new(data_bytes(data)).digest(), "big")
    return pow(g, h, p) == (pow(public, r, p) * pow(r, s, p)) % p


def export_public_key(public_key):
    return public_key


def import_public_key(saved_key):
    return saved_key


def get_user_keys(username):
    if username not in USER_KEYS:
        USER_KEYS[username] = generate_keys()
    return USER_KEYS[username]


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
    if username in REVOKED_CREATORS:
        print("Creator key revoked")
        return
    data = get_input_data()
    if data is None:
        return

    customer = input("Customer username to grant access: ")
    minutes = int(input("Access duration in minutes: "))
    encrypted = encrypt_data(data)
    public_key, private_key = get_user_keys(username)
    RECORDS.append({
        "owner": username,
        "customer": customer,
        "expiry": (datetime.now() + timedelta(minutes=minutes)).isoformat(),
        "access_active": True,
        "content_id": len(RECORDS) + 1,
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
        try:
            decrypted = decrypt_data(record["encrypted"])
            if isinstance(decrypted, bytes):
                decrypted = decrypted.decode(errors="replace")
            print("Decrypted record:", decrypted)
        except Exception as error:
            print("Could not decrypt this record:", error)


def review_record(username):
    allowed = [record for record in RECORDS
               if record.get("customer") == username and record.get("access_active")
               and datetime.now() <= datetime.fromisoformat(record["expiry"])]
    record = select_record(allowed)
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


def revoke_content_access(username):
    own = [record for record in RECORDS if record["owner"] == username]
    record = select_record(own)
    if record:
        record["access_active"] = False
        save_records()
        print("Customer access revoked")


# ============================== MENUS ================================
# Only edit the PRINTED role/action names if the story changes.
def user_menu(username, role):
    while True:
        if role == "uploader":
            print("\n1. Upload content\n2. View my content\n3. Revoke customer access\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                upload_record(username)
            elif choice == "2":
                view_own_records(username)
            elif choice == "3":
                revoke_content_access(username)
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
            print("\n1. View hashes/logs\n2. Revoke creator key\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                audit_records()
            elif choice == "2":
                REVOKED_CREATORS.add(input("Creator username: "))
                print("Creator key revoked")
            elif choice == "0":
                return


def main():
    load_records()
    while True:
        print("\n=== ContentGuard ===")
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
