# EXACT ALGORITHMS AVAILABLE
# Encryption: DES, AES-128/192/256 or Triple DES.
# Mode: ECB, CBC, CFB, OFB or CTR, selected in EDIT BOX 2.
# Record hashing: SHA-256.
# Digital signature: 2048-bit RSA with SHA-256.

"""SHORT GENERIC EXAM TEMPLATE

Ready for an EduSecure-style question: encryption, SHA-256, RSA signature,
three roles, keyboard/file input, timestamps and file storage.

For DES/AES, edit only CIPHER_NAME and CIPHER_KEY below.
Internal code uses generic words: user, uploader, reviewer, auditor and record.
"""

import hashlib
import pickle
from datetime import datetime

from Crypto.Cipher import AES, DES, DES3
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


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
# Change ONLY these two lines when DES/AES changes.
# DES:     CIPHER_NAME="DES"  and an 8-byte key
# AES-128: CIPHER_NAME="AES"  and a 16-byte key
# AES-192: CIPHER_NAME="AES"  and a 24-byte key
# AES-256: CIPHER_NAME="AES"  and a 32-byte key
# 3DES:    CIPHER_NAME="3DES" and a valid 16/24-byte key
CIPHER_NAME = "DES"
CIPHER_KEY = b"SECUREK1"
CIPHER_MODE = "ECB"              # ECB, CBC, CFB, OFB or CTR
IV = b"1234567890ABCDEF"          # First 8 bytes for DES; 16 for AES.
NONCE = b"12345678"               # Used only for CTR.

DATA_FILE = "symmetric_records.pkl"  # Change only if a filename is given.
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
# Do not edit these for DES/AES/3DES ECB. Edit Box 2 only.
def cipher_module():
    return {"DES": DES, "AES": AES, "3DES": DES3}[CIPHER_NAME]


def encrypt_data(data, key=CIPHER_KEY):
    algorithm = cipher_module()
    mode = CIPHER_MODE.upper()
    if mode == "ECB":
        cipher = algorithm.new(key, algorithm.MODE_ECB)
        return cipher.encrypt(pad(data.encode(), algorithm.block_size))
    if mode == "CTR":
        cipher = algorithm.new(key, algorithm.MODE_CTR, nonce=NONCE)
        return cipher.encrypt(data.encode())
    mode_value = {"CBC": algorithm.MODE_CBC,
                  "CFB": algorithm.MODE_CFB,
                  "OFB": algorithm.MODE_OFB}[mode]
    cipher = algorithm.new(key, mode_value, iv=IV[:algorithm.block_size])
    message = pad(data.encode(), algorithm.block_size) if mode == "CBC" else data.encode()
    return cipher.encrypt(message)


def decrypt_data(encrypted_data, key=CIPHER_KEY):
    algorithm = cipher_module()
    mode = CIPHER_MODE.upper()
    if mode == "ECB":
        plain = algorithm.new(key, algorithm.MODE_ECB).decrypt(encrypted_data)
        return unpad(plain, algorithm.block_size).decode()
    if mode == "CTR":
        cipher = algorithm.new(key, algorithm.MODE_CTR, nonce=NONCE)
        return cipher.decrypt(encrypted_data).decode()
    mode_value = {"CBC": algorithm.MODE_CBC,
                  "CFB": algorithm.MODE_CFB,
                  "OFB": algorithm.MODE_OFB}[mode]
    cipher = algorithm.new(key, mode_value, iv=IV[:algorithm.block_size])
    plain = cipher.decrypt(encrypted_data)
    return (unpad(plain, algorithm.block_size) if mode == "CBC" else plain).decode()


def data_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return pickle.dumps(data)


def hash_data(data):
    return hashlib.sha256(data_bytes(data)).hexdigest()


def generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def get_user_keys(username):
    if username not in USER_KEYS:
        USER_KEYS[username] = generate_keys()
    return USER_KEYS[username]


def sign_data(data, private_key):
    return pkcs1_15.new(private_key).sign(SHA256.new(data_bytes(data)))


def verify_signature(data, signature, public_key):
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data_bytes(data)), signature)
        return True
    except (ValueError, TypeError):
        return False


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
        "public_key": public_key.export_key(),
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

    public_key = RSA.import_key(record["public_key"])
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
        public_key = RSA.import_key(record["public_key"])
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
