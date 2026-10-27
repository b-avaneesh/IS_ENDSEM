# HASH PERMUTATION: record/plaintext integrity uses SHA-256.
# Signature generation and verification still use SHA-256 internally.
# =====================================================================
# SHORT REQUIREMENTS FOR THIS PERMUTATION
# - Patient uploads a report by keyboard/text file and views only own history.
# - Doctor opens only reports assigned to that doctor and verifies hash/signature.
# - Administrator sees owner, hashes, timestamps and status, never plaintext.
# - The confidentiality algorithm is replaced by the named permutation below.
#
# EXACT CRYPTOGRAPHY IN THIS SOLUTION
# - Encryption/decryption: 2x2 Hill cipher (key matrix [[3,3],[2,5]]).
# - Record hashing: SHA-256.
# - Digital signature: 2048-bit RSA with SHA-256.
# - Variant filename: ROLE_HILL.py
# =====================================================================
# ================= EXACT ALGORITHMS USED =================
# Encryption/decryption: 2x2 Hill cipher (key matrix [[3,3],[2,5]]).
# Record hashing: SHA-256.
# Digital signature: 2048-bit RSA with SHA-256.
# =========================================================

"""Ready-to-run role template tailored specifically for HILL."""

import hashlib
import pickle
from datetime import datetime
from math import gcd

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# ============================ USER ACCOUNTS ============================
USERS = {
    "user1": ("123", "uploader"),
    "user2": ("123", "reviewer"),
    "user3": ("123", "auditor"),
}

ROLE_NAMES = {
    "uploader": "Patient",
    "reviewer": "Doctor",
    "auditor": "Hospital Administrator",
}


# ========================== FIXED SETTINGS ==========================
CIPHER_KEY = [[3, 3], [2, 5]]
DATA_FILE = "q01_medisecure_hill_sha256_records.pkl"
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def hill(data, key):
    data = clean(data)
    if len(data) % 2:
        data += "X"
    answer = ""
    for i in range(0, len(data), 2):
        x, y = ord(data[i]) - 65, ord(data[i + 1]) - 65
        answer += chr((key[0][0] * x + key[0][1] * y) % 26 + 65)
        answer += chr((key[1][0] * x + key[1][1] * y) % 26 + 65)
    return answer


def hill_inverse(key):
    a, b = key[0]
    c, d = key[1]
    inverse = pow((a * d - b * c) % 26, -1, 26)
    return [[d * inverse % 26, -b * inverse % 26],
            [-c * inverse % 26, a * inverse % 26]]


def encrypt_data(data, key=CIPHER_KEY):
    return hill(data, key)


def decrypt_data(encrypted_data, key=CIPHER_KEY):
    return hill(encrypted_data, hill_inverse(key))


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

    route_value = input("Assigned doctor username: ")
    encrypted = encrypt_data(data)
    public_key, private_key = get_user_keys(username)
    RECORDS.append({
        "owner": username,
        "assigned_doctor": route_value,
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
        try:
            decrypted = decrypt_data(record["encrypted"])
            if isinstance(decrypted, bytes):
                decrypted = decrypted.decode(errors="replace")
            print("Decrypted record:", decrypted)
        except Exception as error:
            print("Could not decrypt this record:", error)


def review_record(username):
    allowed = [record for record in RECORDS if record.get("assigned_doctor") == username]
    record = select_record(allowed)
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
        print("\n=== MediSecure ===")
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
