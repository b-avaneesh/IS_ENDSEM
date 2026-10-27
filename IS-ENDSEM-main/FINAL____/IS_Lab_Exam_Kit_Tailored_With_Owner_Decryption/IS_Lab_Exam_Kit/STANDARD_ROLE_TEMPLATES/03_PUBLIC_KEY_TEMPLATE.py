# EXACT ALGORITHMS AVAILABLE
# Encryption: educational RSA, ElGamal or Rabin, selected in EDIT BOX 2.
# Record hashing: SHA-256.
# Digital signature: separate 2048-bit RSA signature with SHA-256.

"""ROLE TEMPLATE: RSA, ElGamal or Rabin encryption."""

import hashlib
import pickle
from datetime import datetime

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


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
# Change only this line: "RSA", "ELGAMAL" or "RABIN".
ALGORITHM = "RSA"

DATA_FILE = "public_key_records.pkl"  # Change only if a filename is given.
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
# The small fixed keys keep the exam code easy and reproducible.
def generate_encryption_keys():
    if ALGORITHM == "RSA":
        return (3233, 17), (3233, 2753)
    if ALGORITHM == "ELGAMAL":
        p, g, private = 7919, 2, 2999
        return (p, g, pow(g, private, p)), (p, private)
    if ALGORITHM == "RABIN":
        p, q = 499, 547                    # Both are 3 mod 4.
        return p * q, (p, q)
    raise ValueError("Unknown algorithm")


ENCRYPTION_PUBLIC, ENCRYPTION_PRIVATE = generate_encryption_keys()


def encrypt_data(data, key=ENCRYPTION_PUBLIC):
    if ALGORITHM == "RSA":
        n, e = key
        return [pow(ord(ch), e, n) for ch in data]
    if ALGORITHM == "ELGAMAL":
        p, g, public = key
        k = 11
        return [(pow(g, k, p), ord(ch) * pow(public, k, p) % p) for ch in data]
    n = key
    return [pow(ord(ch) * 1000 + 123, 2, n) for ch in data]


def decrypt_data(encrypted_data, key=ENCRYPTION_PRIVATE):
    if ALGORITHM == "RSA":
        n, d = key
        return "".join(chr(pow(value, d, n)) for value in encrypted_data)
    if ALGORITHM == "ELGAMAL":
        p, private = key
        return "".join(chr(b * pow(pow(a, private, p), -1, p) % p)
                       for a, b in encrypted_data)
    p, q = key
    n = p * q
    answer = ""
    for value in encrypted_data:
        mp, mq = pow(value, (p + 1) // 4, p), pow(value, (q + 1) // 4, q)
        yp, yq = pow(p, -1, q), pow(q, -1, p)
        root = (yp * p * mq + yq * q * mp) % n
        roots = [root, (-root) % n]
        other = (yp * p * mq - yq * q * mp) % n
        roots += [other, (-other) % n]
        message = next(number for number in roots if number % 1000 == 123)
        answer += chr(message // 1000)
    return answer


def attack_weak_rsa(encrypted_data, public_key=ENCRYPTION_PUBLIC):
    """Use only when the question asks to attack/factor a small RSA key."""
    n, e = public_key
    for p in range(2, int(n ** 0.5) + 1):
        if n % p == 0:
            q = n // p
            d = pow(e, -1, (p - 1) * (q - 1))
            return decrypt_data(encrypted_data, (n, d)), p, q
    return None


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
