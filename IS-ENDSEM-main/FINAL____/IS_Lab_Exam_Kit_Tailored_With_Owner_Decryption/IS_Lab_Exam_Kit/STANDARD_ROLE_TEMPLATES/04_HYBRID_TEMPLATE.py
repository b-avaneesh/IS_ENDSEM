# EXACT ALGORITHMS AVAILABLE
# RSA-HYBRID: RSA-OAEP encrypts the AES key; AES-128 EAX encrypts the record.
# ECC-HYBRID: ECC P-256 creates a shared key; AES-128 EAX encrypts the record.
# DH-AES: Diffie-Hellman creates a shared key; AES-128 EAX encrypts the record.
# Record hashing: SHA-256. Digital signature: 2048-bit RSA with SHA-256.
# HYBRID simply means: public-key method handles the key, AES handles the data.

"""ROLE TEMPLATE: RSA-hybrid, ECC-hybrid or Diffie-Hellman + AES."""

import hashlib
import pickle
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Random import get_random_bytes
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
# Change only this line: "RSA-HYBRID", "ECC-HYBRID" or "DH-AES".
ALGORITHM = "ECC-HYBRID"

DATA_FILE = "hybrid_records.pkl"  # Change only if a filename is given.
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
def load_encryption_keys():
    key_file = ALGORITHM.lower() + "_key.pem"
    try:
        with open(key_file, "rt") as file:
            saved_key = file.read()
        private_key = RSA.import_key(saved_key) if ALGORITHM == "RSA-HYBRID" else ECC.import_key(saved_key)
    except FileNotFoundError:
        private_key = RSA.generate(2048) if ALGORITHM == "RSA-HYBRID" else ECC.generate(curve="P-256")
        with open(key_file, "wt") as file:
            file.write(private_key.export_key(format="PEM").decode()
                       if ALGORITHM == "RSA-HYBRID" else private_key.export_key(format="PEM"))
    return private_key.public_key(), private_key


if ALGORITHM == "DH-AES":
    P, G, ENCRYPTION_PRIVATE = 7919, 2, 1234
    ENCRYPTION_PUBLIC = pow(G, ENCRYPTION_PRIVATE, P)
else:
    ENCRYPTION_PUBLIC, ENCRYPTION_PRIVATE = load_encryption_keys()


def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    encrypted, tag = cipher.encrypt_and_digest(data.encode())
    return encrypted, cipher.nonce, tag


def aes_decrypt(package, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=package["nonce"])
    return cipher.decrypt_and_verify(package["data"], package["tag"]).decode()


def encrypt_data(data, key=ENCRYPTION_PUBLIC):
    if ALGORITHM == "RSA-HYBRID":
        aes_key = get_random_bytes(16)
        encrypted, nonce, tag = aes_encrypt(data, aes_key)
        return {"data": encrypted, "nonce": nonce, "tag": tag,
                "encrypted_key": PKCS1_OAEP.new(key).encrypt(aes_key)}
    if ALGORITHM == "ECC-HYBRID":
        temporary = ECC.generate(curve="P-256")
        shared = key.pointQ * temporary.d
        aes_key = SHA256.new(int(shared.x).to_bytes(32, "big")).digest()[:16]
        encrypted, nonce, tag = aes_encrypt(data, aes_key)
        return {"data": encrypted, "nonce": nonce, "tag": tag,
                "temporary_public": temporary.public_key().export_key(format="PEM")}
    sender_private = 4321
    shared = pow(key, sender_private, P)
    aes_key = SHA256.new(str(shared).encode()).digest()[:16]
    encrypted, nonce, tag = aes_encrypt(data, aes_key)
    return {"data": encrypted, "nonce": nonce, "tag": tag,
            "sender_public": pow(G, sender_private, P)}


def decrypt_data(encrypted_data, key=ENCRYPTION_PRIVATE):
    if ALGORITHM == "RSA-HYBRID":
        aes_key = PKCS1_OAEP.new(key).decrypt(encrypted_data["encrypted_key"])
    elif ALGORITHM == "ECC-HYBRID":
        temporary = ECC.import_key(encrypted_data["temporary_public"])
        shared = temporary.pointQ * key.d
        aes_key = SHA256.new(int(shared.x).to_bytes(32, "big")).digest()[:16]
    else:
        shared = pow(encrypted_data["sender_public"], key, P)
        aes_key = SHA256.new(str(shared).encode()).digest()[:16]
    return aes_decrypt(encrypted_data, aes_key)


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
