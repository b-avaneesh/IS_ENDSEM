# HASH PERMUTATION: record/plaintext integrity uses MD5.
# Signature generation and verification still use SHA-256 internally.
# =====================================================================
# SHORT REQUIREMENTS FOR THIS PERMUTATION
# - Buyer addresses each encrypted order to one supplier.
# - Supplier sees only addressed orders and records ACCEPTED or REJECTED.
# - Auditor sees routing/status/hash/signature metadata but never plaintext.
# - The confidentiality algorithm is replaced by the named permutation below.
#
# EXACT CRYPTOGRAPHY IN THIS SOLUTION
# - Encryption/decryption: AES-128 EAX for data; RSA-OAEP for the AES key.
# - Record hashing: MD5.
# - Digital signature: separate 2048-bit RSA with SHA-256.
# - Variant filename: ROLE_RSA_HYBRID.py
# =====================================================================
# ================= EXACT ALGORITHMS USED =================
# Encryption/decryption: AES-128 EAX for data; RSA-OAEP for the AES key.
# Record hashing: MD5.
# Digital signature: separate 2048-bit RSA with SHA-256.
# =========================================================

"""Ready-to-run role template tailored specifically for RSA HYBRID."""

import hashlib
import pickle
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

# ============================ USER ACCOUNTS ============================
USERS = {
    "user1": ("123", "uploader"),
    "user2": ("123", "reviewer"),
    "user3": ("123", "auditor"),
}

ROLE_NAMES = {
    "uploader": "Buyer",
    "reviewer": "Supplier",
    "auditor": "Auditor",
}


# ========================== FIXED SETTINGS ==========================
DATA_FILE = "q05_supply_secure_rsa_hybrid_md5_records.pkl"
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
def load_encryption_keys():
    key_file = "rsa_hybrid_key.pem"
    try:
        with open(key_file, "rb") as file:
            private_key = RSA.import_key(file.read())
    except FileNotFoundError:
        private_key = RSA.generate(2048)
        with open(key_file, "wb") as file:
            file.write(private_key.export_key())
    return private_key.public_key(), private_key


ENCRYPTION_PUBLIC, ENCRYPTION_PRIVATE = load_encryption_keys()


def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    encrypted, tag = cipher.encrypt_and_digest(data.encode())
    return encrypted, cipher.nonce, tag


def aes_decrypt(package, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=package["nonce"])
    return cipher.decrypt_and_verify(package["data"], package["tag"]).decode()


def encrypt_data(data, key=ENCRYPTION_PUBLIC):
    aes_key = get_random_bytes(16)
    encrypted, nonce, tag = aes_encrypt(data, aes_key)
    return {"data": encrypted, "nonce": nonce, "tag": tag,
            "encrypted_key": PKCS1_OAEP.new(key).encrypt(aes_key)}


def decrypt_data(encrypted_data, key=ENCRYPTION_PRIVATE):
    aes_key = PKCS1_OAEP.new(key).decrypt(encrypted_data["encrypted_key"])
    return aes_decrypt(encrypted_data, aes_key)


def data_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return pickle.dumps(data)


def hash_data(data):
    return hashlib.md5(data_bytes(data)).hexdigest()


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

    route_value = input("Supplier username: ")
    encrypted = encrypt_data(data)
    public_key, private_key = get_user_keys(username)
    RECORDS.append({
        "owner": username,
        "supplier": route_value,
        "encrypted": encrypted,
        "encrypted_hash": hash_data(encrypted),
        "plain_hash": hash_data(data),
        "signature": sign_data(encrypted, private_key),
        "public_key": public_key.export_key(),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "verification": "Not verified",
        "status": "PENDING",
        "order_id": len(RECORDS) + 1,
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
    allowed = [record for record in RECORDS if record.get("supplier") == username]
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
    decision = input("Order decision (ACCEPTED/REJECTED): ").upper()
    record["status"] = decision if decision in ("ACCEPTED", "REJECTED") else "PENDING"
    record["status_changed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        print("\n=== SupplySecure ===")
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
