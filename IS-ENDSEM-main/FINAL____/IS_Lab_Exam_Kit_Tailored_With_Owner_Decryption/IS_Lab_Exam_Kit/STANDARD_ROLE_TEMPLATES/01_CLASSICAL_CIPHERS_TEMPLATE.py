# EXACT ALGORITHMS AVAILABLE
# Encryption: Additive, Multiplicative, Affine, Vigenere, Autokey,
#             Playfair, Hill or Transposition (selected in EDIT BOX 2).
# Record hashing: SHA-256.
# Digital signature: 2048-bit RSA with SHA-256.

"""ROLE TEMPLATE: all Lab 1 classical ciphers."""

import hashlib
import pickle
from datetime import datetime

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from math import gcd


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
# Change only these two lines. Key examples are in 00_TEMPLATE_MAP.txt.
ALGORITHM = "HILL"
CIPHER_KEY = [[3, 3], [2, 5]]

DATA_FILE = "classical_records.pkl"  # Change only if a filename is given.
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
def clean(data):
    return "".join(ch.upper() for ch in data if ch.isalpha())


def playfair_matrix(key):
    letters = []
    for ch in clean(key).replace("J", "I") + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in letters:
            letters.append(ch)
    return [letters[i:i + 5] for i in range(0, 25, 5)]


def playfair_pairs(data, inserting=True):
    data, pairs, i = clean(data).replace("J", "I"), [], 0
    while i < len(data):
        first = data[i]
        second = data[i + 1] if i + 1 < len(data) else "X"
        if inserting and first == second:
            pairs.append((first, "X"))
            i += 1
        else:
            pairs.append((first, second))
            i += 2
    return pairs


def playfair_change(first, second, matrix, direction):
    positions = {}
    for row in range(5):
        for column in range(5):
            positions[matrix[row][column]] = (row, column)
    r1, c1 = positions[first]
    r2, c2 = positions[second]
    if r1 == r2:
        return matrix[r1][(c1 + direction) % 5] + matrix[r2][(c2 + direction) % 5]
    if c1 == c2:
        return matrix[(r1 + direction) % 5][c1] + matrix[(r2 + direction) % 5][c2]
    return matrix[r1][c2] + matrix[r2][c1]


def hill_inverse(key):
    a, b = key[0]
    c, d = key[1]
    inverse = pow((a * d - b * c) % 26, -1, 26)
    return [[d * inverse % 26, -b * inverse % 26],
            [-c * inverse % 26, a * inverse % 26]]


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


def encrypt_data(data, key=CIPHER_KEY):
    data = clean(data)
    if ALGORITHM == "ADDITIVE":
        return "".join(chr((ord(ch) - 65 + key) % 26 + 65) for ch in data)
    if ALGORITHM == "MULTIPLICATIVE":
        if gcd(key, 26) != 1:
            raise ValueError("Key must be coprime with 26")
        return "".join(chr(((ord(ch) - 65) * key) % 26 + 65) for ch in data)
    if ALGORITHM == "AFFINE":
        a, b = key
        return "".join(chr((a * (ord(ch) - 65) + b) % 26 + 65) for ch in data)
    if ALGORITHM == "VIGENERE":
        key = clean(key)
        return "".join(chr((ord(ch) - 65 + ord(key[i % len(key)]) - 65) % 26 + 65)
                       for i, ch in enumerate(data))
    if ALGORITHM == "AUTOKEY":
        numbers = [ord(ch) - 65 for ch in data]
        stream = [key % 26] + numbers[:-1]
        return "".join(chr((value + stream[i]) % 26 + 65) for i, value in enumerate(numbers))
    if ALGORITHM == "PLAYFAIR":
        matrix = playfair_matrix(key)
        return "".join(playfair_change(a, b, matrix, 1) for a, b in playfair_pairs(data))
    if ALGORITHM == "HILL":
        return hill(data, key)
    if ALGORITHM == "TRANSPOSITION":
        while len(data) % len(key):
            data += "X"
        return "".join("".join(data[i:i + len(key)][position] for position in key)
                       for i in range(0, len(data), len(key)))
    raise ValueError("Unknown algorithm")


def decrypt_data(encrypted_data, key=CIPHER_KEY):
    data = clean(encrypted_data)
    if ALGORITHM == "ADDITIVE":
        return "".join(chr((ord(ch) - 65 - key) % 26 + 65) for ch in data)
    if ALGORITHM == "MULTIPLICATIVE":
        inverse = pow(key, -1, 26)
        return "".join(chr(((ord(ch) - 65) * inverse) % 26 + 65) for ch in data)
    if ALGORITHM == "AFFINE":
        a, b = key
        inverse = pow(a, -1, 26)
        return "".join(chr((inverse * (ord(ch) - 65 - b)) % 26 + 65) for ch in data)
    if ALGORITHM == "VIGENERE":
        key = clean(key)
        return "".join(chr((ord(ch) - 65 - (ord(key[i % len(key)]) - 65)) % 26 + 65)
                       for i, ch in enumerate(data))
    if ALGORITHM == "AUTOKEY":
        recovered = []
        for i, ch in enumerate(data):
            current = key % 26 if i == 0 else recovered[i - 1]
            recovered.append((ord(ch) - 65 - current) % 26)
        return "".join(chr(value + 65) for value in recovered)
    if ALGORITHM == "PLAYFAIR":
        matrix = playfair_matrix(key)
        return "".join(playfair_change(a, b, matrix, -1)
                       for a, b in playfair_pairs(data, False))
    if ALGORITHM == "HILL":
        return hill(data, hill_inverse(key))
    if ALGORITHM == "TRANSPOSITION":
        answer = ""
        for i in range(0, len(data), len(key)):
            block, original = data[i:i + len(key)], [""] * len(key)
            for encrypted_position, original_position in enumerate(key):
                original[original_position] = block[encrypted_position]
            answer += "".join(original)
        return answer
    raise ValueError("Unknown algorithm")


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
