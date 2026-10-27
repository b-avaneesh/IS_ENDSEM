from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from pathlib import Path
from math import gcd
import random
import secrets
import hashlib
import hmac
import math
import base64
import json
import re

# Standalone lab example; local teaching keys are stored in keys/.
TITLE = 'Property Documents'
ASYMMETRIC = 'DH'
BASE = Path(__file__).resolve().parent
BLOCK_CIPHER, KEY_BYTES = AES, 16
P, G = 467, 2


# =========================================================
# SSE - CREATE ENCRYPTED INDEX AND SEARCH
# =========================================================

def token(key, word):
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


def create_index(documents, key, iv=None):
    index = {}
    for doc_id, doc in documents.items():
        for word in set(doc.lower().split()):
            record_iv = get_random_bytes(BLOCK_CIPHER.block_size)
            enc_id = symmetric_encrypt(doc_id, key, record_iv)
            index.setdefault(token(SEARCH_KEY, word), []).append((record_iv.hex(), enc_id))
    (BASE / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return index


def search(index, query, key, documents=None):
    results = []
    for iv_hex, enc_id in index.get(token(SEARCH_KEY, query.strip()), []):
        doc_id = symmetric_decrypt(enc_id, key, bytes.fromhex(iv_hex))
        results.append((doc_id, read_document(doc_id)))
    return results


# =========================================================
# HOMOMORPHIC ENCRYPTION AND DECRYPTION
# =========================================================

def encrypt_homomorphic_paillier(m):
    p = 17
    q = 19
    n = p * q
    n2 = n * n
    g = n + 1
    lam = (p - 1) * (q - 1)
    mu = pow(lam, -1, n)
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c,n2

def decrypt_homomorphic_paillier(c):
    p = 17
    q = 19
    n = p * q
    n2 = n * n
    g = n + 1
    lam = (p - 1) * (q - 1)
    mu = pow(lam, -1, n)
    u = pow(c, lam, n2)
    L = (u - 1) // n
    m = (L * mu) % n
    return m

def expected_homomorphic(a, b):
    return (a + b) % 323


def calculate_homomorphic(a, b):
    if not (0 <= a < 323 and 0 <= b < 323):
        raise ValueError("Use integers from 0 to 322")
    c1, modulus = encrypt_homomorphic_paillier(a)
    c2, modulus = encrypt_homomorphic_paillier(b)
    return {"operation": "addition modulo 323", "ciphertext": c1 * c2 % modulus}


def decrypt_homomorphic(ciphertext):
    return decrypt_homomorphic_paillier(ciphertext)


# =========================================================
# GENERATE KEYS, SIGN MESSAGE AND VERIFY SIGNATURE
# =========================================================

def digest_text(text):
    value = 5381
    for byte in text.encode():
        value = ((value * 33) + byte) & 0xffffffff
    return f"{value:08x}"

def generate_keys():
    private_key = RSA.generate(2048)
    return private_key, private_key.publickey().export_key().decode()


def sign_message(message, private_key):
    signature = pkcs1_15.new(private_key).sign(SHA256.new(message.encode()))
    return signature.hex(), digest_text(message)


def verify_signature(message, signature, public_key):
    try:
        pkcs1_15.new(RSA.import_key(public_key)).verify(SHA256.new(message.encode()), bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


# =========================================================
# AES-128 ENCRYPTION AND DECRYPTION
# =========================================================

def symmetric_encrypt(plaintext, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext.encode(), BLOCK_CIPHER.block_size)).hex()


def symmetric_decrypt(ciphertext_hex, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), BLOCK_CIPHER.block_size).decode()


# =========================================================
# DH KEY PROTECTION
# =========================================================

def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def wrap_key(key):
    ephemeral = secrets.randbelow(P - 3) + 2
    public = pow(G, ephemeral, P)
    shared = pow(PUBLIC_Y, ephemeral, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return [public, b64(cipher.nonce), b64(ciphertext), b64(tag)]

def unwrap_key(wrapped):
    public, nonce, ciphertext, tag = wrapped
    shared = pow(public, PRIVATE_X, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=unb64(nonce))
    return cipher.decrypt_and_verify(unb64(ciphertext), unb64(tag))

# =========================================================
# TRANSPOSITION CLASSICAL CIPHER
# =========================================================

def transposition_key_order(key):
    return sorted(range(len(key)), key=lambda i: (key[i], i))

def transposition_encrypt(plaintext, key):
    cols = len(key)
    padded = plaintext + "X" * (-len(plaintext) % cols)
    rows = [padded[i:i + cols] for i in range(0, len(padded), cols)]
    order = transposition_key_order(key)
    return "".join("".join(row[c] for row in rows) for c in order)

def transposition_decrypt(ciphertext, key):
    cols = len(key)
    rows_count = len(ciphertext) // cols
    order = transposition_key_order(key)
    col_texts = [ciphertext[i * rows_count:(i + 1) * rows_count] for i in range(cols)]
    columns = [None] * cols
    for i, original_col in enumerate(order):
        columns[original_col] = col_texts[i]
    rows = ["".join(columns[c][r] for c in range(cols)) for r in range(rows_count)]
    return "".join(rows)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = transposition_encrypt(text, "ZEBRA")
    decrypted = transposition_decrypt(encrypted, "ZEBRA")
    return {"algorithm": "Transposition", "ciphertext": encrypted, "decrypted_text": decrypted}

# =========================================================
# FILE STORAGE
# =========================================================


def initialize():
    global SERVER_RSA, SERVER_ECC, PRIVATE_X, PUBLIC_Y
    for name in ("encrypted", "hashes", "signature", "public_key", "add", "metadata", "keys"):
        (BASE / name).mkdir(parents=True, exist_ok=True)
    key_file = BASE / "keys" / "local.json"
    if key_file.exists():
        state = json.loads(key_file.read_text())
    else:
        state = {"symmetric": get_random_bytes(KEY_BYTES).hex(),
                 "search": get_random_bytes(32).hex()}
        if ASYMMETRIC == "RSA":
            state["private"] = RSA.generate(2048).export_key().decode()
        elif ASYMMETRIC == "ECDH":
            state["private"] = ECC.generate(curve="P-256").export_key(format="PEM")
        else:
            state["private"] = secrets.randbelow(P - 3) + 2
        key_file.write_text(json.dumps(state), encoding="utf-8")
    if ASYMMETRIC == "RSA":
        SERVER_RSA = RSA.import_key(state["private"])
    elif ASYMMETRIC == "ECDH":
        SERVER_ECC = ECC.import_key(state["private"])
    else:
        PRIVATE_X = state["private"]
        PUBLIC_Y = pow(G, PRIVATE_X, P)
    return bytes.fromhex(state["symmetric"]), bytes.fromhex(state["search"])


def record_path(folder, filename):
    if (not filename or filename in (".", "..") or
            any(ch in filename for ch in '<>:"/\\|?*') or
            filename.endswith((".", " ")) or
            filename.split('.')[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
             *[f"LPT{i}" for i in range(1, 10)]}):
        raise ValueError("Enter a plain filename, for example report1.txt")
    return BASE / folder / filename


def write_file(folder, filename, value):
    record_path(folder, filename).write_text(value, encoding="utf-8")


def read_file(folder, filename):
    return record_path(folder, filename).read_text(encoding="utf-8")


def load_documents():
    documents = {}
    for file in (BASE / "encrypted").iterdir():
        if file.is_file():
            try:
                documents[file.name] = read_document(file.name)
            except (ValueError, OSError, KeyError, TypeError):
                print("Skipping invalid document:", file.name)
    return documents


# =========================================================
# STUDENT
# =========================================================

def student(filename, plaintext, num1, num2, key, iv):
    if record_path("encrypted", filename).exists():
        raise ValueError("Document already exists!")
    homomorphic = calculate_homomorphic(num1, num2)
    # A fresh IV is stored for each record.
    iv = get_random_bytes(BLOCK_CIPHER.block_size)
    ciphertext = symmetric_encrypt(plaintext, key, iv)
    private_key, public_key = generate_keys()
    signature, hash_value = sign_message(ciphertext, private_key)
    metadata = {"iv": iv.hex(), "wrapped_key": wrap_key(key), "num1": num1, "num2": num2}
    write_file("encrypted", filename, ciphertext)
    write_file("hashes", filename, hash_value)
    write_file("signature", filename, json.dumps(signature))
    write_file("public_key", filename, json.dumps(public_key))
    write_file("add", filename, json.dumps(homomorphic))
    write_file("metadata", filename, json.dumps(metadata))
    print("Encrypted", homomorphic["operation"], ":", homomorphic["ciphertext"])
    print("Record uploaded successfully.")

# =========================================================
# READ DOCUMENT
# =========================================================

def read_document(filename):
    ciphertext = read_file("encrypted", filename)
    if digest_text(ciphertext) != read_file("hashes", filename):
        raise ValueError("Integrity verification failed.")
    signature = json.loads(read_file("signature", filename))
    public_key = json.loads(read_file("public_key", filename))
    if not verify_signature(ciphertext, signature, public_key):
        raise ValueError("Digital signature verification failed.")
    metadata = json.loads(read_file("metadata", filename))
    key = unwrap_key(metadata["wrapped_key"])
    return symmetric_decrypt(ciphertext, key, bytes.fromhex(metadata["iv"]))

# =========================================================
# FACULTY
# =========================================================

def faculty(filename, num1=None, num2=None, key=None, iv=None):
    ciphertext = read_file("encrypted", filename)
    print("\nStudent Hash :", read_file("hashes", filename))
    print("Faculty Hash :", digest_text(ciphertext))
    plaintext = read_document(filename)
    print("Hash verified successfully.")
    print("Signature verified:", True)
    metadata = json.loads(read_file("metadata", filename))
    homomorphic = json.loads(read_file("add", filename))
    result = decrypt_homomorphic(homomorphic["ciphertext"])
    expected = expected_homomorphic(metadata["num1"], metadata["num2"])
    print("Homomorphic decrypted result:", result)
    if result != expected:
        raise ValueError("Homomorphic verification failed.")
    print("homomorphic verified")
    print("\nPlaintext:")
    print(plaintext)
    return plaintext

# =========================================================
# HOD
# =========================================================

def hod(filename):
    ciphertext = read_file("encrypted", filename)
    saved_hash = read_file("hashes", filename)
    signature = json.loads(read_file("signature", filename))
    public_key = json.loads(read_file("public_key", filename))
    result = (digest_text(ciphertext) == saved_hash and
              verify_signature(ciphertext, signature, public_key))
    print("\nHash:", saved_hash)
    print("Signature and hash verified:", result)
    return result

# =========================================================
# MAIN MENU
# =========================================================

def main():
    global SEARCH_KEY
    key, SEARCH_KEY = initialize()
    documents = load_documents()
    num1=0
    num2=0
    iv = None
    create_index(documents, key)
    while True:

        print("\n" + "=" * 40)
        print("             " + TITLE)
        print("=" * 40)
        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")
        print("=" * 40)

        choice = input("Enter choice: ")

        if choice == "1":

            while True:
                print("\n------ Student Menu ------")
                print("1. Add a new document")
                print("2. view documents")
                print("3. Back to main menu")
                print("4. Classical cipher demonstration")

                student_choice = input("Enter choice: ")

                if student_choice == "1":

                    filename = input("Enter filename: ").strip()

                    if filename == "":
                        print("Filename cannot be empty.")
                        continue

                    if filename in documents:
                        print("Document already exists!")
                        continue

                    plaintext = input("Enter document record: ")


                    try:
                        num1 = int(input("Enter first integer: "))
                        num2 = int(input("Enter second integer: "))
                    except ValueError:
                        print("Enter valid integers.")
                        continue

                    try:
                        student(filename, plaintext, num1, num2, key, iv)
                        documents[filename] = plaintext
                        create_index(documents, key)
                    except (ValueError, OSError) as exc:
                        print(exc)

                elif student_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:
                        print("\n------ All Documents ------")

                        for filename, plaintext in documents.items():
                            print(f"\nFilename: {filename}")
                            print(f"Plaintext: {plaintext}")
                elif student_choice == "4":
                    try:
                        result = classical_demo(input("Enter classical cipher text: "))
                        print("Ciphertext:", result["ciphertext"])
                        print("Decrypted text:", result["decrypted_text"])
                    except ValueError as exc:
                        print(exc)

                elif student_choice == "3":
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == "2":

            while True:
                print("\n------ Faculty Menu ------")
                print("1. Verify and decrypt a document")
                print("2. Enter searchable text")
                print("3. Back to main menu")

                faculty_choice = input("Enter choice: ")

                if faculty_choice == "1":

                    filename = input("Enter filename: ").strip()

                    if filename not in documents:
                        print("Document not found!")
                        continue


                    try:
                        faculty(filename)
                    except (ValueError, OSError, KeyError, TypeError) as exc:
                        print(exc)

                elif faculty_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:                        
                        search_text = input("Enter searchable text: ").lower()
                        encrypted_index = json.loads((BASE / "index.json").read_text())
                        try:
                            results = search(encrypted_index, search_text, key, documents)
                        except (ValueError, OSError, KeyError, TypeError) as exc:
                            print(exc)
                            continue
                        
                        
                        if results:
                            for doc_id, doc in results:
                                print(doc_id, ":", doc)
                        else:
                            print("No matching documents found")
                        

                elif faculty_choice == "3":
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == "3":

            filename = input("Enter filename: ")

            try:
                hod(filename)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                print(exc)

        elif choice == "4":

            print("\nExiting " + TITLE + "...")
            break

        else:

            print("\nInvalid choice. Please try again.")

# =========================================================
# PROGRAM START
# =========================================================

if __name__ == "__main__":
    main()
