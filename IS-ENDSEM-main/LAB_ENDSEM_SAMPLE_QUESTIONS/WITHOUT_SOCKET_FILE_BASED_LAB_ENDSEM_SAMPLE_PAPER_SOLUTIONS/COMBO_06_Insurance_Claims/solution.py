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
TITLE = 'Insurance Claims'
ASYMMETRIC = 'ElGamal'
BASE = Path(__file__).resolve().parent
BLOCK_CIPHER, KEY_BYTES = AES, 16
P, G = 467, 2
SIG_P, SIG_G = 467, 2


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

HOM_P, HOM_G, HOM_X = 467, 2, 127
HOM_Y = pow(HOM_G, HOM_X, HOM_P)


def encrypt_homomorphic_elgamal(m):
    k = secrets.randbelow(HOM_P - 2) + 1
    return pow(HOM_G, k, HOM_P), m * pow(HOM_Y, k, HOM_P) % HOM_P


def decrypt_homomorphic(ciphertext):
    a, b = ciphertext
    return b * pow(pow(a, HOM_X, HOM_P), -1, HOM_P) % HOM_P


def expected_homomorphic(a, b):
    return a * b % HOM_P


def calculate_homomorphic(a, b):
    if not (1 <= a < HOM_P and 1 <= b < HOM_P):
        raise ValueError("Use integers from 1 to 466")
    c1, c2 = encrypt_homomorphic_elgamal(a), encrypt_homomorphic_elgamal(b)
    combined = [c1[0] * c2[0] % HOM_P, c1[1] * c2[1] % HOM_P]
    return {"operation": "multiplication modulo 467", "ciphertext": combined}


# =========================================================
# GENERATE KEYS, SIGN MESSAGE AND VERIFY SIGNATURE
# =========================================================

def digest_text(text):
    return hashlib.sha1(text.encode()).hexdigest()

def generate_keys():
    private_key = secrets.randbelow(SIG_P - 2) + 1
    return private_key, pow(SIG_G, private_key, SIG_P)


def sign_message(content, private_key):
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    k = secrets.randbelow(SIG_P - 2) + 1
    while math.gcd(k, SIG_P - 1) != 1:
        k = secrets.randbelow(SIG_P - 2) + 1
    r = pow(SIG_G, k, SIG_P)
    s = ((value - private_key * r) * pow(k, -1, SIG_P - 1)) % (SIG_P - 1)
    return [r, s], digest_text(content)

def verify_signature(content, signature, public_key):
    r, s = signature
    if not (0 < r < SIG_P and 0 <= s < SIG_P - 1):
        return False
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    y = public_key
    return pow(SIG_G, value, SIG_P) == pow(y, r, SIG_P) * pow(r, s, SIG_P) % SIG_P


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
# ElGamal KEY PROTECTION
# =========================================================

def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def wrap_key(key):
    pairs = []
    for byte in key:
        k = secrets.randbelow(P - 3) + 2
        pairs.append([pow(G, k, P), (byte + 1) * pow(PUBLIC_Y, k, P) % P])
    return pairs

def unwrap_key(wrapped):
    return bytes((b * pow(pow(a, PRIVATE_X, P), -1, P) % P) - 1
                 for a, b in wrapped)

# =========================================================
# PLAYFAIR CLASSICAL CIPHER
# =========================================================

def playfair_build_grid(key):
    key = "".join(ch for ch in key.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").replace("J", "I")
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    grid = [seen[i * 5:(i + 1) * 5] for i in range(5)]
    pos = {ch: (r, c) for r, row in enumerate(grid) for c, ch in enumerate(row)}
    return grid, pos

def playfair_prepare_digraphs(plaintext):
    letters = "".join(ch for ch in plaintext.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").replace("J", "I")
    i, digraphs = 0, []
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else "X"
        if a == b:
            digraphs.append(a + ("Q" if a == "X" else "X"))
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    if digraphs and len(digraphs[-1]) == 1:
        digraphs[-1] += "X"
    return digraphs

def playfair_encrypt(plaintext, key):
    grid, pos = playfair_build_grid(key)
    out = []
    for a, b in playfair_prepare_digraphs(plaintext):
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(grid[ra][(ca + 1) % 5] + grid[rb][(cb + 1) % 5])
        elif ca == cb:
            out.append(grid[(ra + 1) % 5][ca] + grid[(rb + 1) % 5][cb])
        else:
            out.append(grid[ra][cb] + grid[rb][ca])
    return "".join(out)

def playfair_decrypt(ciphertext, key):
    grid, pos = playfair_build_grid(key)
    out = []
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(grid[ra][(ca - 1) % 5] + grid[rb][(cb - 1) % 5])
        elif ca == cb:
            out.append(grid[(ra - 1) % 5][ca] + grid[(rb - 1) % 5][cb])
        else:
            out.append(grid[ra][cb] + grid[rb][ca])
    return "".join(out)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = playfair_encrypt(text, "GUIDANCE")
    decrypted = playfair_decrypt(encrypted, "GUIDANCE")
    return {"algorithm": "Playfair", "ciphertext": encrypted, "decrypted_text": decrypted}

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
