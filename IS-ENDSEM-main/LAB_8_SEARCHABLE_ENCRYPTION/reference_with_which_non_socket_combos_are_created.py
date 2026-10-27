from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random
from math import gcd
import hashlib
import hmac
from Crypto.Random import get_random_bytes


def token(key, word):
    return hmac.new(key, word.lower().encode(),
                    hashlib.sha256).digest()


# 2. Create and encrypt the inverted index
def create_index(documents, key, iv):
    index = {}

    for doc_id, doc in documents.items():
        for word in doc.lower().split():
            t = token(key, word)

            if t not in index:
                index[t] = []

            enc_id = des_encrypt(doc_id, key, iv)
            index[t].append((iv, enc_id))

    return index


def search(index, query, key, documents):
    t = token(key, query)

    if t not in index:
        return []

    results = []

    for iv, enc_id in index[t]:
        doc_id = des_decrypt(enc_id, key, iv)
        results.append((doc_id, documents[doc_id]))

    return results


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
    return c, n2


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


def encrypt_homomorphic_RSA(m):
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    while gcd(e, phi) != 1:
        e += 1
    d = pow(e, -1, phi)
    # print("Public key:", (e, n))
    # print("Private key:", (d, n))
    return pow(m, e, n), n


def decrypt_homomorphic_RSA(c):
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    while gcd(e, phi) != 1:
        e += 1
    d = pow(e, -1, phi)
    return pow(c, d, n)


def generate_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


def sign_message(message, private_key):
    hash_value = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(hash_value)

    return signature, hash_value


def verify_signature(message, signature, public_key):
    hash_value = SHA256.new(message.encode())

    try:
        pkcs1_15.new(public_key).verify(hash_value, signature)
        return True
    except (ValueError, TypeError):
        return False


# =========================================================
# DES ENCRYPTION AND DECRYPTION
# =========================================================

def des_encrypt(plaintext, key, iv):
    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv=iv
    )

    padded_text = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_text)

    return ciphertext.hex()


def des_decrypt(ciphertext_hex, key, iv):
    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv=iv
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        DES.block_size
    )

    return plaintext.decode()


# =========================================================
# STUDENT
# =========================================================

def student(filename, plaintext, num1, num2, key, iv):
    # DES encryption

    des_ciphertext = des_encrypt(plaintext, key, iv)

    c1, n2 = encrypt_homomorphic_paillier(num1)
    c2, n2 = encrypt_homomorphic_paillier(num2)
    # c_add = (c1 * c2) % n2
    c1, n = encrypt_homomorphic_RSA(num1)
    c2, n = encrypt_homomorphic_RSA(num2)
    c_add = (c1 * c2) % n
    print("Encrypted add:", c_add)

    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Hash and sign the encrypted record
    signature, hash_value = sign_message(
        des_ciphertext,
        private_key
    )

    # Store encrypted record
    with open("encrypted/" + filename, "w") as f:
        f.write(des_ciphertext)

    # Store SHA-256 hash
    with open("hashes/" + filename, "w") as f:
        f.write(hash_value.hexdigest())

    # Store RSA digital signature
    with open("signature/" + filename, "w") as f:
        f.write(signature.hex())

    # Store RSA public key
    with open("public_key/" + filename, "w") as f:
        f.write(public_key.export_key().decode())

    with open("add/" + filename, "w") as f:
        f.write(str(c_add))

    print("Record uploaded successfully.")


# =========================================================
# FACULTY
# =========================================================

def faculty(filename, num1, num2, key, iv):
    # Read encrypted record
    with open("encrypted/" + filename, "r") as f:
        ciphertext = f.read()

    # -----------------------------------------------------
    # Verify SHA-256 hash
    # -----------------------------------------------------

    faculty_hash = SHA256.new(ciphertext.encode())

    with open("hashes/" + filename, "r") as f:
        student_hash = f.read()

    with open("add/" + filename, "r") as f:
        student_add = int(f.read())

        add_decrypt = decrypt_homomorphic_RSA(student_add)
        print(add_decrypt)
        if (add_decrypt == (num1 * num2)):
            print("homomorphic verified")

    print("\nStudent Hash :", student_hash)
    print("Faculty Hash :", faculty_hash.hexdigest())

    if faculty_hash.hexdigest() != student_hash:
        print("Hash is not matching!!!")
        print("Integrity verification failed.")
        return

    print("Hash verified successfully.")

    # -----------------------------------------------------
    # Verify RSA digital signature
    # -----------------------------------------------------

    with open("signature/" + filename, "r") as f:
        signature = bytes.fromhex(f.read())

    with open("public_key/" + filename, "r") as f:
        public_key = RSA.import_key(f.read())

    result = verify_signature(
        ciphertext,
        signature,
        public_key
    )

    print("Signature verified:", result)

    if not result:
        print("Digital signature verification failed.")
        return

    # -----------------------------------------------------
    # Decrypt record
    # -----------------------------------------------------

    plaintext = des_decrypt(ciphertext, key, iv)

    print("\nPlaintext:")
    print(plaintext)


# =========================================================
# HOD
# =========================================================

def hod(filename):
    # Read encrypted record
    with open("encrypted/" + filename, "r") as f:
        ciphertext = f.read()

    # Read hash
    with open("hashes/" + filename, "r") as f:
        student_hash = f.read()

    print("\nHash:", student_hash)

    # Read digital signature
    with open("signature/" + filename, "r") as f:
        signature = bytes.fromhex(f.read())

    # Read RSA public key
    with open("public_key/" + filename, "r") as f:
        public_key = RSA.import_key(f.read())

    # Verify signature
    result = verify_signature(
        ciphertext,
        signature,
        public_key
    )

    print("Signature verified:", result)


# =========================================================
# MAIN MENU
# =========================================================

def main():
    documents = {}
    num1 = 0
    num2 = 0
    key = b"A1B2C3D4"
    iv = b"A1B2C3D4"
    while True:

        print("\n" + "=" * 40)
        print("             EduSecure")
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

                student_choice = input("Enter choice: ")

                if student_choice == "1":

                    filename = input("Enter filename: ").strip()

                    if filename == "":
                        print("Filename cannot be empty.")
                        continue

                    if filename in documents:
                        print("Document already exists!")
                        continue

                    plaintext = input("Enter academic record: ")

                    documents[filename] = plaintext
                    print("Document added successfully!")

                    num1 = int(input("Enter first integer: "))
                    num2 = int(input("Enter second integer: "))

                    student(filename, plaintext, num1, num2, key, iv)

                elif student_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:
                        print("\n------ All Documents ------")

                        for filename, plaintext in documents.items():
                            print(f"\nFilename: {filename}")
                            print(f"Plaintext: {plaintext}")
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

                    faculty(filename, num1, num2, key, iv)

                elif faculty_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:
                        search_text = input("Enter searchable text: ").lower()
                        encrypted_index = create_index(documents, key, iv)
                        results = search(encrypted_index, search_text, key, documents)

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

            hod(filename)

        elif choice == "4":

            print("\nExiting EduSecure...")
            break

        else:

            print("\nInvalid choice. Please try again.")


# =========================================================
# PROGRAM START
# =========================================================

if __name__ == "__main__":
    main()