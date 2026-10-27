from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# You are tasked with developing a secure education data management system called EduSecure. This system ensures that students’ academic records are stored confidentially, accessed only by authorized users, and verified for authenticity. The system supports three types of users: Students, Faculties, and HoDs, each with specific roles and permissions.
#
# The platform uses DES symmetric encryption for storing sensitive academic records, RSA digital signatures for authenticating users, and SHA-256 hashing to verify record integrity.
#
# User Roles & Permissions
#
# Student:
#
# Encrypts a student’s academic records (for example: - ISL-5CCE-A2.txt) using DES before uploading.
#
# Signs the SHA-256 hash of the encrypted record using his/her RSA private key.
#
# Can view past uploaded records and his/her encrypted/hashed forms with timestamps.
#
# Faculty:
#
# Decrypts the student’s records using the shared DES key.
#
# Verifies RSA signatures of the students to ensure authenticity.
#
# Computes SHA-256 hash of decrypted records and compares with the stored hash.
#
# Stores verification results with timestamps.
#
# HoD:
#
# Can view only the hashed academic records with timestamps.
#
# Verifies RSA signatures on stored records for accreditation purposes.
#
# Access Roles:
#
# Allow Students to encrypt records with DES, sign using RSA, and upload securely.
#
# Enable Faculties to decrypt with DES, verify RSA signatures, and hash the records.
#
# Allow HoDs to view only hashes and verify signatures.
#
# Task:
#
# Develop a menu-driven Python program that implements these functionalities using:
#
# DES symmetric encryption,
#
# RSA digital signatures, and
#
# SHA-256 hashing.
#
# Ensure secure handling of academic records and proper role-based access. Use any file or database structure to store and retrieve the records securely.
# =========================================================
# RSA DIGITAL SIGNATURE
# =========================================================

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

def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)

    padded_text = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_text)

    return ciphertext.hex()


def des_decrypt(ciphertext_hex, key):
    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = DES.new(key, DES.MODE_ECB)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        DES.block_size
    )

    return plaintext.decode()


# =========================================================
# STUDENT
# =========================================================

def student(filename, plaintext):

    # DES encryption
    key = b"A1B2C3D4"
    des_ciphertext = des_encrypt(plaintext, key)

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

    print("Record uploaded successfully.")


# =========================================================
# FACULTY
# =========================================================

def faculty(filename):

    # Read encrypted record
    with open("encrypted/" + filename, "r") as f:
        ciphertext = f.read()

    # -----------------------------------------------------
    # Verify SHA-256 hash
    # -----------------------------------------------------

    faculty_hash = SHA256.new(ciphertext.encode())

    with open("hashes/" + filename, "r") as f:
        student_hash = f.read()

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

    key = b"A1B2C3D4"
    plaintext = des_decrypt(ciphertext, key)

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

            filename = input("Enter filename: ")
            plaintext = input("Enter academic record: ")

            student(filename, plaintext)

        elif choice == "2":

            filename = input("Enter filename: ")

            faculty(filename)

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