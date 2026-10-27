# Question 1 — Secure Student Result Transfer
#
# A university wants to securely transfer a student's result from the Examination Section to an authorized Faculty through an insecure network.
#
# Develop a menu-driven Python application called SecureResult using:
#
# AES-128 for confidentiality
# RSA for protecting the AES key
# SHA-256 for integrity
# RSA digital signature for authentication
# Student
#
# The student enters:
#
# Student ID
# Course Code
# Marks
# Grade
#
# The system must:
#
# Encrypt the result using AES-128.
# Generate an RSA key pair.
# Encrypt the AES key using the RSA public key.
# Compute SHA-256 hash of the AES ciphertext.
# Sign the hash using the RSA private key.
# Store the following in separate files:
# encrypted result
# encrypted AES key
# SHA-256 hash
# RSA signature
# RSA public key
# Faculty
#
# Faculty enters the filename.
#
# The system must:
#
# Read the encrypted result.
# Compute its SHA-256 hash.
# Compare it with the stored hash.
# If the hash doesn't match, report tampering and stop.
# Verify the RSA signature.
# Recover the AES key using the RSA private key.
# Decrypt and display the result.
# Tampering test
#
# Modify one character in the encrypted result file and run the Faculty operation again.
#
# Expected behavior:
#
# Hash mismatch
# Integrity verification failed
# No decryption performed
import ast
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def aes_encrypt(plaintext, key):

    # Convert string to bytes
    plaintext = plaintext.encode()

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad plaintext
    padded_text = pad(plaintext, AES.block_size)

    # Encrypt
    ciphertext = cipher.encrypt(padded_text)

    return ciphertext.hex()

def aes_decrypt(ciphertext_hex, key):
    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode()

from math import gcd


def RSA_encrypt(plaintext,e,n):

    # Encryption
    ciphertext = []

    for ch in plaintext:
        M = ord(ch)
        C = pow(M, e, n)
        ciphertext.append(C)

    return ciphertext

def RSA_decrypt(ciphertext,d,n):
    # Decryption
    decrypted = ""

    for C in ciphertext:
        M = pow(C, d, n)
        decrypted += chr(M)

    return decrypted

def generate_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


def sign_message(message, private_key):
    hash_value = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(hash_value)
    return signature, hash_value.hexdigest()


def verify_signature(message, signature, public_key):
    hash_value = SHA256.new(message.encode())

    try:
        pkcs1_15.new(public_key).verify(hash_value, signature)
        return True
    except (ValueError, TypeError):
        return False

def student(filename, plaintext,e,n):
    # -----------------------------
    #encrypt plaintext using aes:
    # -----------------------------

    key = b"0123456789ABCDEF"
    aes_ciphertext = aes_encrypt(plaintext,key)

    # -----------------------------
    #encrypt aes key using rsa:
    # -----------------------------
    encrypted_aes_key = RSA_encrypt(key.decode(),e,n)

    # -----------------------------
    #compute sha256 hash + digital rsa signature
    # -----------------------------
    private_key, public_key = generate_keys()
    signature, hash_val = sign_message(aes_ciphertext,private_key)

    # -----------------------------
    #Storing encrypted data::
    # -----------------------------

    f1 = open("encrypted_ct/"+filename, "w")
    f1.write(aes_ciphertext)

    # -----------------------------
    # Storing encrypted aes key::
    # -----------------------------
    f2 = open("encrypted_key/"+filename, "w")
    f2.write(str(encrypted_aes_key))

    # -----------------------------
    # Storing sha256 hash::
    # -----------------------------
    f3 = open("hashes/"+filename, "w")
    f3.write(hash_val)

    # -----------------------------
    # Storing rsa signature::
    # -----------------------------
    f4 = open("signature/"+filename, "w")
    f4.write(signature.hex())

    # -----------------------------
    # Storing public key of RSA (so that receiver can verify at the other end)::
    # -----------------------------
    f5 = open("public_key/"+filename, "w")
    f5.write(public_key.export_key().decode())

    print("Record uploaded successfully.")

def faculty(filename, d, n):
    # -----------------------------
    # fetching encrypted data::
    # -----------------------------

    f1 = open("encrypted_ct/" + filename, "r")
    ciphertext = f1.read()

    # -----------------------------
    # fetching encrypted aes key::
    # -----------------------------
    f2 = open("encrypted_key/" + filename, "r")
    encrypted_aes_key = ast.literal_eval(f2.read())

    # -----------------------------
    # fetching sha256 hash::
    # -----------------------------
    f3 = open("hashes/" + filename, "r")
    student_hash = f3.read()

    # -----------------------------
    # fetching rsa signature::
    # -----------------------------
    f4 = open("signature/" + filename, "r")
    signature = bytes.fromhex(f4.read())

    # -----------------------------
    # Storing public key of RSA (so that receiver can verify at the other end)::
    # -----------------------------
    f5 = open("public_key/" + filename, "r")
    public_rsa_key = RSA.import_key(f5.read())

    # -----------------------------
    #hash matching:
    # -----------------------------

    faculty_hash = SHA256.new(ciphertext.encode()).hexdigest()

    if faculty_hash != student_hash:
        print("hash is not matching!")
        print("tampering detected!")
        return

    # -----------------------------
    #signature verification:
    # -----------------------------

    result = verify_signature(ciphertext,signature,public_rsa_key)

    if result is False:
        print("Not verified!")
        return

    # -----------------------------
    #recover aes key using rsa private key:
    # -----------------------------

    aes_key = RSA_decrypt(encrypted_aes_key,d,n)

    # -----------------------------
    #final plaintext recovery:
    # -----------------------------

    plaintext = aes_decrypt(ciphertext, aes_key.encode())
    print("Plaintext:", plaintext)

def tamper_file(filename):

    f = open("encrypted_ct/"+filename, "r")
    ciphertext = f.read()
    f.close()

    # Change exactly one hexadecimal character
    if ciphertext[0] != "0":
        tampered_ciphertext = "0" + ciphertext[1:]
    else:
        tampered_ciphertext = "1" + ciphertext[1:]

    f = open("encrypted_ct/"+filename, "w")
    f.write(tampered_ciphertext)
    f.close()

    print("\nOne character of AES ciphertext was modified.")
def main():

    # --------------------------------------
    # RSA parameters
    # --------------------------------------

    p = 10007
    q = 10009

    n = p * q
    phi = (p - 1) * (q - 1)

    # Find e
    e = -1

    for i in range(2, phi):
        if gcd(i, phi) == 1:
            e = i
            break

    # Find d
    d = pow(e, -1, phi)

    print("n =", n)
    print("phi =", phi)
    print("e =", e)
    print("d =", d)

    # --------------------------------------
    # Menu
    # --------------------------------------

    while True:

        print("\n===== Secure File Transfer =====")
        print("1. Student")
        print("2. Faculty")
        print("3. Tamper File")
        print("4. Exit")

        choice = input("Enter choice: ")

        if choice == "1":

            filename = input("Enter filename: ")
            plaintext = input("Enter academic record: ")

            student(filename, plaintext, e, n)

        elif choice == "2":

            filename = input("Enter filename: ")

            faculty(filename, d, n)

        elif choice == "3":

            filename = input("Enter filename: ")

            tamper_file(filename)

        elif choice == "4":

            print("Exiting...")
            break

        else:

            print("Invalid choice.")

if __name__ == "__main__":
    main()