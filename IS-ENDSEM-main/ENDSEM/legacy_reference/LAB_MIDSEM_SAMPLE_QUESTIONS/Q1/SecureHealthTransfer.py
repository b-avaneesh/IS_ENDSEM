# INFORMATION SECURITY LAB – MID-TERM EXAMINATION
#
# Question:
#
# A hospital needs to securely transfer a confidential patient laboratory
# report from the Laboratory Section to an authorized doctor through an
# insecure network.
#
# Develop ONE integrated Python application named "SecureHealthTransfer"
# that uses AES-128, RSA, ElGamal and hashing to provide confidentiality,
# authentication and integrity protection.
#
# The solution must be implemented as one integrated application, not as
# separate independent programs.
#
#
# FIXED INPUT:
#
# Patient Report:
#
# PATIENT ID:1042; TEST:???; RESULT:13.5; STATUS:NORMAL
#
# Authorization Code: A2
#
# Key ID: EHR-AES-01
#
# Key Status: ACTIVE
#
#
# HASHING ALGORITHM:
#
# Generate the hash only on the exact AES ciphertext.
#
# Initial hash value:
#
# h = 5381
#
# For each character of the ciphertext:
#
# h = (h * 33) + ord(ch)
#
# Apply bitwise operations to mix the bits and keep the hash value within
# a 32-bit range.
#
# Display the final hash as exactly 8 uppercase hexadecimal digits.
#
#
# REQUIRED INTEGRATED PROCESS:
#
# 1. Encrypt the exact Patient Report using AES-128 and the specified
#    AES mode/padding.
#
# 2. Generate the RSA values n, phi(n), e and d using the given RSA
#    parameters.
#
#    Use RSA to encrypt the AES key and recover it at the receiver.
#
# 3. Generate the ElGamal public key and private key.
#
#    Encrypt Authorization Code A2 using k = 53.
#
#    At the receiver, decrypt it and verify the recovered authorization
#    code.
#
# 4. Generate the specified hash of the exact AES ciphertext.
#
# 5. Store the following in separate files:
#
#    - AES-encrypted patient report
#    - RSA-encrypted AES key
#    - ElGamal-encrypted authorization code
#    - Sender hash
#
# 6. At the receiver, perform integrity verification FIRST.
#
#    Hash the received encrypted report and compare it with the sender's
#    stored hash.
#
# 7. If the hashes match:
#
#    - Display "Integrity Verified"
#    - Verify that Key ID EHR-AES-01 is ACTIVE
#    - Use RSA to recover the AES key
#    - Recover and verify the authorization code using ElGamal
#    - Decrypt the patient report using AES
#    - Display the decrypted patient report
#
# 8. After successful execution, modify exactly ONE character in the
#    encrypted report file and run the receiver again using the stored
#    sender hash.
#
# 9. When tampering is detected:
#
#    - Display that integrity verification failed
#    - Detect/report data corruption or tampering
#    - Stop the process
#    - DO NOT perform decryption
#
#
# EXPECTED PROCESS:
#
# Sender:
#
# Patient Report
#       |
#       v
#    AES-128
#       |
#       v
# AES Ciphertext
#       |
#       +------------------> Hash
#       |                       |
#       |                       v
#       |                  Store Hash
#       |
#       +------------------> Store Ciphertext
#
#
# AES Key
#    |
#    v
#   RSA
#    |
#    v
# RSA-Encrypted AES Key
#
#
# Authorization Code A2
#    |
#    v
#  ElGamal (k = 53)
#    |
#    v
# Encrypted Authorization Code
#
#
# Receiver:
#
# Received AES Ciphertext
#         |
#         v
#    Calculate Hash
#         |
#         v
# Compare with Sender Hash
#         |
#         +------ NO ------> Tampering Detected
#         |                  STOP
#         |                  NO DECRYPTION
#         |
#        YES
#         |
#         v
# Integrity Verified
#         |
#         v
# Verify Key ID EHR-AES-01 is ACTIVE
#         |
#         v
# RSA Decrypt AES Key
#         |
#         v
# ElGamal Decrypt Authorization Code
#         |
#         v
# Verify Authorization Code = A2
#         |
#         v
# AES Decrypt Patient Report
#         |
#         v
# Display Original Patient Report
#
#
# TAMPERING TEST:
#
# After the first successful receiver execution, modify exactly one
# character of the AES ciphertext file.
#
# Run the receiver again.
#
# The receiver should calculate a different hash, detect tampering, and
# stop before performing any decryption.
import ast
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from math import gcd

#aes for encrypting text:
def aes_encrypt(plaintext,key):

    # Convert string to bytes
    plaintext = plaintext.encode()

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad plaintext
    padded_text = pad(plaintext, AES.block_size)

    # Encrypt
    ciphertext = cipher.encrypt(padded_text)

    return ciphertext.hex()

def aes_decrypt(ciphertext_hex,key):
    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode()

#RSA for encrypting AES KEY
def RSA_encrypt(plaintext,e ,n):

    # Encryption
    ciphertext = []

    for ch in plaintext:
        M = ord(ch)
        C = pow(M, e, n)
        ciphertext.append(C)

    return ciphertext



def RSA_decrypt(ciphertext, d, n):
    # Decryption
    decrypted = ""

    for C in ciphertext:
        M = pow(C, d, n)
        decrypted += chr(M)

    return decrypted

####################################################

#ELGAMAL for encrypting authorization code:
def elgamal_encrypt(message, p, g, h):
    ciphertext = []

    for ch in message:

        # Convert character to number
        m = ord(ch)

        # m must be less than p
        if m >= p:
            print("Character value is too large for chosen p")
            return []

        k = 53

        # c1 = g^k mod p
        c1 = pow(g, k, p)

        # c2 = m * h^k mod p
        c2 = (m * pow(h, k, p)) % p

        ciphertext.append((c1, c2))

    return ciphertext


def elgamal_decrypt(ciphertext, p, x):
    plaintext = ""

    for c1, c2 in ciphertext:

        # s = c1^x mod p
        s = pow(c1, x, p)

        # s^(-1) mod p
        s_inv = pow(s, -1, p)

        # m = c2 * s^(-1) mod p
        m = (c2 * s_inv) % p

        # Convert number back to character
        plaintext += chr(m)

    return plaintext


def hash_function(text):
    hash_value = 5381

    for ch in text:
        hash_value = hash_value * 33 + ord(ch)

        # Mix the bits
        hash_value = hash_value ^ (hash_value >> 16)

        # Keep it within 32 bits
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


def sender(p,g,h,e,n):
    ##sender side:
    # AES-128 key
    key = b"0123456789ABCDEF"
    # Take plaintext input
    authorization_code = "A2"
    plaintext = input("Enter plaintext: ")
    #------------------------------------------
    #ENCRYPT PATIENT REPORT USING AES
    # ------------------------------------------
    aes_ciphertext = aes_encrypt(plaintext, key)
    print("\nAES Ciphertext:")
    print(aes_ciphertext)
    # --------------------------------------------------------
    # 2. RSA encrypt AES key
    # --------------------------------------------------------
    encrypted_aes_key = RSA_encrypt(key.decode(),e,n)
    print("\nRSA Encrypted AES Key:")
    print(encrypted_aes_key)

    # --------------------------------------------------------
    # 3. ElGamal encrypt authorization code
    # --------------------------------------------------------
    encrypted_auth_code = elgamal_encrypt(authorization_code, p, g, h)
    print("\nElGamal Encrypted Authorization Code:")
    print(encrypted_auth_code)

    # --------------------------------------------------------
    # 4. Hash AES ciphertext
    # --------------------------------------------------------
    hash_of_aes_cipher = hash_function(aes_ciphertext)
    print("\nHash:")
    print(f"{hash_of_aes_cipher:08X}")

    # --------------------------------------------------------
    # 5. Store everything in separate files
    # --------------------------------------------------------


    f1 = open("aes_cipher.txt", "w")
    f1.write(aes_ciphertext)

    f2 = open("encrypted_aes_key.txt", "w")
    f2.write(str(encrypted_aes_key))

    f3 = open("encrypted_auth_code.txt", "w")
    f3.write(str(encrypted_auth_code))

    f4 = open("hash_of_aes_cipher.txt", "w")
    f4.write(str(hash_of_aes_cipher))

    f1.close()
    f2.close()
    f3.close()
    f4.close()
def receiver(d,n,p_elgamal,x):
    print("\n========== RECEIVER ==========")
    # --------------------------------------------------------
    # Read AES ciphertext
    # --------------------------------------------------------
    f1 = open("aes_cipher.txt", "r")
    aes_ciphertext = f1.read()
    # --------------------------------------------------------
    # Read RSA encrypted AES key
    # --------------------------------------------------------
    f2 = open("encrypted_aes_key.txt", "r")
    encrypted_aes_key = ast.literal_eval(f2.read())
    # --------------------------------------------------------
    # Read ElGamal encrypted authorization code
    # --------------------------------------------------------
    f3 = open("encrypted_auth_code.txt", "r")
    encrypted_auth_code = ast.literal_eval(f3.read())
    # --------------------------------------------------------
    # Read sender hash
    # --------------------------------------------------------
    f4 = open("hash_of_aes_cipher.txt", "r")
    sender_hash = int(f4.read())
    # --------------------------------------------------------
    # 6. Integrity verification FIRST
    # --------------------------------------------------------
    receiver_hash = hash_function(aes_ciphertext)
    print("\nSender Hash:")
    print(f"{sender_hash:08X}")

    print("\nReceiver Hash:")
    print(f"{receiver_hash:08X}")

    if receiver_hash != sender_hash:
        print("\nIntegrity Verification FAILED!")
        print("Tampering / data corruption detected.")
        print("STOPPING PROCESS.")
        print("Decryption NOT performed.")
        return False
    else:
        print("Integrity verified!")

    # --------------------------------------------------------
    # Verify Key ID / status
    # --------------------------------------------------------
    key_id = "EHR-AES-01"
    key_status = "ACTIVE"

    print("\nKey ID:", key_id)
    print("Key Status:", key_status)

    if key_status != "ACTIVE":
        print("AES key is not active.")
        return False
    # --------------------------------------------------------
    # 7. RSA decrypt AES key
    # --------------------------------------------------------

    aes_key = RSA_decrypt(encrypted_aes_key,d,n).encode()
    print("\nRecovered AES Key:")
    print(aes_key.decode())

    # --------------------------------------------------------
    # ElGamal decrypt authorization code
    # --------------------------------------------------------
    final_auth_code = elgamal_decrypt(encrypted_auth_code, p_elgamal, x)
    print("\nRecovered Authorization Code:")
    print(final_auth_code)
    if final_auth_code != "A2":
        print("Authorization FAILED!")
        return False

    print("Authorization Verified!")
    # --------------------------------------------------------
    # AES decrypt patient report
    # --------------------------------------------------------
    final_plaintext_received = aes_decrypt(aes_ciphertext,aes_key)
    print("\nDecrypted Patient Report:")
    print(final_plaintext_received)

    f1.close()
    f2.close()
    f3.close()
    f4.close()

    return True

# ============================================================
# TAMPER WITH CIPHERTEXT
# ============================================================

def tamper_file():

    f = open("aes_cipher.txt", "r")
    ciphertext = f.read()
    f.close()

    # Change exactly one hexadecimal character
    if ciphertext[0] != "0":
        tampered_ciphertext = "0" + ciphertext[1:]
    else:
        tampered_ciphertext = "1" + ciphertext[1:]

    f = open("aes_cipher.txt", "w")
    f.write(tampered_ciphertext)
    f.close()

    print("\nOne character of AES ciphertext was modified.")


def main():

    # ========================================================
    # ELGAMAL PARAMETERS
    # ========================================================
    # Public parameters
    p_elgamal = 2147483647
    g = 2

    # Private key
    x = 127

    # Public key component
    h = pow(g, x, p_elgamal)

    # ========================================================
    # RSA PARAMETERS
    # ========================================================
    p_rsa = 10007
    q_rsa = 10009

    n = p_rsa * q_rsa
    phi = (p_rsa - 1) * (q_rsa - 1)

    # Find e
    e = -1

    for i in range(2, phi):
        if gcd(i, phi) == 1:
            e = i
            break

    # Find d
    d = pow(e, -1, phi)
    # ========================================================
    # Display RSA values
    # ========================================================

    print("========== RSA PARAMETERS ==========")
    print("n   =", n)
    print("phi =", phi)
    print("e   =", e)
    print("d   =", d)

    # ========================================================
    # Display ElGamal values
    # ========================================================

    print("\n========== ELGAMAL PARAMETERS ==========")
    print("p =", p_elgamal)
    print("g =", g)
    print("h =", h)
    print("x =", x)

    # ========================================================
    # SENDER
    # ========================================================

    sender(p_elgamal, g, h, e, n)
    # ========================================================
    # FIRST RECEIVER RUN
    # Should succeed
    # ========================================================

    print("\n\n========================================")
    print("FIRST RECEIVER RUN")
    print("========================================")

    receiver(d, n, p_elgamal, x)

    # ========================================================
    # TAMPERING
    # ========================================================

    print("\n\n========================================")
    print("TAMPERING")
    print("========================================")

    tamper_file()

    # ========================================================
    # SECOND RECEIVER RUN
    # Should detect tampering and STOP
    # ========================================================

    print("\n\n========================================")
    print("SECOND RECEIVER RUN")
    print("========================================")

    receiver(d, n, p_elgamal, x)

    # ============================================================
    # PROGRAM START
    # ============================================================

if __name__ == "__main__":
    main()



