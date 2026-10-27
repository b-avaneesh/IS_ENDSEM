from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random


# =========================
# DES
# =========================

def des_encrypt(text, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    return cipher.encrypt(pad(text.encode(), 8))


def des_decrypt(ciphertext, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 8).decode()


# =========================
# RSA DIGITAL SIGNATURE
# =========================

def sign_data(data, private_key):
    h = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(h)


def verify_signature(data, signature, public_key):
    try:
        h = SHA256.new(data)
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except:
        return False


# =========================
# RSA ENCRYPT DES KEY
# =========================

def encrypt_des_key(key, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(key.encode())


def decrypt_des_key(encrypted_key, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_key).decode()


# =========================
# ELGAMAL
# =========================

def elgamal_encrypt(message, p, g, h, k):
    result = []

    c1 = pow(g, k, p)
    s = pow(h, k, p)

    for ch in message:
        m = ord(ch)
        c2 = (m * s) % p
        result.append((c1, c2))

    return result


def elgamal_decrypt(ciphertext, p, x):
    message = ""

    for c1, c2 in ciphertext:
        s = pow(c1, x, p)
        m = (c2 * pow(s, -1, p)) % p
        message += chr(m)

    return message


# =========================
# MAIN
# =========================

def main():

    text = "ID:1042; NAME:Rahul; COURSE:CSE; MARKS:91"

    des_key = "A1B2C3D4"

    auth_code = "A2"


    # -------------------------
    # 1. DES ENCRYPTION
    # -------------------------

    encrypted_text = des_encrypt(text, des_key)

    print("DES Ciphertext:", encrypted_text.hex())


    # -------------------------
    # 2. SHA-256
    # -------------------------

    hash_value = SHA256.new(encrypted_text).hexdigest()

    print("SHA-256:", hash_value)


    # -------------------------
    # 3. RSA SIGNATURE
    # -------------------------

    sender_private = RSA.generate(2048)
    sender_public = sender_private.publickey()

    signature = sign_data(encrypted_text, sender_private)

    print("RSA Signature:", signature.hex())


    # -------------------------
    # 4. RSA ENCRYPT DES KEY
    # -------------------------

    receiver_private = RSA.generate(2048)
    receiver_public = receiver_private.publickey()

    encrypted_key = encrypt_des_key(des_key, receiver_public)

    print("Encrypted DES Key:", encrypted_key.hex())


    # -------------------------
    # 5. ELGAMAL AUTHORIZATION
    # -------------------------

    p = 467
    g = 2
    x = 127

    h = pow(g, x, p)

    encrypted_auth = elgamal_encrypt(
        auth_code, p, g, h, 53
    )

    print("Encrypted Auth Code:", encrypted_auth)


    # ==================================================
    # RECEIVER
    # ==================================================

    print("\n========== RECEIVER ==========")


    # -------------------------
    # 6. SHA-256 VERIFY
    # -------------------------

    received_hash = SHA256.new(encrypted_text).hexdigest()

    if received_hash != hash_value:
        print("Integrity Failed")
        return

    print("Integrity Verified")


    # -------------------------
    # 7. RSA SIGNATURE VERIFY
    # -------------------------

    if not verify_signature(
        encrypted_text,
        signature,
        sender_public
    ):
        print("Signature Invalid")
        return

    print("Signature Verified")


    # -------------------------
    # 8. RECOVER DES KEY
    # -------------------------

    recovered_key = decrypt_des_key(
        encrypted_key,
        receiver_private
    )

    print("DES Key Recovered:", recovered_key)


    # -------------------------
    # 9. ELGAMAL AUTH
    # -------------------------

    recovered_auth = elgamal_decrypt(
        encrypted_auth,
        p,
        x
    )

    print("Authorization Code:", recovered_auth)

    if recovered_auth != "A2":
        print("Access Denied")
        return

    print("Authorization Verified")


    # -------------------------
    # 10. DES DECRYPT
    # -------------------------

    decrypted_text = des_decrypt(
        encrypted_text,
        recovered_key
    )

    print("\nDecrypted Record:")
    print(decrypted_text)


if __name__ == "__main__":
    main()